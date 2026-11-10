#!/usr/bin/env python3
"""Local SQLite transactional reference for a revocable settlement gateway.

This is not a blockchain adapter. Subject registration and complete support
discovery are trusted inputs. SQLite serializes writers; it supplies the atomic
boundary between evidence validation and this file's integer-balance ledger.
No claim about a distributed chain, oracle truth, or production durability is
made by this implementation.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterable, Optional


class GateRejected(RuntimeError):
    """A denied operation with a stable, machine-readable reason."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def require_effect_id(effect_id: str) -> None:
    """The empty text key is reserved for the cleanup cursor's initial state."""
    if not isinstance(effect_id, str) or not effect_id:
        raise ValueError("effect_id must be a non-empty string")


class DurableGateway:
    """One connection; create a separate instance for each concurrent thread.

    ``clock`` is read *after* acquiring the write transaction. Production-like
    local runs default to persisted UTC seconds (time.time). Explicit ``now``
    is a deterministic test/model timestamp at that same transaction boundary,
    never a timestamp captured by this class before waiting for the DB lock.
    A trusted non-regressing clock is an assumption; clock rollback is not
    addressed here. ``fault_hook`` is solely for process-crash tests.
    """

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time,
                 fault_hook: Optional[Callable[[str], None]] = None):
        self.path = str(path)
        self.clock = clock
        self.fault_hook = fault_hook
        self.db = sqlite3.connect(self.path, isolation_level=None, timeout=30.0)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA busy_timeout=30000")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS subjects (
                subject_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL CHECK(epoch >= 0),
                valid INTEGER NOT NULL CHECK(valid IN (0, 1)),
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS accounts (
                account_id TEXT PRIMARY KEY,
                balance INTEGER NOT NULL CHECK(balance >= 0)
                    CHECK(typeof(balance) = 'integer')
            );
            CREATE TABLE IF NOT EXISTS effects (
                effect_id TEXT PRIMARY KEY,
                contract_version INTEGER NOT NULL,
                payer TEXT NOT NULL REFERENCES accounts(account_id),
                recipient TEXT NOT NULL REFERENCES accounts(account_id),
                amount INTEGER NOT NULL CHECK(amount > 0),
                payload_hash TEXT,
                state TEXT NOT NULL CHECK(state IN ('pending', 'settled', 'cancelled')),
                CHECK(payer != recipient)
            );
            CREATE TABLE IF NOT EXISTS effect_support (
                effect_id TEXT NOT NULL REFERENCES effects(effect_id),
                subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
                PRIMARY KEY(effect_id, subject_id)
            );
            CREATE TABLE IF NOT EXISTS stages (
                effect_id TEXT PRIMARY KEY REFERENCES effects(effect_id),
                payload TEXT NOT NULL,
                payload_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tokens (
                nonce TEXT PRIMARY KEY,
                effect_id TEXT NOT NULL REFERENCES effects(effect_id),
                contract_version INTEGER NOT NULL,
                payload_hash TEXT NOT NULL,
                support_snapshot TEXT NOT NULL,
                issued_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('issued', 'consumed', 'revoked'))
            );
            CREATE TABLE IF NOT EXISTS ledger (
                effect_id TEXT PRIMARY KEY REFERENCES effects(effect_id),
                nonce TEXT NOT NULL UNIQUE REFERENCES tokens(nonce),
                receipt_id TEXT NOT NULL UNIQUE,
                payer TEXT NOT NULL,
                recipient TEXT NOT NULL,
                amount INTEGER NOT NULL,
                settled_at REAL NOT NULL
            );
        """)
        self._reject_legacy_empty_effect_ids()

    def _reject_legacy_empty_effect_ids(self) -> None:
        """Reject old empty/NULL identities; never rename a bound ledger action.

        These two primary-key probes preserve the existing schema. They do not
        scan ordinary effects or mutate persisted stages, tokens, receipts or
        cleanup cursors. Integer IDs in
        old TEXT-affinity schemas were already stored as nonempty text; new
        registration APIs require an actual nonempty Python string.
        """
        for condition in ("effect_id = ''", "effect_id IS NULL"):
            row = self.db.execute(
                "SELECT 1 FROM effects WHERE " + condition + " LIMIT 1").fetchone()
            if row is not None:
                self.db.close()
                raise GateRejected("invalid_persisted_effect_id")

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "DurableGateway":
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _time(self, now: Optional[float]) -> float:
        value = float(self.clock() if now is None else now)
        if not math.isfinite(value):
            raise ValueError("time must be finite")
        return value

    @staticmethod
    def _integer(value: int, *, positive: bool = False) -> None:
        if type(value) is not int or value < (1 if positive else 0):
            raise ValueError("integer units required")
        if value > 2**63 - 1:
            raise ValueError("balance exceeds SQLite signed-integer range")

    def create_account(self, account_id: str, balance: int = 0) -> None:
        """Trusted initial setup; duplicate creation cannot mint additional funds."""
        self._integer(balance)
        with self._transaction():
            row = self.db.execute("SELECT balance FROM accounts WHERE account_id=?",
                                  (account_id,)).fetchone()
            if row is not None:
                raise GateRejected("account_exists")
            self.db.execute("INSERT INTO accounts VALUES (?, ?)", (account_id, balance))

    def balance(self, account_id: str) -> int:
        row = self.db.execute("SELECT balance FROM accounts WHERE account_id=?",
                              (account_id,)).fetchone()
        if row is None:
            raise GateRejected("unknown_account")
        return row["balance"]

    def put_subject(self, subject_id: str, expires_at: float) -> int:
        """Register one immutable evidence generation. IDs are never recycled."""
        if not math.isfinite(expires_at):
            raise ValueError("finite evidence expiry required")
        with self._transaction():
            row = self.db.execute("SELECT * FROM subjects WHERE subject_id=?",
                                  (subject_id,)).fetchone()
            if row is not None:
                if not row["valid"]:
                    raise GateRejected("invalidated_subject_tombstone")
                if row["expires_at"] != expires_at:
                    raise GateRejected("subject_generation_is_immutable")
                return row["epoch"]
            self.db.execute("INSERT INTO subjects VALUES (?, 0, 1, ?)",
                            (subject_id, expires_at))
            return 0

    def invalidate(self, subject_id: str) -> int:
        """Publish a permanent invalidation; cleanup is deliberately separate."""
        with self._transaction():
            row = self.db.execute("SELECT epoch FROM subjects WHERE subject_id=?",
                                  (subject_id,)).fetchone()
            if row is None:
                raise GateRejected("unknown_subject")
            epoch = row["epoch"] + 1
            self.db.execute("UPDATE subjects SET epoch=?, valid=0 WHERE subject_id=?",
                            (epoch, subject_id))
            return epoch

    def _require_subjects(self, support: Iterable[str]) -> tuple[str, ...]:
        ids = tuple(sorted(set(support)))
        if not ids:
            raise GateRejected("empty_support")
        for subject_id in ids:
            if self.db.execute("SELECT 1 FROM subjects WHERE subject_id=?",
                               (subject_id,)).fetchone() is None:
                raise GateRejected("unknown_subject")
        return ids

    def create_effect(self, effect_id: str, payer: str, recipient: str,
                      amount: int, support: Iterable[str]) -> None:
        require_effect_id(effect_id)
        self._integer(amount, positive=True)
        with self._transaction():
            ids = self._require_subjects(support)
            self.db.execute("INSERT INTO effects VALUES (?, 0, ?, ?, ?, NULL, 'pending')",
                            (effect_id, payer, recipient, amount))
            self.db.executemany("INSERT INTO effect_support VALUES (?, ?)",
                                ((effect_id, sid) for sid in ids))

    def _effect(self, effect_id: str) -> sqlite3.Row:
        row = self.db.execute("SELECT * FROM effects WHERE effect_id=?", (effect_id,)).fetchone()
        if row is None:
            raise GateRejected("unknown_effect")
        return row

    def _pending(self, effect_id: str) -> sqlite3.Row:
        row = self._effect(effect_id)
        if row["state"] != "pending":
            raise GateRejected("effect_" + row["state"])
        return row

    def extend_contract(self, effect_id: str, additional_support: Iterable[str]) -> int:
        """Append support and version the contract. Removed support is unsupported."""
        with self._transaction():
            row = self._pending(effect_id)
            ids = self._require_subjects(additional_support)
            current = {r[0] for r in self.db.execute(
                "SELECT subject_id FROM effect_support WHERE effect_id=?", (effect_id,))}
            additions = set(ids) - current
            if not additions:
                return row["contract_version"]
            self.db.executemany("INSERT INTO effect_support VALUES (?, ?)",
                                ((effect_id, sid) for sid in sorted(additions)))
            version = row["contract_version"] + 1
            self.db.execute("UPDATE effects SET contract_version=? WHERE effect_id=?",
                            (version, effect_id))
            return version

    def stage(self, effect_id: str, payload: object) -> str:
        """Persist actual payload bytes. Recipient/amount and payload are immutable."""
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        with self._transaction():
            effect = self._pending(effect_id)
            if effect["payload_hash"] is not None:
                if effect["payload_hash"] != digest:
                    raise GateRejected("payload_is_immutable")
                return digest
            self.db.execute("INSERT INTO stages VALUES (?, ?, ?)", (effect_id, serialized, digest))
            self.db.execute("UPDATE effects SET payload_hash=? WHERE effect_id=?", (digest, effect_id))
        return digest

    def _support(self, effect_id: str, timestamp: float) -> list[dict]:
        rows = self.db.execute("""
            SELECT s.* FROM subjects s JOIN effect_support es USING(subject_id)
            WHERE es.effect_id=? ORDER BY subject_id
        """, (effect_id,)).fetchall()
        if not rows:
            raise GateRejected("empty_support")
        for row in rows:
            if not row["valid"]:
                raise GateRejected("support_invalidated")
            if timestamp >= row["expires_at"]:
                raise GateRejected("support_expired")
        return [dict(row) for row in rows]

    def issue(self, effect_id: str, *, now: Optional[float] = None, ttl: float = 30.0) -> str:
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("positive finite token ttl required")
        with self._transaction():
            timestamp = self._time(now)
            effect = self._pending(effect_id)
            stage = self.db.execute("SELECT * FROM stages WHERE effect_id=?", (effect_id,)).fetchone()
            if stage is None:
                raise GateRejected("payload_not_staged")
            snapshot = self._support(effect_id, timestamp)
            expiry = min(timestamp + ttl, min(s["expires_at"] for s in snapshot))
            nonce = uuid.uuid4().hex
            self.db.execute("INSERT INTO tokens VALUES (?, ?, ?, ?, ?, ?, ?, 'issued')", (
                nonce, effect_id, effect["contract_version"], stage["payload_hash"],
                json.dumps(snapshot, sort_keys=True), timestamp, expiry))
            return nonce

    def _fault(self, phase: str) -> None:
        if self.fault_hook:
            self.fault_hook(phase)

    def settle(self, nonce: str, *, now: Optional[float] = None,
               expected_effect_id: Optional[str] = None) -> dict:
        """Atomically validate and transfer, or return an already committed receipt.

        Repeating the *same* consumed token is an idempotent query, even if its
        evidence subsequently expires or is invalidated. It creates no new
        financial effect. Another token for the same effect cannot settle again.
        """
        with self._transaction():
            timestamp = self._time(now)
            token = self.db.execute("SELECT * FROM tokens WHERE nonce=?", (nonce,)).fetchone()
            if token is None:
                raise GateRejected("unknown_token")
            effect_id = token["effect_id"]
            if expected_effect_id is not None and expected_effect_id != effect_id:
                raise GateRejected("token_effect_mismatch")
            prior = self.db.execute("SELECT * FROM ledger WHERE nonce=?", (nonce,)).fetchone()
            if prior is not None:
                return dict(prior)
            if token["state"] != "issued":
                raise GateRejected("token_" + token["state"])
            effect = self._pending(effect_id)
            if effect["contract_version"] != token["contract_version"]:
                raise GateRejected("contract_changed")
            if timestamp < token["issued_at"]:
                raise GateRejected("clock_regression")
            snapshot = self._support(effect_id, timestamp)
            if snapshot != json.loads(token["support_snapshot"]):
                raise GateRejected("support_snapshot_changed")
            if timestamp >= token["expires_at"]:
                raise GateRejected("token_expired")
            stage = self.db.execute("SELECT * FROM stages WHERE effect_id=?", (effect_id,)).fetchone()
            if stage is None:
                raise GateRejected("payload_not_staged")
            digest = hashlib.sha256(stage["payload"].encode("utf-8")).hexdigest()
            if digest != token["payload_hash"] or digest != effect["payload_hash"]:
                raise GateRejected("payload_changed")
            payer_balance = self.balance(effect["payer"])
            recipient_balance = self.balance(effect["recipient"])
            amount = effect["amount"]
            if payer_balance < amount:
                raise GateRejected("insufficient_funds")
            if recipient_balance + amount > 2**63 - 1:
                raise GateRejected("balance_overflow")
            self.db.execute("UPDATE accounts SET balance=balance-? WHERE account_id=?",
                            (amount, effect["payer"]))
            self._fault("after_debit")
            self.db.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?",
                            (amount, effect["recipient"]))
            receipt = {
                "effect_id": effect_id, "nonce": nonce, "receipt_id": uuid.uuid4().hex,
                "payer": effect["payer"], "recipient": effect["recipient"],
                "amount": amount, "settled_at": timestamp,
            }
            self.db.execute("INSERT INTO ledger VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(receipt.values()))
            self.db.execute("UPDATE tokens SET state='consumed' WHERE nonce=?", (nonce,))
            self.db.execute("UPDATE effects SET state='settled' WHERE effect_id=?", (effect_id,))
            self.db.execute("DELETE FROM stages WHERE effect_id=?", (effect_id,))
            self._fault("before_commit")
        self._fault("after_commit")
        return receipt

    def cleanup(self, effect_id: str) -> int:
        """Cancel an unsettled effect and physically delete its staging row.

        This is local staging cleanup, never reversal of a committed transfer.
        It is allowed independently of invalidation so the caller can cancel.
        """
        with self._transaction():
            effect = self._effect(effect_id)
            if effect["state"] == "settled":
                raise GateRejected("cannot_rollback_settled_effect")
            deleted = self.db.execute("DELETE FROM stages WHERE effect_id=?", (effect_id,)).rowcount
            self.db.execute("UPDATE effects SET state='cancelled' WHERE effect_id=?", (effect_id,))
            self.db.execute("UPDATE tokens SET state='revoked' WHERE effect_id=? AND state='issued'",
                            (effect_id,))
            return deleted

    def inspect(self) -> dict:
        """Consistent evidence snapshot, including actual balances and ledger."""
        self.db.execute("BEGIN")
        try:
            tables = {}
            for name, order in (("accounts", "account_id"), ("subjects", "subject_id"),
                                ("effects", "effect_id"), ("effect_support", "effect_id, subject_id"),
                                ("stages", "effect_id"), ("tokens", "nonce"), ("ledger", "effect_id")):
                tables[name] = [dict(row) for row in self.db.execute(f"SELECT * FROM {name} ORDER BY {order}")]
            self.db.execute("COMMIT")
            return tables
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
