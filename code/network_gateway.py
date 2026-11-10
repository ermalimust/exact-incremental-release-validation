"""Single-host HTTP gateway with atomic evidence validation and SQLite settlement.

This is a loopback socket experiment, not a distributed database or chain. The
clock is read after BEGIN IMMEDIATE, and denotes evaluation time, not COMMIT time.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import time
import uuid

from durable_gateway import DurableGateway, GateRejected, require_effect_id
from integrated_controller import Registry
from persistent_workflow import compile_registry

POLICIES = ("support_epoch", "global_epoch", "full_recheck")


class NetworkGateway(DurableGateway):
    def __init__(self, path, policy="support_epoch", *, clock=time.time,
                 request_id=None, actor_id=None, fault_hook=None):
        if policy not in POLICIES:
            raise ValueError("unknown policy")
        super().__init__(path, clock=clock, fault_hook=fault_hook)
        self.policy, self.request_id, self.actor_id = policy, request_id, actor_id
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS network_meta (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                global_epoch INTEGER NOT NULL, policy TEXT NOT NULL,
                workload TEXT
            );
            CREATE TABLE IF NOT EXISTS network_tokens (
                nonce TEXT PRIMARY KEY REFERENCES tokens(nonce),
                global_epoch INTEGER NOT NULL, ttl_deadline REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL,
                effect_id TEXT, subject_id TEXT, nonce TEXT,
                at_time REAL NOT NULL, payload TEXT NOT NULL,
                request_id TEXT, actor_id TEXT
            );
        """)
        with self._transaction():
            row = self.db.execute("SELECT * FROM network_meta WHERE singleton=1").fetchone()
            if row is None:
                self.db.execute("INSERT INTO network_meta VALUES (1,0,?,NULL)", (policy,))
            elif row["policy"] != policy:
                raise GateRejected("persisted_policy_mismatch")

    def _time(self, now):
        value = super()._time(now)
        if self.db.in_transaction:
            self._decision_timestamp = value
        return value

    @contextmanager
    def _transaction(self):
        self.db.execute("BEGIN IMMEDIATE")
        self._decision_timestamp = super()._time(None)
        try:
            yield
            self.db.execute("COMMIT")
        except BaseException as exc:
            if isinstance(exc, GateRejected):
                # Capture the actual failed validation prefix before releasing
                # the serialization lock; later reject logging may race.
                prefix = self.db.execute("SELECT COALESCE(MAX(seq),0) FROM audit").fetchone()[0]
                self._last_denial = {"evaluated_prefix_seq": prefix,
                                     "evaluated_at": self._decision_timestamp}
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def _global(self):
        return self.db.execute("SELECT global_epoch FROM network_meta WHERE singleton=1").fetchone()[0]

    def _bump_global(self):
        self.db.execute("UPDATE network_meta SET global_epoch=global_epoch+1 WHERE singleton=1")
        return self._global()

    def _audit(self, kind, timestamp, *, effect_id=None, subject_id=None, nonce=None, **details):
        self.db.execute("INSERT INTO audit(kind,effect_id,subject_id,nonce,at_time,payload,request_id,actor_id) VALUES (?,?,?,?,?,?,?,?)", (
            kind, effect_id, subject_id, nonce, timestamp,
            json.dumps(details, sort_keys=True, allow_nan=False), self.request_id, self.actor_id))

    def log_reject(self, operation, arguments, reason):
        # Rejections have no state transition and are logged in a fresh tx after
        # rollback; their seq is not used as the acceptance linearization point.
        decision = getattr(self, "_last_denial", {})
        with self._transaction():
            self._audit("reject", self._time(None), effect_id=arguments.get("effect_id") or arguments.get("expected_effect_id"),
                        subject_id=arguments.get("subject_id"), nonce=arguments.get("nonce"),
                        operation=operation, reason=reason, **decision)

    def invalidate(self, subject_id):
        with self._transaction():
            timestamp = self._time(None)
            row = self.db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone()
            if row is None:
                raise GateRejected("unknown_subject")
            epoch = row["epoch"] + 1
            self.db.execute("UPDATE subjects SET epoch=?,valid=0 WHERE subject_id=?", (epoch, subject_id))
            ge = self._bump_global()
            self._audit("invalidate", timestamp, subject_id=subject_id, epoch=epoch,
                        valid=0, expires_at=row["expires_at"], global_epoch=ge)
            return epoch

    def refresh(self, subject_id, expires_at=None):
        with self._transaction():
            timestamp = self._time(None)
            row = self.db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone()
            if row is None:
                raise GateRejected("unknown_subject")
            if not row["valid"]:
                raise GateRejected("invalidated_subject_tombstone")
            expiry = row["expires_at"] if expires_at is None else float(expires_at)
            if not math.isfinite(expiry) or expiry <= timestamp:
                raise ValueError("refresh expiry must be finite and future")
            epoch = row["epoch"] + 1
            self.db.execute("UPDATE subjects SET epoch=?,expires_at=? WHERE subject_id=?", (epoch, expiry, subject_id))
            ge = self._bump_global()
            self._audit("refresh", timestamp, subject_id=subject_id, epoch=epoch,
                        valid=1, expires_at=expiry, global_epoch=ge)
            return {"epoch": epoch, "expires_at": expiry}

    def extend_contract(self, effect_id, additional_support):
        with self._transaction():
            timestamp = self._time(None)
            effect = self._pending(effect_id)
            ids = self._require_subjects(additional_support)
            current = {r[0] for r in self.db.execute("SELECT subject_id FROM effect_support WHERE effect_id=?", (effect_id,))}
            additions = sorted(set(ids) - current)
            version = effect["contract_version"]
            if additions:
                self.db.executemany("INSERT INTO effect_support VALUES (?,?)", ((effect_id, sid) for sid in additions))
                version += 1
                self.db.execute("UPDATE effects SET contract_version=? WHERE effect_id=?", (version, effect_id))
                ge = self._bump_global()
                self._audit("extend", timestamp, effect_id=effect_id, additions=additions,
                            contract_version=version, global_epoch=ge)
            return version

    def stage(self, effect_id, payload):
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        with self._transaction():
            timestamp = self._time(None)
            effect = self._pending(effect_id)
            if effect["payload_hash"] is not None:
                if effect["payload_hash"] != digest:
                    raise GateRejected("payload_is_immutable")
                return digest
            self.db.execute("INSERT INTO stages VALUES (?,?,?)", (effect_id, serialized, digest))
            self.db.execute("UPDATE effects SET payload_hash=? WHERE effect_id=?", (digest, effect_id))
            self._audit("stage", timestamp, effect_id=effect_id, payload_hash=digest)
            return digest

    def issue(self, effect_id, *, now=None, ttl=30.0):
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("positive finite token ttl required")
        with self._transaction():
            timestamp = self._time(now)
            effect = self._pending(effect_id)
            stage = self.db.execute("SELECT * FROM stages WHERE effect_id=?", (effect_id,)).fetchone()
            if stage is None:
                raise GateRejected("payload_not_staged")
            snapshot = self._support(effect_id, timestamp)
            deadline = timestamp + ttl
            expiry = min(deadline, min(s["expires_at"] for s in snapshot))
            nonce, ge = uuid.uuid4().hex, self._global()
            self.db.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,?,'issued')", (
                nonce, effect_id, effect["contract_version"], stage["payload_hash"],
                json.dumps(snapshot, sort_keys=True), timestamp, expiry))
            self.db.execute("INSERT INTO network_tokens VALUES (?,?,?)", (nonce, ge, deadline))
            self._audit("issue", timestamp, effect_id=effect_id, nonce=nonce,
                        contract_version=effect["contract_version"], snapshot=snapshot,
                        expires_at=expiry, ttl_deadline=deadline, global_epoch=ge,
                        payload_hash=stage["payload_hash"])
            return nonce

    def settle(self, nonce, *, now=None, expected_effect_id=None):
        with self._transaction():
            timestamp = self._time(now)
            token = self.db.execute("SELECT t.*,n.global_epoch,n.ttl_deadline FROM tokens t JOIN network_tokens n USING(nonce) WHERE nonce=?", (nonce,)).fetchone()
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
            if self.policy == "full_recheck":
                self._support(effect_id, timestamp)
                if timestamp >= token["ttl_deadline"]:
                    raise GateRejected("token_expired")
            else:
                # Only epochs and fixed deadlines: validity was established at
                # issuance; all admissible status/deadline changes increment epochs.
                versions = [(r["subject_id"], r["epoch"]) for r in self.db.execute(
                    "SELECT s.subject_id,s.epoch FROM subjects s JOIN effect_support es USING(subject_id) WHERE es.effect_id=? ORDER BY subject_id", (effect_id,))]
                issued = [(s["subject_id"], s["epoch"]) for s in json.loads(token["support_snapshot"])]
                if versions != issued:
                    raise GateRejected("support_epoch_changed")
                if self.policy == "global_epoch" and self._global() != token["global_epoch"]:
                    raise GateRejected("global_epoch_changed")
                if timestamp >= token["expires_at"]:
                    raise GateRejected("token_expired")
            stage = self.db.execute("SELECT * FROM stages WHERE effect_id=?", (effect_id,)).fetchone()
            if stage is None:
                raise GateRejected("payload_not_staged")
            digest = hashlib.sha256(stage["payload"].encode("utf-8")).hexdigest()
            if digest != token["payload_hash"] or digest != effect["payload_hash"]:
                raise GateRejected("payload_changed")
            amount = effect["amount"]
            if self.balance(effect["payer"]) < amount:
                raise GateRejected("insufficient_funds")
            if self.balance(effect["recipient"]) + amount > 2**63 - 1:
                raise GateRejected("balance_overflow")
            self.db.execute("UPDATE accounts SET balance=balance-? WHERE account_id=?", (amount, effect["payer"]))
            self._fault("after_debit")
            self.db.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?", (amount, effect["recipient"]))
            receipt = dict(effect_id=effect_id, nonce=nonce, receipt_id=uuid.uuid4().hex,
                           payer=effect["payer"], recipient=effect["recipient"], amount=amount, settled_at=timestamp)
            self.db.execute("INSERT INTO ledger VALUES (?,?,?,?,?,?,?)", tuple(receipt.values()))
            self.db.execute("UPDATE tokens SET state='consumed' WHERE nonce=?", (nonce,))
            self.db.execute("UPDATE effects SET state='settled' WHERE effect_id=?", (effect_id,))
            self.db.execute("DELETE FROM stages WHERE effect_id=?", (effect_id,))
            self._audit("settle", timestamp, effect_id=effect_id, nonce=nonce,
                        receipt=receipt, policy=self.policy, contract_version=effect["contract_version"],
                        global_epoch=self._global())
            self._fault("before_commit")
        self._fault("after_commit")
        return receipt

    def cleanup(self):
        with self._transaction():
            timestamp = self._time(None)
            effects = [r[0] for r in self.db.execute("""SELECT DISTINCT e.effect_id FROM effects e
                JOIN effect_support es USING(effect_id) JOIN subjects s USING(subject_id)
                WHERE e.state='pending' AND s.valid=0 ORDER BY e.effect_id""")]
            removed = 0
            for eid in effects:
                removed += self.db.execute("DELETE FROM stages WHERE effect_id=?", (eid,)).rowcount
                self.db.execute("UPDATE effects SET state='cancelled' WHERE effect_id=?", (eid,))
                self.db.execute("UPDATE tokens SET state='revoked' WHERE effect_id=? AND state='issued'", (eid,))
            self._audit("cleanup", timestamp, cancelled_effects=effects, stage_rows_deleted=removed)
            return {"cancelled_effects": effects, "stage_rows_deleted": removed}

    def inspect(self):
        self.db.execute("BEGIN")
        try:
            output = {}
            for table, order in (("accounts","account_id"), ("subjects","subject_id"),
                                 ("effects","effect_id"), ("effect_support","effect_id,subject_id"),
                                 ("stages","effect_id"), ("tokens","nonce"), ("network_tokens","nonce"),
                                 ("ledger","effect_id"), ("audit","seq")):
                output[table] = [dict(r) for r in self.db.execute(f"SELECT * FROM {table} ORDER BY {order}")]
            for row in output["audit"]:
                row["payload"] = json.loads(row["payload"])
            output["metadata"] = dict(self.db.execute("SELECT * FROM network_meta WHERE singleton=1").fetchone())
            if output["metadata"]["workload"]:
                output["metadata"]["workload"] = json.loads(output["metadata"]["workload"])
            self.db.execute("COMMIT")
            return output
        except BaseException:
            self.db.execute("ROLLBACK")
            raise


def bootstrap(db_path, workload: dict, policy="support_epoch"):
    """Trusted initial registration; benchmark calls this once before serving."""
    declaration, supports = compile_registry(Registry(**workload["registry"]))
    for effect in workload["effects"]:
        require_effect_id(effect["effect_id"])
    expiry = float(workload.get("expires_at", time.time() + 3600))
    subjects = set(workload.get("extra_subjects", []))
    for support in supports.values():
        subjects.update(support)
    # Register graph nodes even if currently unrelated to any effect.
    subjects.update("a:" + aid for aid in declaration["artifact_parents"])
    subjects.update("o:" + oid for values in declaration["artifact_obligations"].values() for oid in values)
    subjects.update("o:" + oid for values in declaration["effect_obligations"].values() for oid in values)
    deadlines = workload.get("subject_expiries", {})
    with NetworkGateway(db_path, policy) as gate:
        if gate.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]:
            raise GateRejected("bootstrap_requires_empty_database")
        for account, balance in workload["accounts"].items():
            gate.create_account(account, balance)
        for sid in sorted(subjects):
            gate.put_subject(sid, float(deadlines.get(sid, expiry)))
        for effect in workload["effects"]:
            eid = effect["effect_id"]
            gate.create_effect(eid, effect["payer"], effect["recipient"], effect["amount"], supports[eid])
            if workload.get("stage_at_bootstrap", True):
                gate.stage(eid, effect["payload"])
        initial = {"registry": declaration, "supports": supports, "expires_at": expiry,
                   "subject_expiries": {s: float(deadlines.get(s, expiry)) for s in sorted(subjects)},
                   "accounts": workload["accounts"], "effects": workload["effects"]}
        with gate._transaction():
            gate.db.execute("UPDATE network_meta SET workload=? WHERE singleton=1", (json.dumps(initial, sort_keys=True),))
            gate._audit("bootstrap", gate._time(None), initial=initial, policy=policy)
        return gate.inspect()


def serve(db_path, policy, ready_file, port=0):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            if self.path != "/rpc":
                self.send_error(404)
                return
            operation, arguments, gate = "unknown", {}, None
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4 * 1024 * 1024:
                    raise ValueError("invalid request size")
                request = json.loads(self.rfile.read(length))
                operation = request["operation"]
                arguments = dict(request.get("arguments", {}))
                gate = NetworkGateway(db_path, policy, request_id=request.get("request_id"), actor_id=request.get("actor_id"))
                if operation == "ping":
                    result = {"pid": os.getpid(), "policy": policy}
                elif operation == "settle":
                    phase = arguments.pop("fault_phase", None)
                    marker = arguments.pop("fault_marker", None)
                    if phase is not None:
                        if phase not in ("after_debit", "before_commit", "after_commit") or not marker:
                            raise ValueError("fault injection requires known phase and marker path")
                        marker_path = Path(marker).resolve()
                        # This local experiment permits fault markers only beside
                        # the database; no arbitrary server-side file writes.
                        if marker_path.parent != Path(db_path).resolve().parent:
                            raise ValueError("fault marker must be beside database")
                        def crash_hook(current):
                            if current == phase:
                                marker_path.write_text(json.dumps({"phase": phase, "pid": os.getpid(), "at_time": time.time()}), encoding="utf-8")
                                os._exit(91)
                        gate.fault_hook = crash_hook
                    # Explicit client timestamps are intentionally not accepted.
                    if "now" in arguments:
                        raise ValueError("server clock required")
                    result = gate.settle(**arguments)
                elif operation == "issue":
                    if "now" in arguments:
                        raise ValueError("server clock required")
                    result = gate.issue(**arguments)
                elif operation in ("invalidate", "refresh", "cleanup", "inspect", "stage"):
                    result = getattr(gate, operation)(**arguments)
                elif operation == "extend":
                    result = gate.extend_contract(**arguments)
                else:
                    raise ValueError("unknown operation")
                response = {"ok": True, "result": result}
            except (GateRejected, ValueError, TypeError, KeyError) as exc:
                reason = exc.reason if isinstance(exc, GateRejected) else str(exc)
                if gate is not None:
                    gate.log_reject(operation, arguments, reason)
                response = {"ok": False, "reason": reason}
            except Exception as exc:
                response = {"ok": False, "reason": "server_error:" + type(exc).__name__}
            finally:
                if gate is not None:
                    gate.close()
            body = json.dumps(response, allow_nan=False).encode("utf-8")
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    # Validate persisted policy before publishing readiness.
    with NetworkGateway(db_path, policy):
        pass
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    ready = {"host": "127.0.0.1", "port": server.server_port, "pid": os.getpid(), "policy": policy}
    Path(ready_file).write_text(json.dumps(ready), encoding="utf-8")
    server.serve_forever(poll_interval=0.05)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--policy", required=True, choices=POLICIES)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    serve(args.db, args.policy, args.ready_file, args.port)
