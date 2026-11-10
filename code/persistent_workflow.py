"""Fixed registered dependency graph connected to one durable local ledger.

The graph is a trusted, complete declaration, not discovered ground truth.
All validity, revocation, token, staging and settlement state lives in the
DurableGateway database. This module compiles Registry into support contracts;
it does not run an independent in-memory release or rollback state machine.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from types import MappingProxyType
from typing import Callable, Optional

from durable_gateway import DurableGateway, GateRejected, require_effect_id
from integrated_controller import Registry


def compile_registry(registry: Registry) -> tuple[dict, dict[str, tuple[str, ...]]]:
    """Snapshot and validate a fixed DAG, then explicitly walk every ancestry.

    Public Registry fields are used; no private controller state is read.
    Artifact and obligation namespaces exactly match IntegratedController.
    """
    declaration = {
        "artifact_parents": {k: tuple(v) for k, v in registry.artifact_parents.items()},
        "artifact_obligations": {k: tuple(v) for k, v in registry.artifact_obligations.items()},
        "effect_artifacts": {k: tuple(v) for k, v in registry.effect_artifacts.items()},
        "effect_obligations": {k: tuple(v) for k, v in registry.effect_obligations.items()},
    }
    for field in ("effect_artifacts", "effect_obligations"):
        for effect_id in declaration[field]:
            require_effect_id(effect_id)
    parents = declaration["artifact_parents"]
    if any(parent not in parents for values in parents.values() for parent in values):
        raise ValueError("unknown artifact parent")
    if set(declaration["artifact_obligations"]) - set(parents):
        raise ValueError("obligations attached to an unknown artifact")
    if set(declaration["effect_obligations"]) - set(declaration["effect_artifacts"]):
        raise ValueError("obligations attached to an unknown effect")
    visited, active = set(), set()

    def validate(aid):
        if aid in active:
            raise ValueError("artifact dependency cycle")
        if aid in visited:
            return
        active.add(aid)
        for parent in parents[aid]:
            validate(parent)
        active.remove(aid)
        visited.add(aid)

    for aid in parents:
        validate(aid)
    supports = {}
    for effect, roots in declaration["effect_artifacts"].items():
        if not roots or any(root not in parents for root in roots):
            raise ValueError("unknown or empty effect artifact roots")
        ancestors, work = set(), list(roots)
        while work:
            aid = work.pop()
            if aid in ancestors:
                continue
            ancestors.add(aid)
            work.extend(parents[aid])
        obligations = set(declaration["effect_obligations"].get(effect, ()))
        for aid in ancestors:
            obligations.update(declaration["artifact_obligations"].get(aid, ()))
        supports[effect] = tuple(sorted({"a:" + a for a in ancestors} |
                                         {"o:" + o for o in obligations}))
    return declaration, supports


class PersistentWorkflow:
    """Compile a persisted Registry into the actual gateway's support sets.

    Initial evidence admission and effect configuration are trusted setup.
    Thereafter the registry is fixed. Reopen without a Registry loads the
    persisted declaration; supplying a different Registry is rejected.
    Time is evaluated after acquiring the gateway transaction's write lock;
    this is an evaluation timestamp, not a physical COMMIT deadline promise.
    """

    def __init__(self, path: str | Path, registry: Optional[Registry] = None,
                 *, clock: Callable[[], float] = time.time):
        self.gateway = DurableGateway(path, clock=clock)
        try:
            supplied = compile_registry(registry)[0] if registry is not None else None
            encoded = (json.dumps(supplied, sort_keys=True, separators=(",", ":"))
                       if supplied is not None else None)
            db = self.gateway.db
            db.execute("CREATE TABLE IF NOT EXISTS workflow_registry (singleton INTEGER PRIMARY KEY CHECK(singleton=1), declaration TEXT NOT NULL)")
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT declaration FROM workflow_registry WHERE singleton=1").fetchone()
                if row is None:
                    if encoded is None:
                        raise GateRejected("registry_required_for_initialization")
                    db.execute("INSERT INTO workflow_registry VALUES (1, ?)", (encoded,))
                else:
                    if encoded is not None and row["declaration"] != encoded:
                        raise GateRejected("registered_graph_is_immutable")
                    encoded = row["declaration"]
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            restored = json.loads(encoded)
            self.declaration, supports = compile_registry(Registry(**restored))
            self.supports = MappingProxyType(supports)
            self.registry_digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            self.artifacts = frozenset(self.declaration["artifact_parents"])
            obligations = {o for values in self.declaration["artifact_obligations"].values() for o in values}
            obligations.update(o for values in self.declaration["effect_obligations"].values() for o in values)
            self.obligations = frozenset(obligations)
        except BaseException:
            self.gateway.close()
            raise

    def close(self):
        self.gateway.close()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def support(self, effect_id: str) -> tuple[str, ...]:
        return self.supports[effect_id]

    def create_account(self, account_id: str, balance: int = 0):
        self.gateway.create_account(account_id, balance)

    def admit_valid_artifact(self, artifact_id: str, expires_at: float):
        if artifact_id not in self.artifacts:
            raise GateRejected("artifact_not_registered")
        return self.gateway.put_subject("a:" + artifact_id, expires_at)

    def admit_valid_obligation(self, obligation_id: str, expires_at: float):
        if obligation_id not in self.obligations:
            raise GateRejected("obligation_not_registered")
        return self.gateway.put_subject("o:" + obligation_id, expires_at)

    def configure_effect(self, effect_id: str, payer: str, recipient: str,
                         amount: int, payload: object):
        """Create/retry trusted setup using the complete compiled support.

        Setup can be retried if a process stops between contract creation and
        payload staging. Setup itself is not advertised as one atomic batch.
        """
        support = self.support(effect_id)
        row = self.gateway.db.execute("SELECT * FROM effects WHERE effect_id=?", (effect_id,)).fetchone()
        if row is None:
            self.gateway.create_effect(effect_id, payer, recipient, amount, support)
        else:
            persisted = tuple(r[0] for r in self.gateway.db.execute(
                "SELECT subject_id FROM effect_support WHERE effect_id=? ORDER BY subject_id", (effect_id,)))
            if (row["payer"], row["recipient"], row["amount"], persisted) != (payer, recipient, amount, support):
                raise GateRejected("effect_configuration_is_immutable")
        return self.gateway.stage(effect_id, payload)

    def issue(self, effect_id: str, *, now: Optional[float] = None, ttl: float = 30.0):
        self.support(effect_id)
        return self.gateway.issue(effect_id, now=now, ttl=ttl)

    def settle(self, effect_id: str, token: str, *, now: Optional[float] = None):
        self.support(effect_id)
        return self.gateway.settle(token, now=now, expected_effect_id=effect_id)

    def invalidate_artifact(self, artifact_id: str):
        if artifact_id not in self.artifacts:
            raise GateRejected("artifact_not_registered")
        return self.gateway.invalidate("a:" + artifact_id)

    def invalidate_obligation(self, obligation_id: str):
        if obligation_id not in self.obligations:
            raise GateRejected("obligation_not_registered")
        return self.gateway.invalidate("o:" + obligation_id)

    def cleanup_invalidated(self) -> dict:
        """Derive affected effects from durable tombstones; no volatile queue.

        Safety does not await this walk. Each cleanup physically deletes one
        staged effect payload. This does not delete artifact database records
        or reverse a settled transfer; artifact subjects remain as tombstones.
        """
        state = self.gateway.inspect()
        invalid = {s["subject_id"] for s in state["subjects"] if not s["valid"]}
        # These are the exact current contracts used by settlement, including
        # legal append-only extensions beyond the originally compiled graph.
        current_support = {}
        for membership in state["effect_support"]:
            current_support.setdefault(membership["effect_id"], set()).add(membership["subject_id"])
        cancelled, committed, removed = [], [], 0
        for effect in state["effects"]:
            eid = effect["effect_id"]
            if not invalid.intersection(current_support.get(eid, ())):
                continue
            if effect["state"] == "settled":
                committed.append(eid)
            elif effect["state"] == "pending":
                removed += self.gateway.cleanup(eid)
                cancelled.append(eid)
        return {"cancelled_effects": cancelled, "stage_rows_deleted": removed,
                "already_committed_effects": committed}

    def inspect(self) -> dict:
        state = self.gateway.inspect()
        state["registry_digest"] = self.registry_digest
        state["compiled_support"] = {e: list(s) for e, s in sorted(self.supports.items())}
        return state
