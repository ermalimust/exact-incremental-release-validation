#!/usr/bin/env python3
"""Shared-trace evaluation primitives for the FCS revision.

The module deliberately separates logical trace time from measured component
runtime.  It has no dependency on the frozen TOSEM experiment package.
"""

from __future__ import annotations

import hashlib
import json
import random
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple


@dataclass(frozen=True)
class Obligation:
    obligation_id: str
    effect_id: str
    kind: str
    local: bool
    terminal_time: float
    valid: bool


@dataclass(frozen=True)
class Effect:
    effect_id: str
    workflow_id: int
    plan_version: int
    readiness_time: float
    obligation_ids: Tuple[str, ...]


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    workflow_id: int
    step_id: int


@dataclass(frozen=True)
class Failure:
    failure_id: str
    root_artifact: str
    reveal_time: float


@dataclass(frozen=True)
class ImmutableTrace:
    seed: int
    effects: Tuple[Effect, ...]
    obligations: Tuple[Obligation, ...]
    artifacts: Tuple[Artifact, ...]
    dependency_edges: Tuple[Tuple[str, str], ...]
    failures: Tuple[Failure, ...]

    def canonical_payload(self) -> Dict[str, object]:
        return {
            "seed": self.seed,
            "effects": [asdict(x) for x in self.effects],
            "obligations": [asdict(x) for x in self.obligations],
            "artifacts": [asdict(x) for x in self.artifacts],
            "dependency_edges": [list(x) for x in self.dependency_edges],
            "failures": [asdict(x) for x in self.failures],
        }

    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


def _weighted_invalid(rng: random.Random, kind: str, invalid_rate: float) -> bool:
    multiplier = {
        "schema": 0.25,
        "semantic": 0.75,
        "claim": 1.15,
        "provenance": 1.00,
        "cross_dependency": 1.25,
    }[kind]
    return rng.random() < min(0.95, invalid_rate * multiplier)


def generate_trace(
    seed: int,
    num_workflows: int = 300,
    steps_per_workflow: int = 6,
    obligations_per_effect: int = 8,
    cross_fanout: int = 3,
    invalid_rate: float = 0.035,
) -> ImmutableTrace:
    """Generate a deterministic workflow trace with a complete known registry."""
    if num_workflows < 1 or steps_per_workflow < 2:
        raise ValueError("num_workflows >= 1 and steps_per_workflow >= 2 required")
    if obligations_per_effect < 4:
        raise ValueError("obligations_per_effect >= 4 required")
    if cross_fanout < 0:
        raise ValueError("cross_fanout must be nonnegative")

    rng = random.Random(seed)
    artifacts: List[Artifact] = []
    edges: Set[Tuple[str, str]] = set()
    effects: List[Effect] = []
    obligations: List[Obligation] = []
    failures: List[Failure] = []
    prior_final_artifacts: List[str] = []

    for wf in range(num_workflows):
        workflow_artifacts: List[str] = []
        for step in range(steps_per_workflow):
            aid = f"wf{wf}:s{step}"
            artifacts.append(Artifact(aid, wf, step))
            workflow_artifacts.append(aid)
            if step:
                edges.add((workflow_artifacts[step - 1], aid))

        final_artifact = workflow_artifacts[-1]
        if prior_final_artifacts and cross_fanout:
            parents = rng.sample(
                prior_final_artifacts,
                min(cross_fanout, len(prior_final_artifacts)),
            )
            for parent in parents:
                edges.add((parent, final_artifact))
        prior_final_artifacts.append(final_artifact)

        # Interleaved workflow readiness keeps global wait-all distinct from an
        # effect-scoped obligation closure without adding an artificial multiplier.
        readiness = round(2.0 + wf * 0.025 + rng.uniform(0.0, 1.5), 6)
        effect_id = f"effect:wf{wf}"
        obligation_ids: List[str] = []
        kinds = ["schema", "semantic", "claim", "provenance"]
        for i in range(obligations_per_effect):
            kind = kinds[i] if i < len(kinds) else (
                "cross_dependency" if i % 2 == 0 else "claim"
            )
            local = kind in {"schema", "semantic"}
            if local:
                delay = rng.uniform(0.05, 0.9)
            elif kind == "provenance":
                delay = rng.uniform(0.4, 2.5)
            else:
                delay = rng.uniform(0.6, 6.0)
            terminal_time = round(readiness + delay, 6)
            valid = not _weighted_invalid(rng, kind, invalid_rate)
            oid = f"{effect_id}:o{i}:{kind}"
            obligation_ids.append(oid)
            obligations.append(
                Obligation(oid, effect_id, kind, local, terminal_time, valid)
            )

        effects.append(Effect(effect_id, wf, 0, readiness, tuple(obligation_ids)))

        # A failed registered obligation is tied to one workflow artifact and
        # reveals contamination at the obligation's terminal time.
        invalid_obligations = [
            o for o in obligations[-obligations_per_effect:] if not o.valid
        ]
        for j, obligation in enumerate(invalid_obligations):
            upper = max(1, steps_per_workflow - 1)
            root_step = rng.randrange(upper)
            failures.append(
                Failure(
                    failure_id=f"failure:wf{wf}:{j}",
                    root_artifact=workflow_artifacts[root_step],
                    reveal_time=obligation.terminal_time,
                )
            )

    return ImmutableTrace(
        seed=seed,
        effects=tuple(effects),
        obligations=tuple(obligations),
        artifacts=tuple(artifacts),
        dependency_edges=tuple(sorted(edges)),
        failures=tuple(failures),
    )


@dataclass(frozen=True)
class Decision:
    policy: str
    effect_id: str
    action: str
    decision_time: float
    trace_hash: str
    premature: bool
    eventually_invalid: bool
    reason: str


def _indexes(trace: ImmutableTrace) -> Tuple[Dict[str, Obligation], Dict[str, Effect]]:
    return (
        {o.obligation_id: o for o in trace.obligations},
        {e.effect_id: e for e in trace.effects},
    )


def replay_policy(
    trace: ImmutableTrace,
    policy: str,
    timelock: float = 2.5,
) -> List[Decision]:
    """Replay one policy over the immutable trace."""
    allowed = {
        "readiness_only",
        "strong_local_guardrail",
        "fixed_timelock",
        "global_wait_all",
        "wasf",
    }
    if policy not in allowed:
        raise ValueError(f"unknown policy: {policy}")
    if timelock < 0:
        raise ValueError("timelock must be nonnegative")

    obligation_by_id, _ = _indexes(trace)
    trace_hash = trace.digest()
    global_terminal = max((o.terminal_time for o in trace.obligations), default=0.0)
    decisions: List[Decision] = []

    for effect in trace.effects:
        required = [obligation_by_id[x] for x in effect.obligation_ids]
        effect_terminal = max((o.terminal_time for o in required), default=effect.readiness_time)
        eventually_invalid = any(not o.valid for o in required)

        if policy == "readiness_only":
            decision_time = effect.readiness_time
            action = "release"
            reason = "final transaction ready"
        elif policy == "strong_local_guardrail":
            local = [o for o in required if o.local]
            decision_time = max(
                [effect.readiness_time] + [o.terminal_time for o in local]
            )
            if any(not o.valid for o in local):
                action = "abort"
                reason = "local validator rejected"
            else:
                action = "release"
                reason = "readiness and all local validators passed"
        elif policy == "fixed_timelock":
            decision_time = effect.readiness_time + timelock
            observed_invalid = any(
                (not o.valid) and o.terminal_time <= decision_time for o in required
            )
            action = "abort" if observed_invalid else "release"
            reason = (
                "invalid obligation observed before timer"
                if observed_invalid
                else f"fixed timer T={timelock:g} expired"
            )
        elif policy == "global_wait_all":
            decision_time = global_terminal
            action = "abort" if eventually_invalid else "release"
            reason = "all batch obligations terminal"
        else:
            decision_time = effect_terminal
            action = "abort" if eventually_invalid else "release"
            reason = "effect-scoped registered obligation closure terminal"

        released = action == "release"
        premature = released and decision_time < effect_terminal
        decisions.append(
            Decision(
                policy=policy,
                effect_id=effect.effect_id,
                action=action,
                decision_time=round(decision_time, 6),
                trace_hash=trace_hash,
                premature=premature,
                eventually_invalid=released and eventually_invalid,
                reason=reason,
            )
        )
    return decisions


def summarize_policy(trace: ImmutableTrace, decisions: Sequence[Decision]) -> Dict[str, object]:
    if not decisions:
        raise ValueError("decisions must be nonempty")
    _, effect_by_id = _indexes(trace)
    obligations = {o.obligation_id: o for o in trace.obligations}
    valid_effects = {
        e.effect_id
        for e in trace.effects
        if all(obligations[x].valid for x in e.obligation_ids)
    }
    released = [d for d in decisions if d.action == "release"]
    safe_released = [
        d for d in released if not d.premature and not d.eventually_invalid
    ]
    delays = [
        d.decision_time - effect_by_id[d.effect_id].readiness_time for d in released
    ]
    return {
        "seed": trace.seed,
        "trace_hash": trace.digest(),
        "policy": decisions[0].policy,
        "effects": len(trace.effects),
        "eventually_valid_effects": len(valid_effects),
        "released_effects": len(released),
        "safe_released_effects": len(safe_released),
        "premature_externalizations": sum(d.premature for d in decisions),
        "invalid_externalizations": sum(d.eventually_invalid for d in decisions),
        "safe_release_coverage": (
            len(safe_released) / len(valid_effects) if valid_effects else 0.0
        ),
        "mean_release_delay": sum(delays) / len(delays) if delays else 0.0,
        "max_release_delay": max(delays) if delays else 0.0,
    }


def descendants(root: str, adjacency: Mapping[str, Set[str]]) -> Set[str]:
    seen = {root}
    queue = deque([root])
    while queue:
        current = queue.popleft()
        for child in adjacency.get(current, set()):
            if child not in seen:
                seen.add(child)
                queue.append(child)
    return seen


def rollback_comparison(trace: ImmutableTrace) -> List[Dict[str, object]]:
    """Compare rollback scopes against the same generated contamination closure."""
    adjacency: Dict[str, Set[str]] = defaultdict(set)
    for parent, child in trace.dependency_edges:
        adjacency[parent].add(child)
    artifact_by_id = {a.artifact_id: a for a in trace.artifacts}
    contaminated: Set[str] = set()
    for failure in trace.failures:
        contaminated |= descendants(failure.root_artifact, adjacency)

    rollback_sets: Dict[str, Set[str]] = {
        "transaction_local": {f.root_artifact for f in trace.failures},
        "static_workflow_suffix": set(),
        "wasf_registered_provenance": set(),
    }
    for failure in trace.failures:
        root = artifact_by_id[failure.root_artifact]
        rollback_sets["static_workflow_suffix"] |= {
            a.artifact_id
            for a in trace.artifacts
            if a.workflow_id == root.workflow_id and a.step_id >= root.step_id
        }
        rollback_sets["wasf_registered_provenance"] |= descendants(
            failure.root_artifact, adjacency
        )

    rows: List[Dict[str, object]] = []
    for mechanism, rolled_back in rollback_sets.items():
        recovered = contaminated & rolled_back
        collateral = rolled_back - contaminated
        rows.append(
            {
                "seed": trace.seed,
                "trace_hash": trace.digest(),
                "mechanism": mechanism,
                "failures": len(trace.failures),
                "contaminated_artifacts": len(contaminated),
                "rollback_artifacts": len(rolled_back),
                "recovered_artifacts": len(recovered),
                "residual_contaminated_artifacts": len(contaminated - rolled_back),
                "artifact_recall": (
                    len(recovered) / len(contaminated) if contaminated else 1.0
                ),
                "artifact_precision": (
                    len(recovered) / len(rolled_back) if rolled_back else 1.0
                ),
                "collateral_rollback_rate": (
                    len(collateral) / len(rolled_back) if rolled_back else 0.0
                ),
            }
        )
    return rows


def online_rollback_replay(trace: ImmutableTrace) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    """Execute invalidation events against a live staged-artifact registry.

    Unlike :func:`rollback_comparison`, this routine does not calculate one
    offline set after all failures are known.  Artifacts enter a mutable staged
    registry, failures are consumed in reveal-time order, and each mechanism
    must remove its selected rollback scope immediately.  The returned audit
    rows make the per-event state transition inspectable.

    The generated registry is complete by construction.  Consequently, this
    experiment tests online rollback *execution* given complete provenance; it
    is not evidence that arbitrary dependencies can be discovered online.
    """
    adjacency: Dict[str, Set[str]] = defaultdict(set)
    for parent, child in trace.dependency_edges:
        adjacency[parent].add(child)
    artifact_by_id = {a.artifact_id: a for a in trace.artifacts}
    mechanisms = (
        "transaction_local",
        "static_workflow_suffix",
        "wasf_registered_provenance",
    )
    trace_hash = trace.digest()
    active = {name: set(artifact_by_id) for name in mechanisms}
    contaminated_seen: Set[str] = set()
    audit_rows: List[Dict[str, object]] = []

    for event_index, failure in enumerate(
        sorted(trace.failures, key=lambda item: (item.reveal_time, item.failure_id)),
        start=1,
    ):
        root = artifact_by_id[failure.root_artifact]
        event_contamination = descendants(failure.root_artifact, adjacency)
        contaminated_seen |= event_contamination
        scopes = {
            "transaction_local": {failure.root_artifact},
            "static_workflow_suffix": {
                artifact.artifact_id
                for artifact in trace.artifacts
                if artifact.workflow_id == root.workflow_id
                and artifact.step_id >= root.step_id
            },
            "wasf_registered_provenance": event_contamination,
        }
        for mechanism in mechanisms:
            before = len(active[mechanism])
            removed = active[mechanism] & scopes[mechanism]
            active[mechanism] -= scopes[mechanism]
            residual = active[mechanism] & contaminated_seen
            audit_rows.append(
                {
                    "seed": trace.seed,
                    "trace_hash": trace_hash,
                    "event_index": event_index,
                    "reveal_time": failure.reveal_time,
                    "failure_id": failure.failure_id,
                    "root_artifact": failure.root_artifact,
                    "mechanism": mechanism,
                    "active_before": before,
                    "removed_now": len(removed),
                    "active_after": len(active[mechanism]),
                    "residual_contaminated_after_event": len(residual),
                    "containment_invariant_holds": not residual,
                }
            )

    summaries: List[Dict[str, object]] = []
    for mechanism in mechanisms:
        residual = active[mechanism] & contaminated_seen
        removed_total = set(artifact_by_id) - active[mechanism]
        recovered = contaminated_seen & removed_total
        mechanism_events = [
            row for row in audit_rows if row["mechanism"] == mechanism
        ]
        summaries.append(
            {
                "seed": trace.seed,
                "trace_hash": trace_hash,
                "mechanism": mechanism,
                "invalidation_events": len(trace.failures),
                "contaminated_artifacts": len(contaminated_seen),
                "rollback_artifacts": len(removed_total),
                "recovered_artifacts": len(recovered),
                "residual_contaminated_artifacts": len(residual),
                "artifact_recall": (
                    len(recovered) / len(contaminated_seen)
                    if contaminated_seen else 1.0
                ),
                "events_satisfying_containment_invariant": sum(
                    bool(row["containment_invariant_holds"])
                    for row in mechanism_events
                ),
                "all_events_contained": all(
                    bool(row["containment_invariant_holds"])
                    for row in mechanism_events
                ),
            }
        )
    return summaries, audit_rows


def canonical_digest(values: Iterable[str]) -> str:
    payload = "\n".join(sorted(values)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ReleaseRecord:
    record_id: str
    issuer: str
    effect_id: str
    workflow_id: int
    plan_version: int
    obligation_digest: str
    evidence_digest: str
    issued_at: float


@dataclass(frozen=True)
class GatewayContext:
    effect_id: str
    workflow_id: int
    plan_version: int
    obligation_digest: str
    evidence_digest: str


class ReleaseController:
    def __init__(self) -> None:
        self._sequence = 0
        self._issued: Dict[str, ReleaseRecord] = {}

    def issue(
        self,
        context: GatewayContext,
        obligations_terminal_and_valid: bool,
        issued_at: float,
    ) -> ReleaseRecord:
        if not obligations_terminal_and_valid:
            raise PermissionError("registered obligation closure is not closed and valid")
        material = (
            f"{self._sequence}|{context.effect_id}|{context.workflow_id}|"
            f"{context.plan_version}|{context.obligation_digest}|"
            f"{context.evidence_digest}|{issued_at:.6f}"
        )
        record_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
        self._sequence += 1
        record = ReleaseRecord(
            record_id=record_id,
            issuer="wasf_controller",
            effect_id=context.effect_id,
            workflow_id=context.workflow_id,
            plan_version=context.plan_version,
            obligation_digest=context.obligation_digest,
            evidence_digest=context.evidence_digest,
            issued_at=issued_at,
        )
        self._issued[record.record_id] = record
        return record

    def was_issued(self, record: ReleaseRecord) -> bool:
        """Return whether *this controller* issued this exact immutable record."""
        return self._issued.get(record.record_id) == record


class ExclusiveEffectGateway:
    """Reference gateway that accepts exact controller-issued records once."""

    def __init__(self, controller: ReleaseController) -> None:
        self._controller = controller
        self._consumed: Set[str] = set()
        self.audit_log: List[Dict[str, object]] = []

    def _reject(self, reason: str, record_id: Optional[str]) -> Tuple[bool, str]:
        self.audit_log.append(
            {"accepted": False, "reason": reason, "record_id": record_id}
        )
        return False, reason

    def consume(
        self,
        context: GatewayContext,
        record: Optional[ReleaseRecord],
    ) -> Tuple[bool, str]:
        if record is None:
            return self._reject("missing_release_record", None)
        if not self._controller.was_issued(record):
            return self._reject("unregistered_or_forged_record", record.record_id)
        if record.record_id in self._consumed:
            return self._reject("record_already_consumed", record.record_id)
        if record.effect_id != context.effect_id:
            return self._reject("effect_binding_mismatch", record.record_id)
        if record.workflow_id != context.workflow_id:
            return self._reject("workflow_binding_mismatch", record.record_id)
        if record.plan_version != context.plan_version:
            return self._reject("plan_version_mismatch", record.record_id)
        if record.obligation_digest != context.obligation_digest:
            return self._reject("obligation_digest_mismatch", record.record_id)
        if record.evidence_digest != context.evidence_digest:
            return self._reject("evidence_digest_mismatch", record.record_id)

        self._consumed.add(record.record_id)
        self.audit_log.append(
            {"accepted": True, "reason": "accepted", "record_id": record.record_id}
        )
        return True, "accepted"
