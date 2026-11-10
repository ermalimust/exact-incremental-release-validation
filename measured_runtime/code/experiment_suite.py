#!/usr/bin/env python3
"""Reproducible, event-prefix evaluation of the integrated release controller.

The oracle has no dependency on the controller: its only inputs are frozen
declarations and the common input history. Logical trace time is not runtime.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import random
import statistics
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from time import perf_counter_ns
from typing import Any

POLICIES = ("support_epoch", "global_epoch", "full_recheck", "own_only", "no_revalidate", "no_expiry")
SAFE_POLICIES = POLICIES[:3]
TOPOLOGIES = ("sparse", "dense", "hub", "all_valid")
DEFAULT_SEEDS = (20260700,) + tuple(range(20261027, 20261047))


@dataclass(frozen=True)
class ArtifactDeclaration:
    artifact_id: str
    workflow_id: int
    parents: tuple[str, ...]
    obligations: tuple[str, ...]


@dataclass(frozen=True)
class EffectDeclaration:
    effect_id: str
    workflow_id: int
    consumes: tuple[str, ...]
    obligations: tuple[str, ...]


@dataclass(frozen=True)
class InputEvent:
    time: float
    sequence: int
    kind: str
    subject: str = ""
    state: str = ""
    valid_until: float | None = None
    attempt: int = 0


@dataclass(frozen=True)
class EventTrace:
    seed: int
    topology: str
    artifacts: tuple[ArtifactDeclaration, ...]
    effects: tuple[EffectDeclaration, ...]
    events: tuple[InputEvent, ...]
    generator: str = "bounded_cluster_v1"

    def payload(self) -> dict[str, Any]:
        return asdict(self)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class OracleVerdict:
    safe: bool
    reasons: tuple[str, ...]
    support_artifacts: tuple[str, ...]
    support_obligations: tuple[str, ...]


class PrefixOracle:
    """Independent specification evaluator, never reading runtime state.

    Declared provenance is expanded recursively. Each query reconstructs current
    evidence/readiness/revocations from a prefix of external input events. Neither
    tokens, runtime closures, rollback decisions, nor acceptance enter the truth.
    """
    def __init__(self, trace: EventTrace):
        self.trace = trace
        self.artifacts = {a.artifact_id: a for a in trace.artifacts}
        self.effects = {e.effect_id: e for e in trace.effects}
        self._support_cache: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}

    def support(self, effect_id: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        if effect_id in self._support_cache:
            return self._support_cache[effect_id]
        effect = self.effects[effect_id]
        seen: set[str] = set()
        visiting: set[str] = set()
        obligations = set(effect.obligations)

        def visit(aid: str) -> None:
            if aid in visiting:
                raise ValueError("cyclic provenance declaration")
            if aid in seen:
                return
            visiting.add(aid)
            artifact = self.artifacts[aid]
            for parent in artifact.parents:
                visit(parent)
            obligations.update(artifact.obligations)
            visiting.remove(aid)
            seen.add(aid)

        for aid in effect.consumes:
            visit(aid)
        answer = tuple(sorted(seen)), tuple(sorted(obligations))
        self._support_cache[effect_id] = answer
        return answer

    def state_at(self, event_index: int) -> tuple[dict, dict, set]:
        evidence: dict[str, tuple[str, float]] = {}
        readiness: dict[str, bool] = {}
        invalidated: set[str] = set()
        for event in self.trace.events[:event_index + 1]:
            if event.kind == "resolve":
                if evidence.get(event.subject, (None,))[0] == "invalid" and event.state != "invalid":
                    raise ValueError("revoked evidence identity cannot be restored")
                evidence[event.subject] = (event.state, math.inf if event.valid_until is None else event.valid_until)
            elif event.kind == "readiness":
                readiness[event.subject] = event.state == "ready"
            elif event.kind == "invalidate":
                invalidated.add(event.subject)
        return evidence, readiness, invalidated

    def evaluate(self, effect_id: str, event_index: int) -> OracleVerdict:
        evidence, readiness, invalidated = self.state_at(event_index)
        return self._evaluate_state(effect_id, self.trace.events[event_index].time, evidence, readiness, invalidated)

    def _evaluate_state(self, effect_id: str, now: float, evidence: dict, readiness: dict, invalidated: set) -> OracleVerdict:
        support, obligations = self.support(effect_id)
        reasons = []
        if not readiness.get(effect_id, False):
            reasons.append("not_ready")
        if set(support).intersection(invalidated):
            reasons.append("invalid_artifact")
        for oid in obligations:
            state, deadline = evidence.get(oid, ("unresolved", math.inf))
            if state != "valid":
                reasons.append("invalid_obligation" if state == "invalid" else "unresolved_obligation")
            elif now >= deadline:
                reasons.append("expired_evidence")
        return OracleVerdict(not reasons, tuple(sorted(set(reasons))), support, obligations)

    def settlement_truth(self) -> dict[int, OracleVerdict]:
        """One forward specification replay, equivalent to evaluate(prefix)."""
        evidence: dict[str, tuple[str, float]] = {}
        readiness: dict[str, bool] = {}
        invalidated: set[str] = set()
        verdicts = {}
        for index, event in enumerate(self.trace.events):
            if event.kind == "resolve":
                if evidence.get(event.subject, (None,))[0] == "invalid" and event.state != "invalid":
                    raise ValueError("revoked evidence identity cannot be restored")
                evidence[event.subject] = (event.state, math.inf if event.valid_until is None else event.valid_until)
            elif event.kind == "readiness":
                readiness[event.subject] = event.state == "ready"
            elif event.kind == "invalidate":
                invalidated.add(event.subject)
            elif event.kind == "settle":
                verdicts[index] = self._evaluate_state(event.subject, event.time, evidence, readiness, invalidated)
        return verdicts

    def contaminated_artifacts(self, event_index: int) -> set[str]:
        """Fixed-point dataflow oracle, independent of controller BFS rollback."""
        evidence, _, revoked = self.state_at(event_index)
        revoked.update(a.artifact_id for a in self.trace.artifacts if any(evidence.get(o, (None,))[0] == "invalid" for o in a.obligations))
        changed = True
        while changed:
            before = len(revoked)
            for artifact in self.trace.artifacts:
                if any(parent in revoked for parent in artifact.parents):
                    revoked.add(artifact.artifact_id)
            changed = len(revoked) != before
        return revoked


def generate_event_trace(seed: int, topology: str = "sparse", n_effects: int = 120) -> EventTrace:
    """Bounded clusters prevent dense failures swallowing the entire workload.

    Every method receives exactly the same declarations, events, and two fixed
    issue/settle opportunities. No method gets oracle results or future events.
    """
    if topology not in TOPOLOGIES or n_effects < 12:
        raise ValueError("known topology and at least 12 effects required")
    rng = random.Random(seed)
    artifacts = []
    effects = []
    pending: list[InputEvent] = []
    cluster_size = 12

    def add(time: float, kind: str, subject: str = "", state: str = "", valid_until: float | None = None, attempt: int = 0) -> None:
        pending.append(InputEvent(round(time, 6), len(pending), kind, subject, state, valid_until, attempt))

    for i in range(n_effects):
        start = (i // cluster_size) * cluster_size
        previous = list(range(start, i))
        extra: list[str] = []
        if previous:
            if topology in ("sparse", "all_valid") and rng.random() < 0.35:
                extra = [f"a{rng.choice(previous)}:leaf"]
            elif topology == "dense":
                extra = [f"a{p}:leaf" for p in rng.sample(previous, min(3, len(previous))) ]
            elif topology == "hub" and i - start < 9:
                extra = [f"a{start}:root"]
        root, middle, leaf = f"a{i}:root", f"a{i}:middle", f"a{i}:leaf"
        oid, direct_oid, eid = f"o{i}:source", f"o{i}:effect", f"e{i}"
        artifacts.extend((ArtifactDeclaration(root, i, (), (oid,)), ArtifactDeclaration(middle, i, (root,), ()), ArtifactDeclaration(leaf, i, tuple([middle] + extra), ())))
        effects.append(EffectDeclaration(eid, i, (leaf,), (direct_oid,)))
        expiry_case = topology != "all_valid" and i % 17 == 11
        add(0.8 + rng.random() * 0.6, "resolve", oid, "valid", 4.7 if expiry_case else None)
        add(1.4 + rng.random() * 0.4, "resolve", direct_oid, "valid")
        add(2.0 + rng.random() * 0.2, "readiness", eid, "ready")
        add(3.0 + rng.random() * 0.3, "issue", eid)
        # A subset settles before the revocation. Later revocation is logged as
        # an exposure, never mislabeled as a preventable settlement violation.
        first_settle = 3.5 + rng.random() * 0.3 if i % 7 == 6 else 5.0 + rng.random() * 0.8
        add(first_settle, "settle", eid)
        if expiry_case:
            add(6.5, "resolve", oid, "valid")
        if topology != "all_valid" and i % 19 == 8:
            # A benign relevant refresh exposes the conservative cost of version
            # binding: full state recheck can accept while a token must be renewed.
            add(4.3, "resolve", oid, "valid")
        if topology != "all_valid" and i % 23 == 16:
            add(4.6, "readiness", eid, "not_ready")
            add(6.6, "readiness", eid, "ready")
        # Retry opportunities are input, not method-specific scheduler rewards.
        add(7.0 + rng.random() * 0.1, "issue", eid, attempt=1)
        add(8.0 + rng.random() * 0.1, "settle", eid, attempt=1)

    if topology != "all_valid":
        for cluster in range((n_effects + cluster_size - 1) // cluster_size):
            # Odd clusters remain clean, including when cross-link fanout is high.
            if cluster % 2:
                continue
            root = cluster * cluster_size
            add(2.5 if cluster % 4 == 2 else 4.4 + rng.random() * 0.1, "invalidate", f"a{root}:root")
        # Rollback is intentionally later than the first settlement: admission
        # must honor tombstones before background materialization deletion.
        add(6.1, "rollback")
        # One late event documents the scope limit after irreversible settlement.
        late = min(n_effects - 1, 13)
        add(9.0, "invalidate", f"a{late}:root")
        add(9.1, "rollback")
    return EventTrace(seed, topology, tuple(artifacts), tuple(effects), tuple(sorted(pending, key=lambda x: (x.time, x.sequence))))


def make_registry(trace: EventTrace):
    from integrated_controller import Registry
    return Registry(artifact_parents={a.artifact_id: a.parents for a in trace.artifacts}, artifact_obligations={a.artifact_id: a.obligations for a in trace.artifacts}, effect_artifacts={e.effect_id: e.consumes for e in trace.effects}, effect_obligations={e.effect_id: e.obligations for e in trace.effects})


def replay(trace: EventTrace, policy: str, truth: dict[int, OracleVerdict] | None = None, collect: bool = True) -> tuple[dict, list[dict], list[dict]]:
    from integrated_controller import IntegratedController
    setup_start = perf_counter_ns()
    controller = IntegratedController(make_registry(trace), policy=policy)
    setup_ns = perf_counter_ns() - setup_start
    tokens: dict[tuple[str, int], Any] = {}
    accepted: dict[str, tuple[float, bool]] = {}
    first_attempt: dict[str, float] = {}
    outcomes: list[dict] = []
    audits: list[dict] = []
    methods_ns = 0
    calls = Counter()
    reasons = Counter()
    retries = 0
    false_accepts = 0
    safe_stale_global = 0
    safe_stale_support = 0
    late_exposures: set[str] = set()
    rollback_removed: set[str] = set()
    rollback_residual = 0
    rollback_collateral = 0
    digest = trace.digest() if collect else ""
    oracle = PrefixOracle(trace) if collect else None
    prefix = {"seed": trace.seed, "topology": trace.topology, "policy": policy, "trace_hash": digest}
    for index, event in enumerate(trace.events):
        result: Any = None
        action = event.kind
        reason = ""
        if event.kind in ("issue", "settle") and event.subject in accepted:
            continue
        call_start = perf_counter_ns()
        if event.kind == "resolve":
            result = controller.resolve(event.subject, event.state, valid_until=math.inf if event.valid_until is None else event.valid_until)
        elif event.kind == "readiness":
            result = controller.set_ready(event.subject, event.state == "ready")
        elif event.kind == "invalidate":
            result = controller.invalidate(event.subject)
        elif event.kind == "issue":
            result = controller.issue(event.subject, now=event.time)
            tokens[(event.subject, event.attempt)] = result
        elif event.kind == "settle":
            token = tokens.get((event.subject, event.attempt))
            if token is None:
                result, reason = False, "no_issued_token"
            else:
                result, reason = controller.settle(event.subject, token, now=event.time)
        elif event.kind == "rollback":
            result = controller.rollback_pending()
        else:
            raise ValueError(event.kind)
        methods_ns += perf_counter_ns() - call_start
        calls[action] += 1
        if event.kind == "issue":
            first_attempt.setdefault(event.subject, event.time)
            if event.attempt:
                retries += 1
            reason = "issued" if result is not None else "issue_denied"
        elif event.kind == "settle":
            verdict = truth[index] if truth is not None else None
            safe = verdict.safe if verdict is not None else True
            safe_stale_global += int(safe and reason == "stale_global")
            safe_stale_support += int(safe and reason == "stale_support")
            if result:
                accepted[event.subject] = (event.time, safe)
                false_accepts += int(not safe)
            reasons[reason] += 1
            if collect:
                outcomes.append({**prefix, "event_index": index, "effect_id": event.subject, "attempt": event.attempt, "logical_time": event.time, "accepted": bool(result), "controller_reason": reason, "oracle_safe": safe, "oracle_reasons": ";".join(verdict.reasons) if verdict else "", "support_artifacts": len(verdict.support_artifacts) if verdict else 0, "support_obligations": len(verdict.support_obligations) if verdict else 0})
        elif event.kind == "invalidate" and collect:
            for eid in accepted:
                if event.subject in oracle.support(eid)[0]:
                    late_exposures.add(eid)
        elif event.kind == "rollback" and collect:
            rollback_removed.update(result or ())
            expected = oracle.contaminated_artifacts(index)
            actual_staged = controller.staged_artifacts()
            all_artifacts = set(oracle.artifacts)
            rollback_residual += len(expected & actual_staged)
            rollback_collateral += len((all_artifacts - actual_staged) - expected)
            if rollback_removed != all_artifacts - actual_staged:
                raise AssertionError("Reported rollback removals disagree with staged objects")
        if collect:
            audits.append({**prefix, "event_index": index, "time": event.time, "kind": event.kind, "subject": event.subject, "attempt": event.attempt, "reason": reason, "accepted": bool(result) if event.kind == "settle" else None, "rolled_back": sorted(result) if event.kind == "rollback" and result is not None else []})
    eligible = set()
    first_opportunity: dict[str, float] = {}
    if truth:
        for index, verdict in truth.items():
            event = trace.events[index]
            if verdict.safe:
                eligible.add(event.subject)
                first_opportunity.setdefault(event.subject, event.time)
    safe_released = {eid for eid, (_, safe) in accepted.items() if safe}
    comparable_delays = [accepted[eid][0] - first_opportunity[eid] for eid in safe_released & eligible]
    metrics = dict(getattr(controller, "metrics", {}))
    summary = {**prefix, "effects": len(trace.effects), "artifacts": len(trace.artifacts), "events": len(trace.events), "accepted": len(accepted), "false_accepts": false_accepts, "eligible_effects": len(eligible), "safe_released": len(safe_released), "safe_coverage": len(safe_released & eligible) / len(eligible) if eligible else None, "retry_issues": retries, "stale_global_rejections": reasons["stale_global"], "stale_support_rejections": reasons["stale_support"], "safe_stale_global_rejections": safe_stale_global, "safe_stale_support_rejections": safe_stale_support, "late_revocation_exposures": len(late_exposures), "rollback_residual_sum": rollback_residual, "rollback_collateral_sum": rollback_collateral, "mean_extra_logical_delay": statistics.mean(comparable_delays) if comparable_delays else None, "controller_runtime_ms": methods_ns / 1e6, "setup_runtime_ms": setup_ns / 1e6, "controller_calls": sum(calls.values()), "runtime_metrics": metrics, "rejection_counts": dict(reasons)}
    for key in ("predicate_checks", "version_checks", "cleanup_subject_visits", "settle_attempts", "issue_attempts", "tokens_issued"):
        summary[key] = metrics.get(key, 0)
    return summary, outcomes, audits


def trace_stats(trace: EventTrace, truth: dict[int, OracleVerdict]) -> dict:
    oracle = PrefixOracle(trace)
    initial = [v for i, v in truth.items() if trace.events[i].attempt == 0]
    final = [v for i, v in truth.items() if trace.events[i].attempt == 1]
    support_sizes = [len(oracle.support(e.effect_id)[0]) for e in trace.effects]
    return {"seed": trace.seed, "topology": trace.topology, "trace_hash": trace.digest(), "effects": len(trace.effects), "artifacts": len(trace.artifacts), "edges": sum(len(a.parents) for a in trace.artifacts), "cross_workflow_edges": sum(int(oracle.artifacts[p].workflow_id != a.workflow_id) for a in trace.artifacts for p in a.parents), "initial_safe": sum(v.safe for v in initial), "final_safe": sum(v.safe for v in final), "initial_safe_fraction": statistics.mean(v.safe for v in initial), "final_safe_fraction": statistics.mean(v.safe for v in final), "mean_support_artifacts": statistics.mean(support_sizes), "max_support_artifacts": max(support_sizes), "invalidations": sum(e.kind == "invalidate" for e in trace.events), "events": len(trace.events)}


def mean_ci(values: list[float], seed: int = 90210, replicates: int = 2000) -> dict:
    """Nonparametric bootstrap over independent seeds, not effects."""
    if not values:
        return {"mean": None, "ci95_low": None, "ci95_high": None, "n_seeds": 0}
    rng = random.Random(seed)
    boot = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(replicates))
    return {"mean": statistics.mean(values), "ci95_low": boot[int(.025 * replicates)], "ci95_high": boot[int(.975 * replicates) - 1], "n_seeds": len(values)}


def summarize(rows: list[dict]) -> list[dict]:
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["topology"], row["policy"])].append(row)
    answer = []
    for (topology, policy), members in sorted(grouped.items()):
        output = {"topology": topology, "policy": policy, "n_seeds": len(members)}
        for field in ("effects", "accepted", "false_accepts", "eligible_effects", "safe_released", "retry_issues", "stale_global_rejections", "safe_stale_global_rejections", "safe_stale_support_rejections", "late_revocation_exposures", "rollback_residual_sum", "rollback_collateral_sum", "predicate_checks", "version_checks", "cleanup_subject_visits"):
            output[field + "_total"] = sum(m[field] for m in members)
        for field in ("safe_coverage", "mean_extra_logical_delay", "controller_runtime_ms", "setup_runtime_ms", "stale_global_rejections", "retry_issues"):
            for suffix, value in mean_ci([m[field] for m in members if m[field] is not None]).items():
                if suffix != "n_seeds":
                    output[field + "_" + suffix] = value
        answer.append(output)
    return answer


def paired_comparisons(rows: list[dict]) -> list[dict]:
    answer = []
    for topology in TOPOLOGIES:
        scoped = {(r["seed"], r["policy"]): r for r in rows if r["topology"] == topology}
        seeds = sorted({seed for seed, _ in scoped})
        for baseline in ("global_epoch", "full_recheck"):
            for metric in ("retry_issues", "mean_extra_logical_delay", "controller_runtime_ms", "predicate_checks", "version_checks"):
                values = [scoped[(seed, "support_epoch")][metric] - scoped[(seed, baseline)][metric] for seed in seeds]
                answer.append({"topology": topology, "method": "support_epoch", "baseline": baseline, "metric": metric, "difference": "support_epoch minus baseline", **mean_ci(values)})
    return answer


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    columns = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, sort_keys=True) if isinstance(v, (dict, list, tuple)) else v for k, v in row.items()})


def legacy_regression(output_dir: Path) -> dict:
    """Recover the old seed discrepancy without redefining old results as new."""
    import unified_replay as old
    legacy = old.generate_trace(20260700)
    parents: dict[str, list[str]] = defaultdict(list)
    for parent, child in legacy.dependency_edges:
        parents[child].append(parent)
    by_workflow = {e.workflow_id: e for e in legacy.effects}
    final_by_workflow = {}
    for artifact in legacy.artifacts:
        previous = final_by_workflow.get(artifact.workflow_id)
        if previous is None or artifact.step_id > previous.step_id:
            final_by_workflow[artifact.workflow_id] = artifact
    declarations = tuple(ArtifactDeclaration(a.artifact_id, a.workflow_id, tuple(parents[a.artifact_id]), tuple(by_workflow[a.workflow_id].obligation_ids) if a == final_by_workflow[a.workflow_id] else ()) for a in legacy.artifacts)
    effects = tuple(EffectDeclaration(e.effect_id, e.workflow_id, (final_by_workflow[e.workflow_id].artifact_id,), ()) for e in legacy.effects)
    events: list[InputEvent] = []
    for o in legacy.obligations:
        events.append(InputEvent(o.terminal_time, len(events), "resolve", o.obligation_id, "valid" if o.valid else "invalid"))
    for e in legacy.effects:
        events.append(InputEvent(e.readiness_time, len(events), "readiness", e.effect_id, "ready"))
    for failure in legacy.failures:
        events.append(InputEvent(failure.reveal_time, len(events), "invalidate", failure.root_artifact))
    decisions = old.replay_policy(legacy, "wasf")
    for d in decisions:
        events.append(InputEvent(d.decision_time, len(events), "settle", d.effect_id))
    trace = EventTrace(legacy.seed, "legacy_regression", declarations, effects, tuple(sorted(events, key=lambda e: (e.time, e.sequence))), "legacy_explicit_final_artifact_adapter_v1")
    oracle = PrefixOracle(trace)
    verdicts = oracle.settlement_truth()
    decision_by_id = {d.effect_id: d for d in decisions}
    witnesses = []
    for index, verdict in verdicts.items():
        event = trace.events[index]
        decision = decision_by_id[event.subject]
        if decision.action == "release" and not verdict.safe:
            witnesses.append({"effect_id": event.subject, "logical_time": event.time, "old_action": decision.action, "old_flag_invalid": decision.eventually_invalid, "oracle_reasons": ";".join(verdict.reasons), "oracle_support_artifacts": len(verdict.support_artifacts), "trace_hash": trace.digest()})
    write_csv(output_dir / "legacy_20260700_counterexamples.csv", witnesses)
    (output_dir / "legacy_20260700_explicit_trace.json").write_text(json.dumps(trace.payload(), ensure_ascii=False, indent=2), encoding="utf-8")
    answer = {"seed": legacy.seed, "legacy_trace_hash": legacy.digest(), "explicit_trace_hash": trace.digest(), "effects": len(effects), "old_releases": sum(d.action == "release" for d in decisions), "unsafe_at_old_release_prefix": len(witnesses), "caveat": "The legacy generator omitted consumes/artifact obligations. This adapter explicitly assumes each effect consumes its workflow final artifact and each final artifact carries that workflow's registered obligations. It is a regression construction, not a claim that the missing mapping existed in the submitted implementation."}
    (output_dir / "legacy_regression_summary.json").write_text(json.dumps(answer, indent=2), encoding="utf-8")
    external = [e for e in trace.events if e.kind != "settle"]
    end = max(e.time for e in external)
    repaired_events = list(external)
    for decision in decisions:
        for attempt, issue_time in ((0, decision.decision_time), (1, end + 1)):
            repaired_events.append(InputEvent(issue_time, len(repaired_events), "issue", decision.effect_id, attempt=attempt))
            repaired_events.append(InputEvent(issue_time + 0.000001, len(repaired_events), "settle", decision.effect_id, attempt=attempt))
    repaired_events.append(InputEvent(end + 2, len(repaired_events), "rollback"))
    repaired = EventTrace(trace.seed, trace.topology, trace.artifacts, trace.effects, tuple(sorted(repaired_events, key=lambda e: (e.time, e.sequence))), "legacy_integrated_replay_v1")
    repaired_truth = PrefixOracle(repaired).settlement_truth()
    repaired_rows = []
    for policy in SAFE_POLICIES:
        summary, outcomes, logs = replay(repaired, policy, repaired_truth)
        repaired_rows.append(summary)
        write_csv(output_dir / f"legacy_20260700_{policy}_outcomes.csv", outcomes)
        with (output_dir / f"legacy_20260700_{policy}_events.jsonl").open("w", encoding="utf-8") as handle:
            for row in logs:
                handle.write(json.dumps(row, separators=(",", ":")) + "\n")
        if summary["false_accepts"] or summary["rollback_residual_sum"] or summary["rollback_collateral_sum"]:
            raise AssertionError("Legacy regression failed")
    write_csv(output_dir / "legacy_20260700_repaired_metrics.csv", repaired_rows)
    answer["repaired_trace_hash"] = repaired.digest()
    answer["repaired_policy_false_accepts"] = {r["policy"]: r["false_accepts"] for r in repaired_rows}
    answer["repaired_policy_accepted"] = {r["policy"]: r["accepted"] for r in repaired_rows}
    answer["witness_reason_counts"] = dict(Counter(reason for w in witnesses for reason in w["oracle_reasons"].split(";")))
    (output_dir / "legacy_20260700_repaired_trace.json").write_text(json.dumps(repaired.payload(), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    (output_dir / "legacy_regression_summary.json").write_text(json.dumps(answer, indent=2), encoding="utf-8")
    return answer


def run_benchmarks(output_dir: Path, repeats: int = 5) -> list[dict]:
    rows = []
    for size in (24, 120, 480):
        for topology in ("sparse", "dense", "hub"):
            trace = generate_event_trace(20261027, topology, size)
            for policy in SAFE_POLICIES:
                replay(trace, policy, collect=False)  # warmup, excluded
            for repetition in range(repeats):
                order = list(SAFE_POLICIES)
                random.Random(1000 + repetition).shuffle(order)
                for policy in order:
                    start = perf_counter_ns()
                    summary, _, _ = replay(trace, policy, collect=False)
                    total_ms = (perf_counter_ns() - start) / 1e6
                    rows.append({"effects": size, "topology": topology, "policy": policy, "repetition": repetition, "controller_calls_ms": summary["controller_runtime_ms"], "setup_ms": summary["setup_runtime_ms"], "full_replay_ms": total_ms, "controller_calls": summary["controller_calls"], "metrics": summary["runtime_metrics"]})
    write_csv(output_dir / "runtime_benchmark_raw.csv", rows)
    return rows


def write_paper_tables(output_dir: Path, results: list[dict], aggregates: list[dict]) -> None:
    """Generate compact LaTeX tables from this run, with no hand-entered values."""
    names = {"support_epoch": "WASF support versions", "global_epoch": "Global epoch", "full_recheck": "Full state recheck", "own_only": "No transitive support", "no_revalidate": "No final revalidation", "no_expiry": "No expiry check"}
    lines = [r"% Generated by code/experiment_suite.py; see results/integrated_suite/manifest.json.", r"\begin{table}[t]", r"\centering\footnotesize", r"\setlength{\tabcolsep}{3pt}", r"\caption{Integrated event-prefix evaluation: 84 synthetic traces, 120 effects per trace, and 21 seeds per topology. Unsafe means accepted despite an invalid admitted-event prefix. Coverage is the percentage of effects safely released among effects eligible at one of the two common settlement opportunities. The last three rows are diagnostic ablations.}", r"\label{tab:integrated-results}", r"\begin{tabular}{lrrr}", r"\toprule", r"Method & Released & Unsafe & Coverage (\%) \\", r"\midrule"]
    for policy in POLICIES:
        selected = [r for r in results if r["policy"] == policy]
        released = sum(r["accepted"] for r in selected)
        unsafe = sum(r["false_accepts"] for r in selected)
        coverage = 100 * sum(r["safe_released"] for r in selected) / sum(r["eligible_effects"] for r in selected)
        if policy == "own_only":
            lines.append(r"\midrule")
        lines.append(f"{names[policy]} & {released:,} & {unsafe:,} & {coverage:.2f}" + r" \\")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    safety_table = "\n".join(lines) + "\n"
    lines = [r"% Generated by code/experiment_suite.py; see results/integrated_suite/aggregate_ci.csv.", r"\begin{table*}[t]", r"\centering\footnotesize", r"\setlength{\tabcolsep}{4pt}", r"\caption{Selectivity and local execution cost for the three equally informed safe methods. Rejects count epoch rejection while the independent oracle still permits settlement. Extra delay is measured in synthetic logical-time units relative to the first eligible scheduled settlement. Controller time is measured with \texttt{perf\_counter\_ns}, excludes setup and oracle evaluation, and is not blockchain latency. Means and seed-bootstrap 95\% intervals use 21 seeds. All methods use cached complete supports.}", r"\label{tab:integrated-cost}", r"\begin{tabular}{llrrr}", r"\toprule", r"Topology & Method & Safe epoch rejects (total) & Extra logical delay [95\% CI] & Controller ms [95\% CI] \\", r"\midrule"]
    index = {(r["topology"], r["policy"]): r for r in aggregates}
    for topology in TOPOLOGIES:
        for policy in SAFE_POLICIES:
            row = index[(topology, policy)]
            delay = "{:.3f} [{:.3f}, {:.3f}]".format(*(row["mean_extra_logical_delay_" + part] for part in ("mean", "ci95_low", "ci95_high")))
            runtime = "{:.3f} [{:.3f}, {:.3f}]".format(*(row["controller_runtime_ms_" + part] for part in ("mean", "ci95_low", "ci95_high")))
            rejected = row["safe_stale_global_rejections_total"] + row["safe_stale_support_rejections_total"]
            lines.append(f"{topology.replace('_', ' ')} & {names[policy]} & {rejected:,} & {delay} & {runtime}" + r" \\")
        if topology != TOPOLOGIES[-1]:
            lines.append(r"\midrule")
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table*}"]
    cost_table = "\n".join(lines) + "\n"
    for name, content in (("table_integrated_results.tex", safety_table), ("table_integrated_cost.tex", cost_table)):
        (output_dir / name).write_text(content, encoding="utf-8")
        paper_tables = Path(__file__).resolve().parents[1] / "paper" / "tables"
        if paper_tables.is_dir():
            (paper_tables / name).write_text(content, encoding="utf-8")


def run_suite(output_dir: Path, seeds: tuple[int, ...] = DEFAULT_SEEDS, n_effects: int = 120, benchmark_repeats: int = 5) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    traces_dir = output_dir / "traces"
    traces_dir.mkdir(exist_ok=True)
    results = []
    statistics_rows = []
    all_outcomes = []
    total_logs = 0
    with (output_dir / "controller_event_log.jsonl").open("w", encoding="utf-8") as audit_file:
        for topology in TOPOLOGIES:
            for seed in seeds:
                trace = generate_event_trace(seed, topology, n_effects)
                truth = PrefixOracle(trace).settlement_truth()
                statistics_rows.append(trace_stats(trace, truth))
                (traces_dir / f"{topology}_{seed}.json").write_text(json.dumps(trace.payload(), separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
                order = list(POLICIES)
                random.Random(seed).shuffle(order)
                for policy in order:
                    result, outcomes, logs = replay(trace, policy, truth)
                    results.append(result)
                    all_outcomes.extend(outcomes)
                    for log in logs:
                        audit_file.write(json.dumps(log, separators=(",", ":")) + "\n")
                    total_logs += len(logs)
                print(f"completed {topology} seed {seed}", flush=True)
    write_csv(output_dir / "per_trace_metrics.csv", results)
    write_csv(output_dir / "per_effect_outcomes.csv", all_outcomes)
    write_csv(output_dir / "trace_statistics.csv", statistics_rows)
    aggregates = summarize(results)
    write_csv(output_dir / "aggregate_ci.csv", aggregates)
    write_csv(output_dir / "paired_seed_comparisons.csv", paired_comparisons(results))
    write_paper_tables(output_dir, results, aggregates)
    regression = legacy_regression(output_dir)
    benchmarks = run_benchmarks(output_dir, benchmark_repeats) if benchmark_repeats else []
    safe_results = [r for r in results if r["policy"] in SAFE_POLICIES]
    validation = {"safe_policy_false_accepts": sum(r["false_accepts"] for r in safe_results), "safe_policy_coverage_min": min(r["safe_coverage"] for r in safe_results), "rollback_residual_sum": sum(r["rollback_residual_sum"] for r in safe_results), "rollback_collateral_sum": sum(r["rollback_collateral_sum"] for r in safe_results), "all_valid_false_accepts": sum(r["false_accepts"] for r in results if r["topology"] == "all_valid"), "all_valid_coverage_min": min(r["safe_coverage"] for r in results if r["topology"] == "all_valid"), "ablation_false_accepts": {p: sum(r["false_accepts"] for r in results if r["policy"] == p) for p in POLICIES[3:]}}
    manifest = {"schema_version": 1, "seeds": list(seeds), "n_effects_per_trace": n_effects, "topologies": list(TOPOLOGIES), "policies": list(POLICIES), "trace_count": len(statistics_rows), "policy_replays": len(results), "settlement_outcomes": len(all_outcomes), "event_log_rows": total_logs, "benchmark_samples": len(benchmarks), "python": sys.version, "platform": platform.platform(), "oracle": "Independent declaration traversal + external event-prefix reconstruction; no runtime decisions or controller closure used as truth", "ci": "2000 bootstrap replicates across seeds, percentile 95% interval; workloads are synthetic", "timing": "perf_counter_ns controller calls and setup, separately from logical trace timestamps. Runtime samples are local Python microbenchmarks, not blockchain latency.", "retry_schedule": "All policies share two fixed issue/settle opportunities; no method-specific event schedules", "boundary": "Safety means validity at settlement with all prior events processed. Revocation after accepted settlement is separately reported; it cannot undo an irreversible effect.", "validation": validation, "legacy_regression": regression, "source_hashes": {name: hashlib.sha256((Path(__file__).parent / name).read_bytes()).hexdigest() for name in ("experiment_suite.py", "integrated_controller.py", "unified_replay.py")}}
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "aggregate_ci.json").write_text(json.dumps(aggregates, indent=2), encoding="utf-8")
    if validation["safe_policy_false_accepts"] or validation["safe_policy_coverage_min"] < 1 or validation["rollback_residual_sum"] or validation["rollback_collateral_sum"]:
        raise AssertionError(f"Integrated safety/coverage/rollback validation failed: {validation}")
    if validation["all_valid_false_accepts"] or validation["all_valid_coverage_min"] < 1:
        raise AssertionError(f"Negative control failed: {validation}")
    if not all(validation["ablation_false_accepts"].values()):
        raise AssertionError(f"An ablation was not challenged: {validation}")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "results" / "integrated_suite")
    parser.add_argument("--effects", type=int, default=120)
    parser.add_argument("--seed-count", type=int, default=len(DEFAULT_SEEDS))
    parser.add_argument("--benchmark-repeats", type=int, default=5)
    args = parser.parse_args()
    manifest = run_suite(args.output, DEFAULT_SEEDS[:args.seed_count], args.effects, args.benchmark_repeats)
    print(json.dumps(manifest["validation"], indent=2))


if __name__ == "__main__":
    main()
