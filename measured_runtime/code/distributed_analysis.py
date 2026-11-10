#!/usr/bin/env python3
"""Independent audit-prefix oracle and statistics for the socket experiment.

No gateway module is imported. Complete supports are reconstructed solely from
the submitted workload registry. Safety concerns admitted evidence at the
transaction evaluation timestamp, not unobserved external truth or COMMIT time.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean
from typing import Any, Iterable


class OracleInputError(ValueError):
    """A malformed or incomplete experiment must not silently enter a result."""


def complete_supports(registry: dict[str, Any]) -> dict[str, set[str]]:
    """Compute transitive ancestor artifacts and their evidence independently.

    This traversal deliberately does not reuse Registry, runtime compiled
    support, token snapshots, rejection reasons, or gateway admission decisions.
    """
    parents = {str(k): tuple(map(str, v)) for k, v in
               registry.get("artifact_parents", {}).items()}
    obligations = {str(k): tuple(map(str, v)) for k, v in
                   registry.get("artifact_obligations", {}).items()}
    roots = {str(k): tuple(map(str, v)) for k, v in
             registry.get("effect_artifacts", {}).items()}
    direct = {str(k): tuple(map(str, v)) for k, v in
              registry.get("effect_obligations", {}).items()}
    artifacts = set(parents) | set(obligations)
    for artifact, ancestors in parents.items():
        missing = set(ancestors) - artifacts
        if missing:
            raise OracleInputError(f"unknown parents of {artifact}: {sorted(missing)}")
    supports: dict[str, set[str]] = {}
    for effect in set(roots) | set(direct):
        found: set[str] = set()
        visiting: set[str] = set()
        done: set[str] = set()

        def walk(artifact: str) -> None:
            if artifact not in artifacts:
                raise OracleInputError(f"unknown artifact {artifact}")
            if artifact in visiting:
                raise OracleInputError(f"dependency cycle at {artifact}")
            if artifact in done:
                return
            visiting.add(artifact)
            found.add("a:" + artifact)
            found.update("o:" + item for item in obligations.get(artifact, ()))
            for ancestor in parents.get(artifact, ()):
                walk(ancestor)
            visiting.remove(artifact)
            done.add(artifact)

        for root in roots.get(effect, ()):
            walk(root)
        found.update("o:" + item for item in direct.get(effect, ()))
        supports[effect] = found
    return supports


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    value = row.get("payload", {})
    if isinstance(value, str):
        value = json.loads(value)
    return value or {}


def _subject(row: dict[str, Any]) -> str:
    payload = _payload(row)
    return str(row.get("subject_id") or payload.get("subject_id") or "")


def _effect(row: dict[str, Any]) -> str:
    payload = _payload(row)
    return str(row.get("effect_id") or payload.get("effect_id") or "")


def _finite(value: Any, field: str) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise OracleInputError(f"missing/non-numeric {field}") from exc
    if not math.isfinite(number):
        raise OracleInputError(f"non-finite {field}")
    return number


class PrefixOracle:
    """Reconstruct current admitted predicates without using runtime support."""

    def __init__(self, workload: dict[str, Any]):
        self.supports = complete_supports(workload["registry"])
        expiry = _finite(workload["expires_at"], "workload.expires_at")
        self.subjects = {subject: {"valid": True, "expires_at": expiry}
                         for support in self.supports.values() for subject in support}
        registry = workload["registry"]
        all_subjects = set(map(str, workload.get("extra_subjects", [])))
        all_subjects.update("a:" + str(artifact) for artifact in
                            set(registry.get("artifact_parents", {})) | set(registry.get("artifact_obligations", {})))
        for mapping in (registry.get("artifact_obligations", {}), registry.get("effect_obligations", {})):
            all_subjects.update("o:" + str(obligation) for values in mapping.values() for obligation in values)
        for subject in all_subjects:
            self.subjects.setdefault(subject, {"valid": True, "expires_at": expiry})
        for subject, subject_expiry in workload.get("subject_expiries", {}).items():
            self.subjects.setdefault(subject, {"valid": True})["expires_at"] = _finite(subject_expiry, "subject_expiries")
        # Optional explicit initial evidence permits future non-all-valid cases.
        for subject, record in workload.get("initial_subjects", {}).items():
            self.subjects[subject] = {
                "valid": bool(record["valid"]),
                "expires_at": _finite(record.get("expires_at", expiry), "expires_at"),
            }
        self.ready = {str(item["effect_id"]): bool(item.get("ready", True))
                      for item in workload["effects"]}
        missing = set(self.ready) - self.supports.keys()
        if missing:
            raise OracleInputError(f"effects absent from registry: {sorted(missing)}")
        self.cancelled: set[str] = set()
        self.mutated_subjects: set[str] = set()
        self.extended_effects: set[str] = set()

    def predicate(self, effect_id: str, now: float) -> tuple[bool, list[str]]:
        if effect_id not in self.supports:
            return False, ["unknown_effect"]
        reasons: list[str] = []
        if not self.ready.get(effect_id, False):
            reasons.append("not_ready")
        if effect_id in self.cancelled:
            reasons.append("cancelled")
        for subject in sorted(self.supports[effect_id]):
            current = self.subjects.get(subject)
            if current is None:
                reasons.append("unregistered:" + subject)
            elif not current["valid"]:
                reasons.append("invalid:" + subject)
            elif now >= current["expires_at"]:
                reasons.append("expired:" + subject)
        return not reasons, reasons

    def mutate(self, row: dict[str, Any]) -> None:
        kind = row["kind"]
        payload = _payload(row)
        subject = _subject(row)
        if kind in {"invalidate", "refresh", "register"}:
            if not subject:
                raise OracleInputError(f"{kind} missing subject_id")
            if kind == "register":
                self.subjects[subject] = {
                    "valid": bool(payload.get("valid", True)),
                    "expires_at": _finite(payload["expires_at"], "register.expires_at"),
                }
            elif subject not in self.subjects:
                raise OracleInputError(f"{kind} unknown subject {subject}")
            elif kind == "invalidate":
                self.subjects[subject]["valid"] = False
            else:
                # A benign refresh changes evidence version, not truth. A
                # tombstoned identity may not be resurrected by this operation.
                if "valid" in payload and bool(payload["valid"]) != self.subjects[subject]["valid"]:
                    raise OracleInputError("refresh attempts to change evidence validity")
                if "expires_at" in payload:
                    self.subjects[subject]["expires_at"] = _finite(payload["expires_at"], "refresh.expires_at")
            if kind != "register":
                self.mutated_subjects.add(subject)
        elif kind == "extend":
            effect_id = _effect(row)
            if effect_id not in self.supports:
                raise OracleInputError(f"extend unknown effect {effect_id}")
            # These are admitted contract edits, not the runtime's precomputed
            # transitive support. For artifacts, independently expand ancestry.
            additional = payload.get("additional_support", payload.get("additions", payload.get("subjects", [])))
            for subject_id in additional:
                if not str(subject_id).startswith(("a:", "o:")):
                    raise OracleInputError("extension subject needs a:/o: namespace")
                if str(subject_id).startswith("a:"):
                    raise OracleInputError("artifact extension requires new registry, unsupported")
                self.supports[effect_id].add(str(subject_id))
            self.extended_effects.add(effect_id)
        elif kind == "ready":
            self.ready[_effect(row)] = bool(payload["ready"])
        elif kind == "cleanup":
            # Cleanup of an unsettled effect is a cancellation, even if all
            # evidence is otherwise valid. Source invalidation is independent.
            if payload.get("cancelled", True):
                self.cancelled.update(map(str, payload.get("cancelled_effects", [])))
                if _effect(row):
                    self.cancelled.add(_effect(row))


def evaluate_prefix(workload: dict[str, Any], snapshot: dict[str, Any],
                    source_events: list[dict[str, Any]] | None = None,
                    planned_mutations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    oracle = PrefixOracle(workload)
    rows = snapshot.get("audit", [])
    if not isinstance(rows, list):
        raise OracleInputError("audit must be a list")
    previous_seq = -1
    previous_time = -math.inf
    unsafe: list[dict[str, Any]] = []
    settled_events: list[dict[str, Any]] = []
    conservative: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    seen_issue_effects: set[str] = set()
    source_exposures: list[dict[str, Any]] = []
    source_events = source_events or []
    admitted_invalid: dict[str, float] = {}
    accepted_so_far: set[str] = set()
    cleanup_errors: list[dict[str, Any]] = []
    reject_by_prefix: dict[int, list[dict[str, Any]]] = defaultdict(list)
    unidentified_rejections: list[dict[str, Any]] = []
    for row in rows:
        if row["kind"] != "reject":
            continue
        payload = _payload(row)
        reason = str(payload.get("reason", row.get("reason", "unknown")))
        operation = str(payload.get("operation", row.get("operation", "")))
        if ("stale" in reason or "epoch" in reason or "version" in reason) and operation in {"", "issue", "settle"}:
            if "evaluated_prefix_seq" in payload and "evaluated_at" in payload:
                reject_by_prefix[int(payload["evaluated_prefix_seq"])].append(row)
            else:
                unidentified_rejections.append({"seq": row["seq"], "effect_id": _effect(row), "reason": reason})

    def classify_rejections(prefix_seq: int) -> None:
        for rejected in reject_by_prefix.pop(prefix_seq, []):
            payload = _payload(rejected)
            eligible, _ = oracle.predicate(_effect(rejected), _finite(payload["evaluated_at"], "reject.evaluated_at"))
            if eligible:
                conservative.append({"seq": rejected["seq"], "effect_id": _effect(rejected),
                                     "reason": payload["reason"], "evaluated_prefix_seq": prefix_seq})

    classify_rejections(0)
    classify_rejections(-1)
    for row in rows:
        seq = int(row["seq"])
        now = _finite(row["at_time"], "audit.at_time")
        if seq <= previous_seq:
            raise OracleInputError("audit seq is not strictly increasing")
        if now < previous_time:
            raise OracleInputError("trusted audit evaluation clock regressed")
        previous_seq, previous_time = seq, now
        kind = row["kind"]
        effect_id = _effect(row)
        payload = _payload(row)
        if kind in {"issue", "settle", "reject"} and effect_id:
            eligible, reasons = oracle.predicate(effect_id, now)
            observations.append({"seq": seq, "kind": kind, "effect_id": effect_id,
                                 "eligible": eligible, "reasons": reasons})
            if kind == "issue":
                seen_issue_effects.add(effect_id)
            if kind == "settle":
                settled_events.append(row)
                accepted_so_far.add(effect_id)
                if not eligible:
                    unsafe.append({"seq": seq, "effect_id": effect_id, "reasons": reasons})
                for event in source_events:
                    if event.get("kind", "invalidate") not in {"invalidate", "source_invalidate"}:
                        continue
                    subject = str(event["subject_id"])
                    occurred = _finite(event["occurred_at"], "source.occurred_at")
                    if subject in oracle.supports.get(effect_id, ()) and occurred <= now and subject not in admitted_invalid:
                        source_exposures.append({"seq": seq, "effect_id": effect_id,
                                                 "subject_id": subject, "occurred_at": occurred,
                                                 "settled_at": now,
                                                 "admission": "not_yet_admitted_at_settlement"})
        if kind == "cleanup":
            observed = set(map(str, payload.get("cancelled_effects", [])))
            if effect_id and payload.get("cancelled", True):
                observed.add(effect_id)
            expected_cancelled = {effect for effect, support in oracle.supports.items()
                                  if effect not in accepted_so_far | oracle.cancelled
                                  and any(not oracle.subjects.get(subject, {"valid": False})["valid"]
                                          for subject in support)}
            if observed != expected_cancelled:
                cleanup_errors.append({"seq": seq, "missing": sorted(expected_cancelled - observed),
                                       "collateral": sorted(observed - expected_cancelled)})
        oracle.mutate(row)
        if kind == "invalidate":
            admitted_invalid[_subject(row)] = now
        classify_rejections(seq)
    if reject_by_prefix:
        raise OracleInputError(f"rejection references absent audit prefix: {sorted(reject_by_prefix)}")

    ledger = snapshot.get("ledger", [])
    ledger_effects = [str(row["effect_id"]) for row in ledger]
    ledger_nonces = [str(row["nonce"]) for row in ledger]
    duplicates = {"effect_ids": {k: v for k, v in Counter(ledger_effects).items() if v > 1},
                  "nonces": {k: v for k, v in Counter(ledger_nonces).items() if v > 1}}
    expected = {str(k): int(v) for k, v in workload["accounts"].items()}
    effect_spec = {str(e["effect_id"]): e for e in workload["effects"]}
    ledger_binding_errors: list[str] = []
    audit_receipt_errors: list[dict[str, Any]] = []
    ledger_by_effect = {str(row["effect_id"]): row for row in ledger}
    for row in settled_events:
        receipt = _payload(row).get("receipt")
        recorded = ledger_by_effect.get(_effect(row))
        if not isinstance(receipt, dict) or recorded is None:
            audit_receipt_errors.append({"seq": row["seq"], "reason": "missing_receipt_or_ledger"})
        else:
            fields = ("effect_id", "nonce", "receipt_id", "payer", "recipient", "amount", "settled_at")
            mismatch = [field for field in fields if field not in receipt or receipt.get(field) != recorded.get(field)]
            if row.get("nonce") != receipt.get("nonce"):
                mismatch.append("audit_nonce")
            if row["at_time"] != receipt.get("settled_at"):
                mismatch.append("audit_time")
            if mismatch:
                audit_receipt_errors.append({"seq": row["seq"], "reason": "receipt_mismatch", "fields": mismatch})
    for row in ledger:
        spec = effect_spec.get(str(row["effect_id"]))
        if spec is None or any(row.get(field) != spec.get(field) for field in ("payer", "recipient", "amount")):
            ledger_binding_errors.append(str(row["effect_id"]))
        payer, recipient, amount = str(row["payer"]), str(row["recipient"]), int(row["amount"])
        expected[payer] = expected.get(payer, 0) - amount
        expected[recipient] = expected.get(recipient, 0) + amount
    accounts = snapshot.get("accounts", [])
    actual = ({str(k): int(v) for k, v in accounts.items()} if isinstance(accounts, dict)
              else {str(row["account_id"]): int(row["balance"]) for row in accounts})
    settled = set(ledger_effects)
    audit_settled = {_effect(row) for row in settled_events}
    final_time = previous_time if rows else _finite(workload.get("created_at", 0), "created_at")
    final_eligible = {effect for effect in oracle.supports if oracle.predicate(effect, final_time)[0]}
    planned_subjects = {str(row["subject_id"]) for row in (planned_mutations or []) if row.get("subject_id")}
    independent = {effect for effect, support in oracle.supports.items()
                   if not support.intersection(oracle.mutated_subjects | planned_subjects) and effect not in oracle.extended_effects}
    return {
        "unsafe_settlements": len(unsafe), "unsafe_details": unsafe,
        "duplicate_ledger_entries": max((sum(v - 1 for v in group.values()) for group in duplicates.values()), default=0),
        "duplicate_details": duplicates,
        "duplicate_settlement_audit_entries": sum(v - 1 for v in Counter(_effect(row) for row in settled_events).values() if v > 1),
        "audit_receipt_errors": audit_receipt_errors,
        "balance_conserved": sum(actual.values()) == sum(workload["accounts"].values()),
        "balances_match_ledger": expected == actual,
        "ledger_binding_errors": ledger_binding_errors,
        "audit_ledger_effects_match": audit_settled == settled,
        "cleanup_errors": cleanup_errors,
        "cancelled_effects_with_remaining_stage": sorted(oracle.cancelled & {str(row["effect_id"]) for row in snapshot.get("stages", [])}),
        "audit_missing_ledger": sorted(audit_settled - settled),
        "ledger_missing_audit": sorted(settled - audit_settled),
        "effects_total": len(effect_spec), "settled": len(settled),
        "final_eligible": len(final_eligible),
        "final_eligible_settled": len(final_eligible & settled),
        "independent_effects": len(independent), "independent_settled": len(independent & settled),
        "conservative_stale_rejections": len(conservative), "conservative_stale_details": conservative,
        "unidentifiable_stale_rejections": len(unidentified_rejections),
        "unidentifiable_stale_details": unidentified_rejections,
        "issued_effects": len(seen_issue_effects),
        "source_time_exposure_settlements": len({(row["seq"], row["effect_id"]) for row in source_exposures}),
        "source_time_exposure_details": source_exposures,
        "operation_predicates": observations,
        "settled_effect_ids": sorted(settled), "independent_effect_ids": sorted(independent),
        "final_eligible_effect_ids": sorted(final_eligible),
    }


def quantile(values: Iterable[float], fraction: float) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    position = (len(ordered) - 1) * fraction
    low, high = math.floor(position), math.ceil(position)
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def client_metrics(events: list[dict[str, Any]], meta: dict[str, Any],
                   effect_ids: Iterable[str]) -> dict[str, Any]:
    first_issue: dict[str, int] = {}
    final_reply: dict[str, int] = {}
    rpc_ms: list[float] = []
    issues: Counter[str] = Counter()
    rejects: Counter[str] = Counter()
    transport_failures = 0
    operations: Counter[str] = Counter()
    task_ms: list[float] = []
    compute_ms: list[float] = []
    for event in events:
        start, end = int(event["start_ns"]), int(event["end_ns"])
        if end < start:
            raise OracleInputError("negative client RPC duration")
        operation, effect = str(event["operation"]), str(event.get("effect_id", ""))
        if operation.startswith("task_"):
            if operation == "task_complete":
                task_ms.append((end - start) / 1e6)
            elif operation == "task_compute":
                compute_ms.append((end - start) / 1e6)
            continue
        operations[operation] += 1
        rpc_ms.append((end - start) / 1e6)
        if operation == "issue":
            issues[effect] += 1
            first_issue[effect] = min(start, first_issue.get(effect, start))
        if operation == "settle" and event.get("ok", False):
            final_reply[effect] = min(end, final_reply.get(effect, end))
        if not event.get("ok", False):
            reason = str(event.get("reason", "unknown"))
            rejects[reason] += 1
            if event.get("transport_error", False) or reason in {"transport_error", "timeout", "connection_error", "connection_reset", "response_lost"}:
                transport_failures += 1
    missing_starts = set(final_reply) - first_issue.keys()
    if missing_starts:
        raise OracleInputError(f"successful settle lacks first issue: {sorted(missing_starts)}")
    completion_ms = {effect: (end - first_issue[effect]) / 1e6 for effect, end in final_reply.items()}
    if any(value < 0 for value in completion_ms.values()):
        raise OracleInputError("completion precedes first issue")
    makespan_ns = int(meta["finished_ns"]) - int(meta["started_ns"])
    if makespan_ns <= 0:
        raise OracleInputError("non-positive measured makespan")
    effects = set(effect_ids)
    return {
        "measured_seconds": makespan_ns / 1e9,
        "client_completed": len(set(final_reply) & effects),
        "incomplete_effects": len(effects - final_reply.keys()),
        "not_started_effects": len(effects - first_issue.keys()),
        "completion_p50_ms": quantile(completion_ms.values(), 0.5),
        "completion_p95_ms": quantile(completion_ms.values(), 0.95),
        "completion_mean_ms": mean(completion_ms.values()) if completion_ms else None,
        "completion_ms_by_effect": completion_ms,
        "incomplete_effect_ids": sorted(effects - final_reply.keys()),
        "rpc_p50_ms": quantile(rpc_ms, 0.5), "rpc_p95_ms": quantile(rpc_ms, 0.95),
        "rpc_count": len(rpc_ms), "rpc_by_operation": dict(operations),
        "reissue_count": sum(max(0, count - 1) for count in issues.values()),
        "rpc_reject_count": sum(rejects.values()), "rpc_reject_reasons": dict(rejects),
        "transport_failures": transport_failures,
        "task_completion_p50_ms": quantile(task_ms, 0.5),
        "task_completion_p95_ms": quantile(task_ms, 0.95),
        "task_compute_p50_ms": quantile(compute_ms, 0.5),
        "task_compute_p95_ms": quantile(compute_ms, 0.95),
    }


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def recompute_output(effect: dict[str, Any]) -> dict[str, Any]:
    """Recompute the declared integer calibration task without worker imports.

    Scalar moments use algebra on the original input, independently of the
    worker's moments over its corrected array. The vector digest is defined by
    canonical compact JSON of the corrected values.
    """
    values, factor = effect["input_values"], effect["calibration_factor"]
    if type(factor) is not int or any(type(value) is not int for value in values):
        raise OracleInputError("calibration output requires integer input/factor")
    canonical_vector = "[" + ",".join(str(factor * value) for value in values) + "]"
    return {"effect_id": effect["effect_id"], "generation": effect["generation"],
            "samples": len(values), "sum": factor * sum(values),
            "sum_squares": factor * factor * sum(value ** 2 for value in values),
            "result_sha256": hashlib.sha256(canonical_vector.encode("utf-8")).hexdigest()}


def published_output_checks(directory: str | Path, workload: dict[str, Any],
                            snapshot: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    directory = Path(directory)
    errors: list[dict[str, Any]] = []
    expected: dict[str, dict[str, Any]] = {}
    for effect in workload["effects"]:
        effect_id = str(effect["effect_id"])
        expected[effect_id] = recompute_output(effect)
        if effect.get("payload") != expected[effect_id]:
            errors.append({"effect_id": effect_id, "reason": "declared_payload_differs_from_independent_computation"})
    ledger_ids = {str(row["effect_id"]) for row in snapshot.get("ledger", [])}
    effect_rows = {str(row["effect_id"]): row for row in snapshot.get("effects", [])}
    blocked = {str(row["effect_id"]) for row in events if row["operation"] == "task_blocked"}
    for path in directory.glob("worker_state/*/journal.json"):
        journal = json.loads(path.read_text(encoding="utf-8"))
        blocked.update(str(effect) for effect, state in journal.items()
                       if state.get("terminal") and state["terminal"] not in {"completed", "retry_exhausted"})
    expected_worker = {str(effect["effect_id"]): str(index % int(workload["workers"]))
                       for index, effect in enumerate(workload["effects"])}
    found: Counter[str] = Counter()
    inspected = []
    for path in sorted(directory.glob("worker_state/*/published/*.json")):
        relative = path.relative_to(directory).as_posix()
        try:
            raw = path.read_bytes()
            output = json.loads(raw)
            effect_id = str(output.get("effect_id", ""))
            found[effect_id] += 1
            inspected.append({"path": relative, "effect_id": effect_id, "sha256": hashlib.sha256(raw).hexdigest()})
            if path.stem != effect_id:
                errors.append({"path": relative, "reason": "filename_effect_mismatch"})
            if effect_id not in expected:
                errors.append({"path": relative, "effect_id": effect_id, "reason": "unknown_effect_output"})
                continue
            if path.parent.parent.name != expected_worker[effect_id]:
                errors.append({"path": relative, "effect_id": effect_id, "reason": "wrong_worker_output_directory"})
            if effect_id not in ledger_ids:
                errors.append({"path": relative, "effect_id": effect_id, "reason": "published_without_committed_ledger"})
            if effect_id in blocked:
                errors.append({"path": relative, "effect_id": effect_id, "reason": "blocked_effect_has_published_output"})
            if output != expected[effect_id]:
                errors.append({"path": relative, "effect_id": effect_id, "reason": "published_payload_differs_from_independent_computation"})
        except (OSError, ValueError, AttributeError) as exc:
            errors.append({"path": relative, "reason": "unreadable_published_output", "detail": str(exc)})
    missing = sorted(ledger_ids - found.keys())
    duplicates = {key: count for key, count in found.items() if count > 1}
    for effect_id in sorted(ledger_ids):
        payload = expected.get(effect_id)
        row = effect_rows.get(effect_id)
        if payload is None or row is None:
            errors.append({"effect_id": effect_id, "reason": "committed_effect_missing_declaration_or_snapshot"})
            continue
        digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True,
                                          separators=(",", ":")).encode("utf-8")).hexdigest()
        if row.get("payload_hash") != digest:
            errors.append({"effect_id": effect_id, "reason": "committed_payload_hash_differs_from_independent_computation"})
    return {"published_output_count": sum(found.values()), "published_effect_count": len(found),
            "missing_published_effects": missing, "duplicate_published_effects": duplicates,
            "published_output_errors": errors, "published_output_files": inspected,
            "blocked_effects_with_published_output": sorted(blocked & found.keys()),
            "published_outputs_consistent": not (missing or duplicates or errors)}


def notification_overlap(workload: dict[str, Any], snapshot: dict[str, Any],
                         events: list[dict[str, Any]], source_events: list[dict[str, Any]]) -> dict[str, Any]:
    """Report observed overlap; case labels do not imply a concurrent update.

    Exact activity/issue overlap uses gateway audit sequence and epoch time.
    Worker task overlap additionally maps epoch to perf_counter using the paired
    source timestamps; this estimate is explicitly labelled, since sequential
    clock reads have unbounded scheduling skew.
    """
    supports = complete_supports(workload["registry"])
    audit = snapshot.get("audit", [])
    mutations = [row for row in audit if row["kind"] in {"invalidate", "refresh"}]
    worker_rows = [row for row in audit if str(row.get("actor_id", "")).startswith("worker-")
                   and row["kind"] in {"stage", "issue", "settle", "reject"}]
    activity_start = min((row["at_time"] for row in worker_rows), default=None)
    activity_end = max((row["at_time"] for row in worker_rows), default=None)
    task_starts: dict[str, int] = {}
    task_ends: dict[str, int] = {}
    for event in events:
        effect_id = str(event.get("effect_id", ""))
        if event["operation"] == "task_start":
            task_starts[effect_id] = min(int(event["start_ns"]), task_starts.get(effect_id, int(event["start_ns"])))
        elif event["operation"] in {"task_complete", "task_blocked", "task_incomplete"}:
            task_ends[effect_id] = max(int(event["end_ns"]), task_ends.get(effect_id, 0))
    used_mutations: set[int] = set()
    details = []
    for source in sorted(source_events, key=lambda row: row["occurred_at"]):
        response = source.get("response", {})
        response_result = response.get("result")
        epoch = response_result.get("epoch") if isinstance(response_result, dict) else response_result if isinstance(response_result, int) else None
        candidates = [row for row in mutations if row["seq"] not in used_mutations
                      and row["kind"] == source.get("kind", "invalidate")
                      and _subject(row) == source["subject_id"]
                      and (epoch is None or _payload(row).get("epoch") == epoch)]
        if not candidates:
            details.append({"subject_id": source["subject_id"], "kind": source.get("kind"),
                            "occurred_at": source["occurred_at"], "admission_found": False})
            continue
        admitted = min(candidates, key=lambda row: row["seq"])
        used_mutations.add(admitted["seq"])
        prior = [row for row in audit if row["seq"] < admitted["seq"]]
        issued = {_effect(row) for row in prior if row["kind"] == "issue"}
        settled = {_effect(row) for row in prior if row["kind"] == "settle"}
        cancelled = {str(effect) for row in prior if row["kind"] == "cleanup" for effect in _payload(row).get("cancelled_effects", [])}
        terminal_denied = {_effect(row) for row in prior if row["kind"] == "reject"
                           and _payload(row).get("reason") in {"support_invalidated", "support_expired", "effect_cancelled", "insufficient_funds"}}
        pending_issued = issued - settled - cancelled - terminal_denied
        relevant = {effect for effect, support in supports.items() if source["subject_id"] in support}
        now = float(admitted["at_time"])
        item = {"subject_id": source["subject_id"], "kind": source.get("kind"),
                "occurred_at": source["occurred_at"], "admission_found": True,
                "admission_seq": admitted["seq"], "admitted_at": now,
                "measured_source_to_admission_ms": (now - float(source["occurred_at"])) * 1000,
                "injected_notification_delay_ms": source.get("injected_notification_delay_ms"),
                "within_gateway_worker_activity_window": activity_start is not None and activity_start <= now <= activity_end,
                "after_last_gateway_worker_operation": activity_end is not None and now > activity_end,
                "issued_pending_effects": len(pending_issued),
                "relevant_effects": len(relevant),
                "relevant_settled_before_admission": len(relevant & settled),
                "relevant_issued_pending_effects": len(relevant & pending_issued)}
        if "occurred_ns" in source:
            mapped = int(source["occurred_ns"]) + round((now - float(source["occurred_at"])) * 1e9)
            active = {effect for effect, start in task_starts.items() if start <= mapped <= task_ends.get(effect, math.inf)}
            item.update({"estimated_admission_perf_ns": mapped,
                         "estimated_active_worker_tasks": len(active),
                         "estimated_active_relevant_tasks": len(active & relevant),
                         "estimated_after_last_worker_task": bool(task_ends) and mapped > max(task_ends.values())})
        details.append(item)
    matched = [item for item in details if item["admission_found"]]
    return {"notification_events": len(source_events), "matched_notification_admissions": len(matched),
            "unmatched_notification_admissions": len(source_events) - len(matched),
            "mutations_with_issued_pending_effects": sum(item["issued_pending_effects"] > 0 for item in matched),
            "mutations_with_relevant_issued_pending_effects": sum(item["relevant_issued_pending_effects"] > 0 for item in matched),
            "mutations_after_last_gateway_worker_operation": sum(item["after_last_gateway_worker_operation"] for item in matched),
            "notification_overlap_details": details,
            "notification_overlap_clock_note": "Exact issue/activity overlap uses committed audit order. Estimated worker task overlap maps epoch/perf clocks using sequential source timestamp reads; capture skew is not bounded."}


def recovery_metrics(meta: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    """Observed recovery durations start at coordinator detection, not crash."""
    details = []
    for recovery in meta.get("recovery_events", []):
        detected = int(recovery["detected_ns"])
        is_worker = recovery["kind"] == "worker_restart"
        reported_endpoint = int(recovery["restarted_ns"] if is_worker else recovery["ready_ns"])
        successful = [event for event in events if not str(event["operation"]).startswith("task_")
                      and event.get("ok") and int(event["end_ns"]) >= reported_endpoint
                      and (not is_worker or event.get("worker_id") == recovery["worker_id"])]
        first_rpc = min((int(event["end_ns"]) for event in successful), default=None)
        first_settle = min((int(event["end_ns"]) for event in successful if event["operation"] == "settle"), default=None)
        details.append({**recovery,
                        "detection_to_spawn_ms" if is_worker else "detection_to_gateway_ready_ms": (reported_endpoint - detected) / 1e6,
                        "detection_to_first_successful_rpc_ms": (first_rpc - detected) / 1e6 if first_rpc is not None else None,
                        "detection_to_first_successful_settle_reply_ms": (first_settle - detected) / 1e6 if first_settle is not None else None})
    return {"observed_recovery_count": len(details), "observed_recovery_details": details,
            "recovery_clock_note": "Measured from coordinator process-exit detection; includes the separately reported injected pause. Worker process spawn is not service readiness."}


def analyze_run(directory: str | Path) -> dict[str, Any]:
    directory = Path(directory)
    required = ["workload.json", "server_snapshot.json", "client_events.jsonl", "run_meta.json"]
    missing = [name for name in required if not (directory / name).is_file()]
    if missing:
        partial_meta = {}
        if (directory / "run_meta.json").exists():
            try:
                partial_meta = json.loads((directory / "run_meta.json").read_text(encoding="utf-8"))
            except (ValueError, OSError):
                pass
        return {"run_id": directory.name, "run_directory": str(directory), **partial_meta, "analysis_status": "invalid",
                "analysis_error": "missing files: " + ", ".join(missing)}
    meta: dict[str, Any] = {}
    try:
        workload = json.loads((directory / "workload.json").read_text(encoding="utf-8"))
        snapshot = json.loads((directory / "server_snapshot.json").read_text(encoding="utf-8"))
        meta = json.loads((directory / "run_meta.json").read_text(encoding="utf-8"))
        if "common_input_sha256" in workload:
            authored = {key: value for key, value in workload.items() if key not in {"run_id", "common_input_sha256"}}
            digest = hashlib.sha256(json.dumps(authored, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            if digest != workload["common_input_sha256"] or digest != meta.get("common_input_sha256"):
                raise OracleInputError("common input hash does not match raw workload and metadata")
        source = _jsonl(directory / "source_events.jsonl")
        if len(source) != len(meta.get("planned_source_events", [])):
            raise OracleInputError("recorded source event count does not match planned events")
        safety = evaluate_prefix(workload, snapshot, source, meta.get("planned_source_events", []))
        events = _jsonl(directory / "client_events.jsonl")
        client = client_metrics(events, meta,
                                (item["effect_id"] for item in workload["effects"]))
        publication = published_output_checks(directory, workload, snapshot, events)
        overlap = notification_overlap(workload, snapshot, events, source)
        recovery = recovery_metrics(meta, events)
        before_path = directory / "before_cleanup_snapshot.json"
        before = json.loads(before_path.read_text(encoding="utf-8")) if before_path.exists() else None
        deleted_rows = sum(int(_payload(row).get("stage_rows_deleted", 0)) for row in snapshot.get("audit", []) if row["kind"] == "cleanup")
        cleanup = {"gateway_stage_rows_before_cleanup": len(before["stages"]) if before is not None else None,
                   "gateway_stage_rows_after_cleanup": len(snapshot.get("stages", [])),
                   "gateway_cleanup_deleted_rows": deleted_rows,
                   "remaining_worker_staged_files": [path.relative_to(directory).as_posix() for path in sorted(directory.glob("worker_state/*/staged/*.json"))]}
        cleanup["cleanup_count_matches_snapshot_difference"] = (deleted_rows == len(before["stages"]) - len(snapshot.get("stages", []))) if before is not None else None
        file_hashes = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in required}
        correctness = (safety["unsafe_settlements"] == 0 and safety["duplicate_ledger_entries"] == 0
                       and safety["balance_conserved"] and safety["balances_match_ledger"]
                       and safety["audit_ledger_effects_match"] and not safety["ledger_binding_errors"]
                       and not safety["cleanup_errors"] and not safety["cancelled_effects_with_remaining_stage"]
                       and not safety["duplicate_settlement_audit_entries"] and not safety["audit_receipt_errors"]
                       and publication["published_outputs_consistent"]
                       and cleanup["cleanup_count_matches_snapshot_difference"] is not False
                       and not cleanup["remaining_worker_staged_files"]
                       and overlap["unmatched_notification_admissions"] == 0)
        execution_completed = meta.get("status", "completed") == "completed"
        return {"run_id": workload.get("run_id", directory.name), "run_directory": str(directory),
                **meta, **safety, **client, **publication, **overlap, **recovery, **cleanup,
                "analysis_status": ("run_failed" if not execution_completed else "valid" if correctness else "correctness_failure"),
                "correctness_checks_passed": correctness,
                "throughput_effects_per_s": safety["settled"] / client["measured_seconds"],
                "final_eligible_completion_fraction": safety["final_eligible_settled"] / safety["final_eligible"] if safety["final_eligible"] else None,
                "independent_completion_fraction": safety["independent_settled"] / safety["independent_effects"] if safety["independent_effects"] else None,
                "raw_file_sha256": file_hashes}
    except (ValueError, KeyError, TypeError, OSError) as exc:
        return {"run_id": directory.name, "run_directory": str(directory), **meta,
                "analysis_status": "invalid", "analysis_error": str(exc)}


def bootstrap_mean_ci(values: Iterable[float], *, seed: int = 807, resamples: int = 4000) -> dict[str, Any]:
    """Resample whole seed observations, never individual RPCs/effects."""
    values = list(values)
    if not values:
        return {"n": 0, "mean": None, "ci95_low": None, "ci95_high": None}
    if len(values) == 1:
        return {"n": 1, "mean": values[0], "ci95_low": None, "ci95_high": None}
    if all(value == values[0] for value in values):
        # Every bootstrap resample has the same mean in this exact case.
        return {"n": len(values), "mean": values[0], "ci95_low": values[0], "ci95_high": values[0]}
    rng = random.Random(seed)
    estimates = [mean(rng.choices(values, k=len(values))) for _ in range(resamples)]
    return {"n": len(values), "mean": mean(values),
            "ci95_low": quantile(estimates, 0.025), "ci95_high": quantile(estimates, 0.975)}


CONFIG_FIELDS = ("case", "mode", "workers", "fanout", "notification_delay_ms")
METRICS = ("throughput_effects_per_s", "completion_p50_ms", "completion_p95_ms",
           "rpc_p95_ms", "reissue_count", "conservative_stale_rejections",
           "independent_completion_fraction", "final_eligible_completion_fraction",
           "incomplete_effects", "unsafe_settlements", "source_time_exposure_settlements")


def aggregate_runs(runs: list[dict[str, Any]], *, reference: str = "full_recheck") -> dict[str, Any]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    pair_groups: dict[tuple[Any, ...], dict[str, dict[str, Any]]] = defaultdict(dict)
    invalid = [row for row in runs if row.get("analysis_status") != "valid"]
    expected_policies: dict[tuple[Any, ...], set[str]] = defaultdict(set)
    for run in runs:
        if "policy" in run:
            config = tuple(run.get(key, "free" if key == "mode" else None) for key in CONFIG_FIELDS)
            expected_policies[config].add(run["policy"])
    for run in runs:
        if run.get("analysis_status") != "valid":
            continue
        config = tuple(run.get(key, "free" if key == "mode" else None) for key in CONFIG_FIELDS)
        groups[config + (run["policy"],)].append(run)
        pair_key = config + (run["seed"],)
        policy = run["policy"]
        if policy in pair_groups[pair_key]:
            raise OracleInputError(f"duplicate seed/config/policy: {pair_key}, {policy}")
        pair_groups[pair_key][policy] = run
    summary: list[dict[str, Any]] = []
    for key, rows in sorted(groups.items(), key=lambda item: str(item[0])):
        record: dict[str, Any] = dict(zip(CONFIG_FIELDS + ("policy",), key))
        record.update({"runs": len(rows), "seeds": sorted(row["seed"] for row in rows)})
        for metric in METRICS:
            record[metric] = bootstrap_mean_ci(row[metric] for row in rows if row.get(metric) is not None)
        summary.append(record)
    differences: dict[tuple[Any, ...], dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    unpaired: list[dict[str, Any]] = []
    for key, policies in pair_groups.items():
        missing_policies = expected_policies[key[:-1]] - policies.keys()
        if missing_policies:
            unpaired.append({**dict(zip(CONFIG_FIELDS + ("seed",), key)), "missing_valid_policies": sorted(missing_policies)})
        if reference not in policies:
            unpaired.append({**dict(zip(CONFIG_FIELDS + ("seed",), key)), "missing_reference": reference})
            continue
        baseline = policies[reference]
        for policy, run in policies.items():
            if policy == reference:
                continue
            if baseline.get("common_input_sha256") != run.get("common_input_sha256"):
                raise OracleInputError(f"paired policies have different input hashes: {key}, {policy}")
            for metric in METRICS:
                if run.get(metric) is not None and baseline.get(metric) is not None:
                    differences[key[:-1] + (policy,)][metric].append(run[metric] - baseline[metric])
    paired = []
    for key, metrics in sorted(differences.items(), key=lambda item: str(item[0])):
        paired.append({**dict(zip(CONFIG_FIELDS + ("policy",), key)), "reference": reference,
                       "difference_definition": "policy minus reference, paired by seed and workload configuration",
                       **{metric: bootstrap_mean_ci(values) for metric, values in metrics.items()}})
    return {"run_count": len(runs), "valid_run_count": len(runs) - len(invalid),
            "invalid_or_failed_run_count": len(invalid), "invalid_or_failed_runs": invalid,
            "summary": summary, "paired_differences": paired, "unpaired_runs": unpaired,
            "statistical_unit": "one complete run per workload seed; bootstrap resamples seeds",
            "confidence_interval": "percentile bootstrap 95%, 4000 resamples; n=1 has no interval",
            "latency_censoring": "completion quantiles cover successful client replies only; all incomplete effects reported",
            "deployment_scope": "independent processes and loopback HTTP on one physical Windows host"}


def write_analysis(run_dirs: Iterable[str | Path], output_dir: str | Path) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    runs = [analyze_run(directory) for directory in run_dirs]
    aggregate = aggregate_runs(runs)
    (output / "distributed_analysis.json").write_text(json.dumps({"runs": runs, **aggregate}, indent=2, ensure_ascii=False), encoding="utf-8")
    columns = ["run_id", "analysis_status", "policy", "seed", *CONFIG_FIELDS,
               "effects_total", "settled", "client_completed", "measured_seconds", *METRICS,
               "duplicate_ledger_entries", "balance_conserved", "balances_match_ledger",
               "transport_failures", "analysis_error"]
    with (output / "distributed_per_run.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(runs)
    summary_rows = []
    for row in aggregate["summary"]:
        for metric in METRICS:
            summary_rows.append({**{key: row[key] for key in (*CONFIG_FIELDS, "policy")},
                                 "metric": metric, **row[metric]})
    with (output / "distributed_summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[*CONFIG_FIELDS, "policy", "metric", "n", "mean", "ci95_low", "ci95_high"])
        writer.writeheader()
        writer.writerows(summary_rows)
    return aggregate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True, help="Parent directory with one subdirectory per attempted run")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    directories = sorted(path for path in args.runs.iterdir() if path.is_dir())
    result = write_analysis(directories, args.out)
    print(json.dumps({key: result[key] for key in ("run_count", "valid_run_count", "invalid_or_failed_run_count")}, indent=2))
    if result["invalid_or_failed_run_count"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
