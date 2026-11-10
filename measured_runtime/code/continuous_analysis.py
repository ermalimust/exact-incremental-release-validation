"""Independent graph/prefix validation and whole-run statistics for sustained arrivals.

No runtime gateway or worker is imported. The graph oracle, payload recomputation,
and bootstrap helper are inherited from the independently implemented 04 oracle;
batched cleanup is checked against its reconstructed eligible set.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
import math
from pathlib import Path
from statistics import mean
from typing import Any
from distributed_analysis import (PrefixOracle, OracleInputError, _payload, _effect,
    _subject, _finite, _jsonl, complete_supports, published_output_checks,
    notification_overlap, quantile, bootstrap_mean_ci)

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
            terminal_effects = accepted_so_far | oracle.cancelled
            expected_cancelled = {effect for effect, support in oracle.supports.items()
                                  if effect not in terminal_effects
                                  and any(not oracle.subjects.get(subject, {"valid": False})["valid"]
                                          for subject in support)}
            batch = payload.get("batch_size")
            collateral = observed - expected_cancelled
            missing = expected_cancelled - observed if not payload.get("has_more", False) else set()
            scanned = payload.get("scanned_effects", list(observed))
            too_large = batch is not None and len(scanned) > int(batch)
            root = payload.get("root")
            scan_errors = [effect for effect in scanned if root is not None and root not in oracle.supports.get(effect, set())]
            if observed - set(scanned):
                scan_errors += sorted(observed - set(scanned))
            if collateral or missing or too_large or scan_errors:
                cleanup_errors.append({"seq": seq, "missing": sorted(missing),
                                       "collateral": sorted(collateral), "batch_limit_exceeded": too_large,
                                       "scan_errors": scan_errors})
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


def stage_flow_checks(snapshot):
    """Reconcile staging, cancellation and settlement, including every batch."""
    live = set()
    errors = []
    total_deleted = 0
    for row in snapshot["audit"]:
        if row["kind"] == "stage":
            live.add(_effect(row))
        elif row["kind"] == "settle":
            if _effect(row) not in live:
                errors.append({"seq": row["seq"], "reason": "settlement_without_live_stage"})
            live.discard(_effect(row))
        elif row["kind"] == "cleanup":
            payload = _payload(row)
            cancelled = set(payload.get("cancelled_effects", []))
            expected = len(live & cancelled)
            if expected != payload.get("stage_rows_deleted"):
                errors.append({"seq": row["seq"], "reason": "cleanup_stage_count", "expected": expected,
                               "reported": payload.get("stage_rows_deleted")})
            total_deleted += expected
            live -= cancelled
    actual = {row["effect_id"] for row in snapshot["stages"]}
    if live != actual:
        errors.append({"reason": "final_stage_set", "expected": sorted(live), "actual": sorted(actual)})
    return {"stage_flow_errors": errors, "cleanup_deleted_stage_rows": total_deleted}


def measured_metrics(workload, meta, events, source, cleaning, snapshot, safety):
    start, end = meta["measurement_start_ns"], meta["measurement_end_ns"]
    duration = (end - start) / 1e9
    tasks = {item["effect_id"]: item for item in workload["effects"] if not item.get("cleanup_backlog")}
    measurement = {eid for eid, task in tasks.items() if task["phase"] == "measurement"}
    independent = measurement & set(safety["independent_effect_ids"])
    eligible = measurement & set(safety["final_eligible_effect_ids"])
    complete = {row["effect_id"]: row for row in events if row["operation"] == "task_complete"}
    blocked = {row["effect_id"]: row for row in events if row["operation"] == "task_blocked"}
    unfinished = measurement - complete.keys() - blocked.keys()
    terminal = {**complete, **blocked}
    starts = {row["effect_id"]: row for row in events if row["operation"] == "task_start"}
    completed_in_window = {eid for eid, row in complete.items() if start <= row["end_ns"] < end}
    measured_complete = measurement & complete.keys()
    latencies = [(complete[eid]["end_ns"] - complete[eid]["start_ns"]) / 1e6 for eid in measured_complete]
    healthy_phase = set(workload.get("cleanup_phase_contract", {}).get("healthy_scheduled_effects", []))
    if not healthy_phase <= measurement:
        raise OracleInputError("predeclared healthy cleanup phase contains nonmeasurement identities")
    healthy_phase_latency = [(complete[eid]["end_ns"]-complete[eid]["start_ns"])/1e6
        for eid in healthy_phase & complete.keys()]
    queue = [(starts[eid]["end_ns"] - starts[eid]["start_ns"]) / 1e6 for eid in measurement if eid in starts]
    rpc = [row for row in events if not row["operation"].startswith("task_")]
    measured_rpc = [row for row in rpc if start <= row["start_ns"] < end]
    settle_rpc = [row for row in measured_rpc if row["operation"] == "settle"]
    component_names = ("lock_wait_ms", "transaction_ms", "validation_ms", "sink_sql_ms", "commit_ms", "handler_ms", "mutation_log_ms")
    components = {}
    for operation in ("stage", "issue", "settle"):
        matching = [row for row in measured_rpc if row["operation"] == operation]
        components[operation] = {}
        for component in component_names:
            values = [float(row["metrics"][component]) for row in matching
                      if isinstance(row.get("metrics"), dict) and component in row["metrics"]]
            components[operation][component] = {"n": len(values), "mean": mean(values) if values else None,
                "p50": quantile(values, .5), "p95": quantile(values, .95)}
    for operation in ("refresh", "invalidate"):
        matching = [row["response"] for row in source if row["kind"] == operation and start <= row["occurred_ns"] < end]
        components[operation] = {}
        for component in component_names:
            values = [float(row["metrics"][component]) for row in matching
                      if isinstance(row.get("metrics"), dict) and component in row["metrics"]]
            components[operation][component] = {"n": len(values), "mean": mean(values) if values else None,
                "p50": quantile(values, .5), "p95": quantile(values, .95)}
    # These are measured RPC intervals, including lock wait and transport. They
    # are not claimed to be the narrower SQLite transaction intervals.
    nonempty_cleanup = [row for row in cleaning if row["response"].get("ok")
                        and row["response"]["result"].get("cancelled_effects")]
    intervals = [(row["start_ns"], row["end_ns"]) for row in nonempty_cleanup]
    overlapping = {eid for eid in independent if eid in complete and any(
        complete[eid]["start_ns"] <= right and complete[eid]["end_ns"] >= left for left, right in intervals)}
    overlap_latencies = [(complete[eid]["end_ns"] - complete[eid]["start_ns"]) / 1e6 for eid in overlapping]
    during_cleanup = {eid for eid in independent if eid in complete and any(
        left <= complete[eid]["end_ns"] <= right for left, right in intervals)}
    # Distinguish independence from every planned mutation (above) from
    # disjointness to the particular root currently being cleaned (below).
    # A future, different update must not erase a task from the latter cohort.
    supports = complete_supports(workload["registry"]) if "registry" in workload else {}
    root_disjoint_overlap, root_disjoint_during = set(), set()
    for cleanup in nonempty_cleanup:
        root = cleanup["response"]["result"].get("root")
        if root is None:
            continue
        for eid in measured_complete:
            if root in supports.get(eid, set()):
                continue
            left, right = cleanup["start_ns"], cleanup["end_ns"]
            if complete[eid]["start_ns"] <= right and complete[eid]["end_ns"] >= left:
                root_disjoint_overlap.add(eid)
            if left <= complete[eid]["end_ns"] <= right:
                root_disjoint_during.add(eid)
    disjoint_latency = [(complete[eid]["end_ns"]-complete[eid]["start_ns"])/1e6 for eid in root_disjoint_overlap]
    backlog_cleanup = [row for row in nonempty_cleanup if row["response"]["result"].get("root") == "a:cleanup_root"]
    backlog_first = min((row["start_ns"] for row in backlog_cleanup), default=None)
    backlog_last = max((row["end_ns"] for row in backlog_cleanup), default=None)
    backlog_cleaned = {eid for row in backlog_cleanup for eid in row["response"]["result"].get("cancelled_effects", [])}
    backlog_fully_observed = len(backlog_cleaned) == workload.get("cleanup_backlog", 0)
    backlog_overlap, backlog_during = set(), set()
    backlog_rpc_overlap, backlog_rpc_during = set(), set()
    if backlog_first is not None:
        for eid in measured_complete:
            if "a:cleanup_root" in supports.get(eid,set()):
                continue
            if complete[eid]["start_ns"] <= backlog_last and complete[eid]["end_ns"] >= backlog_first:
                backlog_overlap.add(eid)
            if backlog_first <= complete[eid]["end_ns"] <= backlog_last:
                backlog_during.add(eid)
            for batch in backlog_cleanup:
                left, right = batch["start_ns"], batch["end_ns"]
                if complete[eid]["start_ns"] <= right and complete[eid]["end_ns"] >= left:
                    backlog_rpc_overlap.add(eid)
                if left <= complete[eid]["end_ns"] <= right:
                    backlog_rpc_during.add(eid)
    backlog_latency = [(complete[eid]["end_ns"]-complete[eid]["start_ns"])/1e6 for eid in backlog_overlap]
    path_counts = Counter(row.get("metrics", {}).get("validation_path", "missing") for row in settle_rpc)
    checked = [row["metrics"]["changed_checked"] for row in settle_rpc if "changed_checked" in row.get("metrics", {})]
    total = [row["metrics"]["support_total"] for row in settle_rpc if "support_total" in row.get("metrics", {})]
    trace = []
    bins = math.ceil(workload["warmup_s"] + workload["measurement_s"])
    for second in range(bins):
        lower = meta["started_ns"] + int(second * 1e9)
        upper = lower + 1_000_000_000
        trace.append({"second": second, "arrivals": sum(lower <= meta["started_ns"] + int(task["arrival_offset_ms"]*1e6) < upper for task in tasks.values()),
            "completed": sum(lower <= row["end_ns"] < upper for row in complete.values()),
            "blocked": sum(lower <= row["end_ns"] < upper for row in blocked.values()),
            "source_mutations": sum(lower <= row["occurred_ns"] < upper for row in source),
            "acknowledged_mutations": sum(lower <= row["admitted_reply_ns"] < upper for row in source),
            "cleanup_batches": sum(lower <= row["start_ns"] < upper for row in cleaning),
            "cleaned_effects": sum(len(row["response"].get("result", {}).get("cancelled_effects", [])) for row in cleaning if lower <= row["start_ns"] < upper)})
    root_ms = [(row["admitted_reply_ns"]-row["occurred_ns"])/1e6 for row in source if row["kind"]=="invalidate"]
    cleanup_ms = [(row["end_ns"]-row["start_ns"])/1e6 for row in nonempty_cleanup]
    cleanup_metrics = [row["response"].get("metrics", {}) for row in nonempty_cleanup]
    return {"measurement_seconds": duration, "measurement_arrivals": len(measurement),
        "measurement_cohort_completed": len(measured_complete), "measurement_cohort_blocked": len(measurement & blocked.keys()),
        "measurement_cohort_incomplete": len(unfinished), "measurement_incomplete_effect_ids": sorted(unfinished),
        "measurement_window_completed": len(completed_in_window), "measurement_goodput_per_s": len(completed_in_window)/duration,
        "measurement_cohort_completion_fraction": len(measured_complete)/len(measurement) if measurement else None,
        "measurement_final_eligible": len(eligible), "measurement_final_eligible_completed": len(eligible & complete.keys()),
        "measurement_final_eligible_completion_fraction": len(eligible & complete.keys())/len(eligible) if eligible else None,
        "measurement_independent": len(independent), "measurement_independent_completed": len(independent & complete.keys()),
        "measurement_independent_completion_fraction": len(independent & complete.keys())/len(independent) if independent else None,
        "completion_latency_n": len(latencies), "arrival_to_completion_p50_ms": quantile(latencies, .5),
        "arrival_to_completion_p95_ms": quantile(latencies, .95),
        "arrival_to_completion_p99_ms": quantile(latencies, .99) if len(latencies)>=200 else None,
        "queue_wait_p95_ms": quantile(queue, .95), "component_costs": components,
        "settle_validation_mean_ms": components["settle"]["validation_ms"]["mean"],
        "settle_lock_wait_p95_ms": components["settle"]["lock_wait_ms"]["p95"],
        "settle_handler_mean_ms": components["settle"]["handler_ms"]["mean"],
        "settle_sink_sql_mean_ms": components["settle"]["sink_sql_ms"]["mean"],
        "refresh_handler_mean_ms": components["refresh"]["handler_ms"]["mean"],
        "refresh_mutation_log_mean_ms": components["refresh"]["mutation_log_ms"]["mean"],
        "refresh_lock_wait_p95_ms": components["refresh"]["lock_wait_ms"]["p95"],
        "validation_path_counts": dict(path_counts),
        "settle_changed_checked_mean": mean(checked) if checked else None,
        "settle_support_total_mean": mean(total) if total else None,
        "transport_failures": sum(row.get("reason")=="transport_error" for row in rpc),
        "server_errors": sum(str(row.get("reason", "")).startswith("server_error:") for row in rpc),
        "measurement_source_occurrences": sum(start <= row["occurred_ns"] < end for row in source),
        "measurement_notification_replies": sum(start <= row["admitted_reply_ns"] < end for row in source),
        "notifications_replied_after_measurement": sum(row["admitted_reply_ns"] >= end for row in source),
        "root_reply_latency_p95_ms": quantile(root_ms, .95), "root_reply_latency_n": len(root_ms),
        "nonempty_cleanup_batches": len(nonempty_cleanup), "cleanup_rpc_p95_ms": quantile(cleanup_ms, .95),
        "cleanup_transaction_max_ms": max((row.get("transaction_ms", 0) for row in cleanup_metrics), default=0),
        "independent_tasks_overlapping_cleanup": len(overlapping), "independent_completions_during_cleanup_rpc": len(during_cleanup),
        "independent_cleanup_overlap_p95_ms": quantile(overlap_latencies, .95),
        "root_disjoint_tasks_overlapping_cleanup": len(root_disjoint_overlap),
        "root_disjoint_completions_during_cleanup_rpc": len(root_disjoint_during),
        "root_disjoint_cleanup_overlap_p95_ms": quantile(disjoint_latency,.95),
        "backlog_cleanup_elapsed_ms": (backlog_last-backlog_first)/1e6 if backlog_first is not None and backlog_fully_observed else None,
        "backlog_cleaned_before_final_drain": len(backlog_cleaned),
        "backlog_cleanup_fully_observed_before_drain": backlog_fully_observed,
        "backlog_cleanup_rpc_count": len(backlog_cleanup),
        "backlog_cleanup_transaction_total_ms": sum(row["response"].get("metrics",{}).get("transaction_ms",0) for row in backlog_cleanup),
        "backlog_cleanup_transaction_max_ms": max((row["response"].get("metrics",{}).get("transaction_ms",0) for row in backlog_cleanup), default=0),
        "backlog_root_disjoint_tasks_overlapping_window": len(backlog_overlap),
        "backlog_root_disjoint_completions_during_window": len(backlog_during),
        "backlog_root_disjoint_tasks_overlapping_rpc": len(backlog_rpc_overlap),
        "backlog_root_disjoint_completions_during_rpc": len(backlog_rpc_during),
        "backlog_overlap_latency_p50_ms": quantile(backlog_latency,.5),
        "backlog_overlap_latency_p95_ms": quantile(backlog_latency,.95),
        "backlog_overlap_latency_max_ms": max(backlog_latency,default=None),
        "healthy_phase_cohort_count": len(healthy_phase),
        "healthy_phase_cohort_completed": len(healthy_phase & complete.keys()),
        "healthy_phase_cohort_blocked": len(healthy_phase & blocked.keys()),
        "healthy_phase_cohort_incomplete": len(healthy_phase-terminal.keys()),
        "healthy_phase_latency_p50_ms": quantile(healthy_phase_latency,.5),
        "healthy_phase_latency_max_ms": max(healthy_phase_latency,default=None),
        "measurement_trace": trace, "completed_effect_ids": sorted(complete), "blocked_effect_ids": sorted(blocked)}


def analyze_run(directory):
    directory = Path(directory)
    meta = {}
    try:
        meta = json.loads((directory / "run_meta.json").read_text(encoding="utf-8"))
        workload = json.loads((directory / "workload.json").read_text(encoding="utf-8"))
        snapshot = json.loads((directory / "server_snapshot.json").read_text(encoding="utf-8"))
        authored = {key:value for key,value in workload.items() if key not in {"run_id","common_input_sha256"}}
        digest = hashlib.sha256(json.dumps(authored, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if digest != workload["common_input_sha256"] or digest != meta["common_input_sha256"]:
            raise OracleInputError("workload input hash mismatch")
        exogenous = {**authored, "config": {key:value for key,value in authored["config"].items()
            if key not in {"name", "cleanup_batch"}}}
        exogenous_digest = hashlib.sha256(json.dumps(exogenous, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        events = _jsonl(directory / "client_events.jsonl")
        source = _jsonl(directory / "source_events.jsonl")
        cleaning = _jsonl(directory / "cleanup_events.jsonl")
        if len(source) != len(workload["source_event_plan"]):
            raise OracleInputError("planned/recorded source event count mismatch")
        safety = evaluate_prefix(workload, snapshot, source, workload["source_event_plan"])
        publication = published_output_checks(directory, workload, snapshot, events)
        overlap = notification_overlap(workload, snapshot, events, source)
        stage = stage_flow_checks(snapshot)
        metrics = measured_metrics(workload, meta, events, source, cleaning, snapshot, safety)
        supports = complete_supports(workload["registry"])
        cardinalities = {len(supports[item["effect_id"]]) for item in workload["effects"] if not item.get("cleanup_backlog")}
        if cardinalities != {meta["config"]["support_size"]}:
            raise OracleInputError(f"actual support cardinalities mismatch: {cardinalities}")
        cleanup_residue = sorted({row["effect_id"] for row in snapshot["stages"]} &
            {row["effect_id"] for row in snapshot["effects"] if row["state"] == "cancelled"})
        local_residue = [path.relative_to(directory).as_posix() for path in directory.glob("worker_state/*/staged/*.json")]
        correct = (not safety["unsafe_settlements"] and not safety["duplicate_ledger_entries"]
            and not safety["duplicate_settlement_audit_entries"] and not safety["audit_receipt_errors"]
            and safety["balance_conserved"] and safety["balances_match_ledger"] and safety["audit_ledger_effects_match"]
            and not safety["ledger_binding_errors"] and not safety["cleanup_errors"] and not stage["stage_flow_errors"]
            and publication["published_outputs_consistent"] and not overlap["unmatched_notification_admissions"]
            and not cleanup_residue and not local_residue and not safety["unidentifiable_stale_rejections"])
        return {**meta, **safety, **publication, **overlap, **stage, **metrics,
            "exogenous_input_sha256": exogenous_digest,
            "actual_support_cardinalities": sorted(cardinalities), "cleanup_residue": cleanup_residue,
            "local_staged_residue": local_residue, "correctness_checks_passed": correct,
            "analysis_status": "run_failed" if meta["status"] != "completed" else "valid" if correct else "correctness_failure",
            "raw_file_sha256": {name:hashlib.sha256((directory/name).read_bytes()).hexdigest() for name in
                ("workload.json", "run_meta.json", "server_snapshot.json", "client_events.jsonl", "source_events.jsonl", "cleanup_events.jsonl")}}
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return {**meta, "run_id": directory.name, "analysis_status": "invalid", "analysis_error": repr(exc)}


METRICS = ("measurement_goodput_per_s", "arrival_to_completion_p95_ms", "arrival_to_completion_p99_ms", "queue_wait_p95_ms",
    "measurement_cohort_completion_fraction", "measurement_cohort_blocked", "measurement_cohort_incomplete",
    "measurement_final_eligible_completion_fraction", "measurement_independent_completion_fraction",
    "settle_validation_mean_ms", "settle_lock_wait_p95_ms", "settle_handler_mean_ms", "settle_sink_sql_mean_ms",
    "refresh_handler_mean_ms", "refresh_mutation_log_mean_ms", "refresh_lock_wait_p95_ms",
    "settle_changed_checked_mean", "root_reply_latency_p95_ms", "cleanup_rpc_p95_ms", "cleanup_transaction_max_ms",
    "independent_tasks_overlapping_cleanup", "independent_completions_during_cleanup_rpc",
    "independent_cleanup_overlap_p95_ms", "conservative_stale_rejections", "source_time_exposure_settlements",
    "root_disjoint_tasks_overlapping_cleanup", "root_disjoint_completions_during_cleanup_rpc", "root_disjoint_cleanup_overlap_p95_ms",
    "backlog_cleanup_elapsed_ms", "backlog_cleanup_rpc_count", "backlog_cleanup_transaction_total_ms",
    "backlog_cleanup_transaction_max_ms",
    "backlog_root_disjoint_tasks_overlapping_window", "backlog_root_disjoint_completions_during_window",
    "backlog_root_disjoint_tasks_overlapping_rpc", "backlog_root_disjoint_completions_during_rpc",
    "backlog_overlap_latency_p50_ms", "backlog_overlap_latency_p95_ms", "backlog_overlap_latency_max_ms",
    "healthy_phase_cohort_completed", "healthy_phase_cohort_incomplete",
    "healthy_phase_latency_p50_ms", "healthy_phase_latency_max_ms",
    "mutations_with_relevant_issued_pending_effects")


def aggregate(runs):
    groups, paired = defaultdict(list), defaultdict(dict)
    failures = [run for run in runs if run["analysis_status"] != "valid"]
    for run in runs:
        if run["analysis_status"] != "valid":
            continue
        key = (run["config"]["name"], run["policy"])
        groups[key].append(run)
        pairkey = (run["config"]["name"], run["seed"])
        if run["policy"] in paired[pairkey]:
            raise OracleInputError("duplicate seed/config/policy")
        paired[pairkey][run["policy"]] = run
    summary = [{"config": name, "policy": policy, "runs": len(items),
        **{metric:bootstrap_mean_ci(row[metric] for row in items if row.get(metric) is not None) for metric in METRICS}}
        for (name,policy),items in sorted(groups.items())]
    differences = defaultdict(lambda: defaultdict(list))
    for (name,seed), policies in paired.items():
        for reference in ("full_sql", "guarded_full"):
            if reference not in policies:
                continue
            baseline = policies[reference]
            for policy, run in policies.items():
                if policy == reference:
                    continue
                if run["common_input_sha256"] != baseline["common_input_sha256"]:
                    raise OracleInputError("paired inputs differ")
                for metric in METRICS:
                    if run.get(metric) is not None and baseline.get(metric) is not None:
                        differences[(name,policy,reference)][metric].append(run[metric] - baseline[metric])
    contrast = [{"config":name,"policy":policy,"reference":reference,
                 **{metric:bootstrap_mean_ci(values) for metric,values in data.items()}}
                for (name,policy,reference),data in sorted(differences.items())]
    cleanup_differences = defaultdict(lambda: defaultdict(list))
    for (name, seed), policies in paired.items():
        if not name.startswith("cleanup") or not name.endswith("_bounded"):
            continue
        comparison = name.removesuffix("_bounded")
        unbounded = paired.get((comparison+"_unbounded", seed), {})
        for policy, bounded_run in policies.items():
            if policy not in unbounded:
                continue
            reference = unbounded[policy]
            if bounded_run["exogenous_input_sha256"] != reference["exogenous_input_sha256"]:
                raise OracleInputError("bounded/unbounded cleanup exogenous inputs differ")
            for metric in METRICS:
                if bounded_run.get(metric) is not None and reference.get(metric) is not None:
                    cleanup_differences[(comparison,policy)][metric].append(bounded_run[metric] - reference[metric])
    return {"run_count": len(runs), "valid_run_count":len(runs)-len(failures),
        "invalid_or_failed_run_count":len(failures), "invalid_or_failed_runs":failures,
        "summary":summary,"paired_differences":contrast,
        "cleanup_mode_differences": [{"config":comparison,"policy":policy,"difference":"bounded minus unbounded, paired by seed",
            **{metric:bootstrap_mean_ci(values) for metric,values in rows.items()}}
            for (comparison,policy),rows in sorted(cleanup_differences.items())],
        "statistical_unit":"one complete seed-specific DAG and timing realization, paired across policies",
        "confidence_interval":"whole-run percentile bootstrap 95%; 4000 draws; the per-cell seed count is reported and small-sample intervals are exploratory",
        "latency_scope":"measurement-arrival cohort successful completions; queue time included; blocked/incomplete denominators retained",
        "throughput_scope":"completions within the fixed measurement window; drain completions excluded",
        "p99_rule":"not reported for fewer than 200 successful measurement-cohort tasks per run",
        "cleanup_scope":"observed cleanup RPC intervals include network and lock wait, not just SQLite execution",
        "deployment_scope":"one physical host with independent worker processes and loopback HTTP"}


def write_analysis(root, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    directories = [path for path in sorted(Path(root).iterdir()) if path.is_dir() and (path/"run_meta.json").exists()]
    runs = []
    for path in directories:
        result = analyze_run(path)
        runs.append(result)
        print(json.dumps({"analysis_progress":len(runs),"total":len(directories),
            "run_id":result["run_id"],"analysis_status":result["analysis_status"]}),flush=True)
    print(json.dumps({"analysis_stage":"whole-run aggregation","runs":len(runs)}),flush=True)
    result = {"runs":runs, **aggregate(runs)}
    manifest_path = Path(root)/"suite_manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {f"{config['name']}_s{seed}_{policy}" for config in manifest["configurations"]
            for seed in manifest["seeds"] for policy in manifest["policies"]}
        observed = {row["run_id"] for row in runs}
        result.update(requested_run_count=manifest["requested_runs"],
            missing_requested_runs=sorted(expected-observed), unexpected_runs=sorted(observed-expected),
            all_requested_runs_present=expected==observed)
    result["analysis_source_sha256"] = {path.name:hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (Path(__file__), Path(__file__).with_name("distributed_analysis.py"))}
    (output/"continuous_analysis.json").write_text(json.dumps(result, indent=2),encoding="utf-8")
    with (output/"continuous_per_run.csv").open("w",newline="",encoding="utf-8") as handle:
        writer = csv.DictWriter(handle,fieldnames=["run_id","policy","seed","analysis_status","settled",
            "unsafe_settlements","duplicate_ledger_entries","measurement_arrivals",*METRICS,"analysis_error"],extrasaction="ignore")
        writer.writeheader()
        writer.writerows(runs)
    print(json.dumps({key:result[key] for key in ("run_count","valid_run_count","invalid_or_failed_run_count")}),flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs",type=Path,required=True)
    parser.add_argument("--out",type=Path,required=True)
    args = parser.parse_args()
    write_analysis(args.runs,args.out)


