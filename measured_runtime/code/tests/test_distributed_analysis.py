"""Hand-authored counterexamples for the independently implemented evaluator."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from distributed_analysis import (OracleInputError, PrefixOracle, aggregate_runs,
                                  bootstrap_mean_ci, client_metrics,
                                  complete_supports, evaluate_prefix,
                                  notification_overlap, published_output_checks,
                                  recompute_output)


def workload():
    return {
        "run_id": "oracle-test", "seed": 1, "expires_at": 1000.0,
        "accounts": {"payer": 100, "recipient": 0},
        "extra_subjects": ["o:outside"],
        "registry": {
            "artifact_parents": {"root": [], "child": ["root"], "other": [], "unused": []},
            "artifact_obligations": {"root": ["certificate"], "child": ["receipt"], "other": []},
            "effect_artifacts": {"e1": ["child"], "e2": ["other"]},
            "effect_obligations": {"e1": ["authorization"], "e2": []}},
        "effects": [{"effect_id": e, "payer": "payer", "recipient": "recipient", "amount": 5, "payload": {"id": e}}
                    for e in ("e1", "e2")],
    }


def event(seq, kind, at_time, effect_id=None, subject_id=None, **payload):
    return {"seq": seq, "kind": kind, "at_time": at_time,
            "effect_id": effect_id, "subject_id": subject_id, "payload": payload}


def snapshot(audit, settled=()):
    ledger = [{"effect_id": eid, "nonce": "nonce:" + eid, "payer": "payer", "recipient": "recipient", "amount": 5}
              for eid in settled]
    return {"audit": audit, "ledger": ledger,
            "accounts": {"payer": 100 - 5 * len(ledger), "recipient": 5 * len(ledger)}, "stages": []}


class IndependentOracleTests(unittest.TestCase):
    def test_support_includes_ancestor_obligation_and_effect_local_evidence(self):
        supports = complete_supports(workload()["registry"])
        self.assertEqual(supports["e1"], {"a:root", "a:child", "o:certificate", "o:receipt", "o:authorization"})
        self.assertEqual(supports["e2"], {"a:other"})

    def test_bad_runtime_compiled_support_cannot_hide_unsafe_settlement(self):
        state = snapshot([event(1, "invalidate", 10, subject_id="o:certificate"),
                          event(2, "settle", 11, effect_id="e1")], ("e1",))
        state["effect_support"] = [{"effect_id": "e1", "subject_id": "a:child"}]
        result = evaluate_prefix(workload(), state)
        self.assertEqual(result["unsafe_settlements"], 1)
        self.assertIn("invalid:o:certificate", result["unsafe_details"][0]["reasons"])

    def test_unobserved_source_failure_is_exposure_not_admitted_unsafe(self):
        state = snapshot([event(1, "settle", 11, effect_id="e1"),
                          event(2, "invalidate", 12, subject_id="a:root")], ("e1",))
        result = evaluate_prefix(workload(), state, [{"subject_id": "a:root", "occurred_at": 10, "admitted_at": 12.5}])
        self.assertEqual(result["unsafe_settlements"], 0)
        self.assertEqual(result["source_time_exposure_settlements"], 1)

    def test_settlement_before_source_failure_is_not_exposure(self):
        state = snapshot([event(1, "settle", 9, effect_id="e1")], ("e1",))
        result = evaluate_prefix(workload(), state, [{"subject_id": "a:root", "occurred_at": 10}])
        self.assertEqual(result["source_time_exposure_settlements"], 0)

    def test_expiry_equality_denies(self):
        work = workload()
        work["subject_expiries"] = {"o:certificate": 10}
        state = snapshot([event(1, "settle", 10, effect_id="e1")], ("e1",))
        result = evaluate_prefix(work, state)
        self.assertEqual(result["unsafe_details"][0]["reasons"], ["expired:o:certificate"])

    def test_rejection_uses_failed_evaluation_prefix_not_later_logging_prefix(self):
        state = snapshot([event(1, "refresh", 10, subject_id="a:root", valid=1, expires_at=1000),
                          event(2, "invalidate", 12, subject_id="a:root"),
                          event(3, "reject", 13, effect_id="e1", operation="settle", reason="stale_support_epoch",
                                evaluated_prefix_seq=1, evaluated_at=11)])
        result = evaluate_prefix(workload(), state)
        self.assertEqual(result["conservative_stale_rejections"], 1)
        self.assertFalse(result["operation_predicates"][-1]["eligible"])

    def test_uninstrumented_rejection_never_invented_as_conservative(self):
        state = snapshot([event(1, "reject", 10, effect_id="e1", operation="settle", reason="stale_global_epoch")])
        result = evaluate_prefix(workload(), state)
        self.assertEqual(result["conservative_stale_rejections"], 0)
        self.assertEqual(result["unidentifiable_stale_rejections"], 1)

    def test_cycle_and_unknown_parent_are_rejected(self):
        work = workload()
        work["registry"]["artifact_parents"]["root"] = ["child"]
        with self.assertRaises(OracleInputError):
            complete_supports(work["registry"])
        work["registry"]["artifact_parents"]["root"] = ["missing"]
        with self.assertRaises(OracleInputError):
            complete_supports(work["registry"])

    def test_extra_and_unused_subjects_can_receive_unrelated_mutations(self):
        state = snapshot([event(1, "invalidate", 10, subject_id="o:outside"),
                          event(2, "invalidate", 11, subject_id="a:unused"),
                          event(3, "settle", 12, effect_id="e1")], ("e1",))
        result = evaluate_prefix(workload(), state)
        self.assertEqual(result["unsafe_settlements"], 0)
        self.assertEqual(result["independent_effects"], 2)

    def test_contract_extension_changes_independent_predicate(self):
        state = snapshot([event(1, "extend", 10, effect_id="e2", additions=["o:outside"]),
                          event(2, "invalidate", 11, subject_id="o:outside"),
                          event(3, "settle", 12, effect_id="e2")], ("e2",))
        result = evaluate_prefix(workload(), state)
        self.assertEqual(result["unsafe_settlements"], 1)

    def test_cleanup_checks_expected_cohort_and_actual_stages(self):
        state = snapshot([event(1, "invalidate", 10, subject_id="a:root"),
                          event(2, "cleanup", 11, cancelled_effects=["e2"])])
        state["stages"] = [{"effect_id": "e2"}]
        result = evaluate_prefix(workload(), state)
        self.assertEqual(result["cleanup_errors"], [{"seq": 2, "missing": ["e1"], "collateral": ["e2"]}])
        self.assertEqual(result["cancelled_effects_with_remaining_stage"], ["e2"])

    def test_balance_corruption_detected_even_with_total_conserved(self):
        state = snapshot([event(1, "settle", 10, effect_id="e1")], ("e1",))
        state["accounts"] = {"payer": 90, "recipient": 10}
        result = evaluate_prefix(workload(), state)
        self.assertTrue(result["balance_conserved"])
        self.assertFalse(result["balances_match_ledger"])

    def test_planned_but_unadmitted_mutation_excluded_from_independent_cohort(self):
        result = evaluate_prefix(workload(), snapshot([]), planned_mutations=[{"subject_id": "a:root"}])
        self.assertEqual(result["independent_effect_ids"], ["e2"])

    def test_clock_regression_rejected(self):
        with self.assertRaises(OracleInputError):
            evaluate_prefix(workload(), snapshot([event(1, "issue", 11, effect_id="e1"), event(2, "settle", 10, effect_id="e1")]))


class MetricsTests(unittest.TestCase):
    def test_completion_censoring_and_task_events_separate_from_rpc(self):
        events = [
            {"operation": "task_complete", "effect_id": "e1", "start_ns": 0, "end_ns": 1000000000, "ok": True},
            {"operation": "issue", "effect_id": "e1", "start_ns": 1000000000, "end_ns": 1001000000, "ok": True},
            {"operation": "settle", "effect_id": "e1", "start_ns": 1002000000, "end_ns": 1004000000, "ok": True},
            {"operation": "issue", "effect_id": "e2", "start_ns": 1000000000, "end_ns": 1001000000, "ok": False, "reason": "invalid"}]
        result = client_metrics(events, {"started_ns": 0, "finished_ns": 2000000000}, ["e1", "e2", "e3"])
        self.assertEqual(result["completion_p95_ms"], 4.0)
        self.assertEqual(result["incomplete_effects"], 2)
        self.assertEqual(result["not_started_effects"], 1)
        self.assertLess(result["rpc_p95_ms"], 3)
        self.assertEqual(result["task_completion_p95_ms"], 1000)

    def test_single_seed_has_no_confidence_interval(self):
        self.assertIsNone(bootstrap_mean_ci([3])["ci95_low"])

    def test_paired_differences_use_run_seed_and_preserve_failed_runs(self):
        rows = []
        for seed, baseline, treatment in [(1, 100, 110), (2, 200, 210), (3, 300, 310)]:
            for policy, value in [("full_recheck", baseline), ("support_epoch", treatment)]:
                rows.append({"analysis_status": "valid", "policy": policy, "case": "load", "mode": "load", "workers": 4,
                             "fanout": 2, "notification_delay_ms": 0, "seed": seed, "throughput_effects_per_s": value})
        rows.append({"analysis_status": "invalid", "run_id": "failed-seed", "analysis_error": "missing snapshot"})
        result = aggregate_runs(rows)
        self.assertEqual(result["invalid_or_failed_run_count"], 1)
        paired = result["paired_differences"][0]["throughput_effects_per_s"]
        self.assertEqual(paired, {"n": 3, "mean": 10, "ci95_low": 10.0, "ci95_high": 10.0})

    def test_duplicate_seed_policy_refused(self):
        row = {"analysis_status": "valid", "policy": "full_recheck", "seed": 1}
        with self.assertRaises(OracleInputError):
            aggregate_runs([row, copy.deepcopy(row)])


class PublicationAndOverlapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.directory = Path(self.temp.name)
        self.work = workload()
        self.work["workers"] = 2
        for index, effect in enumerate(self.work["effects"]):
            effect.update({"input_values": [-2, 0, 3], "calibration_factor": index + 2, "generation": "v1"})
            effect["payload"] = recompute_output(effect)
        self.state = snapshot([], ("e1",))
        payload = self.work["effects"][0]["payload"]
        digest = hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.state["effects"] = [{"effect_id": "e1", "payload_hash": digest}]

    def tearDown(self):
        self.temp.cleanup()

    def publish(self, effect_id="e1", worker="0", payload=None):
        path = self.directory / "worker_state" / worker / "published" / (effect_id + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = payload if payload is not None else next(effect["payload"] for effect in self.work["effects"] if effect["effect_id"] == effect_id)
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_independent_integer_recomputation(self):
        result = recompute_output(self.work["effects"][0])
        self.assertEqual(result["sum"], 2)
        self.assertEqual(result["sum_squares"], 52)
        self.assertEqual(result["result_sha256"], hashlib.sha256(b"[-4,0,6]").hexdigest())

    def test_valid_publication_matches_ledger_and_independent_result(self):
        self.publish()
        result = published_output_checks(self.directory, self.work, self.state, [])
        self.assertTrue(result["published_outputs_consistent"])
        self.assertEqual(result["published_effect_count"], 1)

    def test_committed_but_missing_file_is_explicit_failure(self):
        result = published_output_checks(self.directory, self.work, self.state, [])
        self.assertFalse(result["published_outputs_consistent"])
        self.assertEqual(result["missing_published_effects"], ["e1"])

    def test_wrong_declared_payload_does_not_define_oracle_truth(self):
        self.publish()
        self.work["effects"][0]["payload"]["sum"] = 999
        result = published_output_checks(self.directory, self.work, self.state, [])
        self.assertIn("declared_payload_differs_from_independent_computation", [error["reason"] for error in result["published_output_errors"]])

    def test_blocked_effect_cannot_have_published_file(self):
        self.publish()
        self.publish("e2", "1")
        result = published_output_checks(self.directory, self.work, self.state,
                                         [{"operation": "task_blocked", "effect_id": "e2"}])
        reasons = [error["reason"] for error in result["published_output_errors"]]
        self.assertIn("published_without_committed_ledger", reasons)
        self.assertIn("blocked_effect_has_published_output", reasons)
        self.assertEqual(result["blocked_effects_with_published_output"], ["e2"])

    def test_content_and_ledger_hash_corruption_caught(self):
        wrong = copy.deepcopy(self.work["effects"][0]["payload"])
        wrong["sum"] += 1
        self.publish(payload=wrong)
        self.state["effects"][0]["payload_hash"] = "corrupted"
        result = published_output_checks(self.directory, self.work, self.state, [])
        self.assertEqual({error["reason"] for error in result["published_output_errors"]},
                         {"published_payload_differs_from_independent_computation", "committed_payload_hash_differs_from_independent_computation"})

    def test_duplicate_wrong_worker_file_caught(self):
        self.publish()
        self.publish(worker="1")
        result = published_output_checks(self.directory, self.work, self.state, [])
        self.assertEqual(result["duplicate_published_effects"], {"e1": 2})
        self.assertIn("wrong_worker_output_directory", [error["reason"] for error in result["published_output_errors"]])

    def test_case_name_cannot_imply_notification_overlap(self):
        self.work["case"] = "mixed_load"
        rows = [event(1, "issue", 10, effect_id="e1"), event(2, "settle", 11, effect_id="e1"),
                event(3, "invalidate", 13, subject_id="a:root", epoch=1)]
        for row in rows[:2]:
            row["actor_id"] = "worker-0"
        source = [{"kind": "invalidate", "subject_id": "a:root", "occurred_at": 12,
                   "occurred_ns": 12000000000, "injected_notification_delay_ms": 100,
                   "response": {"ok": True, "result": 1}}]
        events = [{"operation": "task_start", "effect_id": "e1", "start_ns": 9000000000, "end_ns": 9000000000},
                  {"operation": "task_complete", "effect_id": "e1", "start_ns": 9000000000, "end_ns": 11500000000}]
        result = notification_overlap(self.work, {"audit": rows}, events, source)
        detail = result["notification_overlap_details"][0]
        self.assertEqual(result["mutations_after_last_gateway_worker_operation"], 1)
        self.assertEqual(detail["relevant_settled_before_admission"], 1)
        self.assertEqual(detail["relevant_issued_pending_effects"], 0)
        self.assertEqual(detail["measured_source_to_admission_ms"], 1000)
        self.assertEqual(detail["injected_notification_delay_ms"], 100)
        self.assertTrue(detail["estimated_after_last_worker_task"])

    def test_exact_issued_overlap_and_unmatched_admission_reported(self):
        rows = [event(1, "issue", 10, effect_id="e1"), event(2, "invalidate", 11, subject_id="a:root", epoch=1),
                event(3, "reject", 12, effect_id="e1", reason="support_invalidated")]
        rows[0]["actor_id"] = rows[2]["actor_id"] = "worker-0"
        source = [{"kind": "invalidate", "subject_id": "a:root", "occurred_at": 10.5, "response": {"result": 1}},
                  {"kind": "refresh", "subject_id": "o:outside", "occurred_at": 10.75}]
        result = notification_overlap(self.work, {"audit": rows}, [], source)
        self.assertEqual(result["mutations_with_relevant_issued_pending_effects"], 1)
        self.assertEqual(result["unmatched_notification_admissions"], 1)


if __name__ == "__main__":
    unittest.main()
