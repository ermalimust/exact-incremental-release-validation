"""Counterexample tests for independent batch and sustained-arrival analysis."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from continuous_analysis import evaluate_prefix, stage_flow_checks, measured_metrics
from continuous_suite import make_workload, configurations
from distributed_analysis import complete_supports


def fixture():
    workload = {"registry": {"artifact_parents": {"r": [], "u": []},
        "artifact_obligations": {}, "effect_artifacts": {"a": ["r"], "b": ["r"], "c": ["u"]},
        "effect_obligations": {}}, "effects": [{"effect_id": name, "payer": "budget",
        "recipient": "sink", "amount": 1} for name in "abc"],
        "expires_at": 100, "accounts": {"budget": 10, "sink": 0}}
    snapshot = {"audit": [{"seq":1,"kind":"invalidate","subject_id":"a:r","at_time":1,
        "payload":{"valid":False,"expires_at":100}},
        {"seq":2,"kind":"cleanup","at_time":2,"payload":{"cancelled_effects":["a"],
        "scanned_effects":["a"],"root":"a:r","batch_size":1,"has_more":True,"stage_rows_deleted":0}},
        {"seq":3,"kind":"cleanup","at_time":3,"payload":{"cancelled_effects":["b"],
        "scanned_effects":["b"],"root":"a:r","batch_size":1,"has_more":False,"stage_rows_deleted":0}}],
        "ledger":[],"stages":[],"accounts":[{"account_id":"budget","balance":10},{"account_id":"sink","balance":0}]}
    return workload, snapshot


class CleanupOracleTests(unittest.TestCase):
    def test_valid_partial_batches_are_accepted(self):
        workload, snapshot = fixture()
        report = evaluate_prefix(workload,snapshot)
        self.assertEqual(report["cleanup_errors"],[])
        self.assertEqual(report["final_eligible_effect_ids"],["c"])

    def test_premature_queue_empty_is_rejected(self):
        workload,snapshot = fixture()
        snapshot["audit"][1]["payload"]["has_more"] = False
        self.assertEqual(evaluate_prefix(workload,snapshot)["cleanup_errors"][0]["missing"],["b"])

    def test_collateral_independent_cancellation_is_rejected(self):
        workload,snapshot = fixture()
        snapshot["audit"][1]["payload"]["cancelled_effects"]=["c"]
        self.assertEqual(evaluate_prefix(workload,snapshot)["cleanup_errors"][0]["collateral"],["c"])

    def test_scanned_candidates_not_only_deletions_respect_bound(self):
        workload,snapshot = fixture()
        snapshot["audit"][1]["payload"]["scanned_effects"]=["a","b"]
        self.assertTrue(evaluate_prefix(workload,snapshot)["cleanup_errors"][0]["batch_limit_exceeded"])

    def test_wrong_root_scan_is_rejected(self):
        workload,snapshot = fixture()
        snapshot["audit"][1]["payload"]["root"]="a:u"
        self.assertEqual(evaluate_prefix(workload,snapshot)["cleanup_errors"][0]["scan_errors"],["a"])

    def test_repeated_empty_queue_after_completion_is_accepted(self):
        workload,snapshot = fixture()
        snapshot["audit"].append({"seq":4,"kind":"cleanup","at_time":4,"payload":{
            "cancelled_effects":[],"scanned_effects":[],"root":None,"batch_size":1,"has_more":False,"stage_rows_deleted":0}})
        self.assertFalse(evaluate_prefix(workload,snapshot)["cleanup_errors"])

    def test_stage_deletion_is_independently_counted(self):
        snapshot={"audit":[{"seq":1,"kind":"stage","effect_id":"a"},
            {"seq":2,"kind":"cleanup","payload":{"cancelled_effects":["a"],"stage_rows_deleted":1}}],"stages":[]}
        self.assertFalse(stage_flow_checks(snapshot)["stage_flow_errors"])
        snapshot["audit"][1]["payload"]["stage_rows_deleted"]=0
        self.assertEqual(stage_flow_checks(snapshot)["stage_flow_errors"][0]["reason"],"cleanup_stage_count")

    def test_unreported_remaining_stage_is_detected(self):
        snapshot={"audit":[{"seq":1,"kind":"stage","effect_id":"a"}],"stages":[]}
        self.assertEqual(stage_flow_checks(snapshot)["stage_flow_errors"][0]["reason"],"final_stage_set")


class WorkloadTests(unittest.TestCase):
    def test_seed_reproducibility(self):
        config=configurations("smoke")[0]
        self.assertEqual(make_workload(config,7),make_workload(config,7))

    def test_seed_changes_graph_and_timing(self):
        config=configurations("smoke")[0]
        first,second=make_workload(config,7),make_workload(config,8)
        self.assertNotEqual(first["registry"]["artifact_parents"],second["registry"]["artifact_parents"])
        self.assertNotEqual(first["source_event_plan"],second["source_event_plan"])
        self.assertNotEqual(first["effects"][0]["arrival_offset_ms"],second["effects"][0]["arrival_offset_ms"])

    def test_support_size_is_independent_of_fanout(self):
        config=configurations("smoke")[0]
        for size in (16,64):
            for fanout in (4,32):
                workload=make_workload({**config,"support_size":size,"fanout":fanout},42)
                supports=complete_supports(workload["registry"])
                self.assertEqual({len(supports[item["effect_id"]]) for item in workload["effects"]
                    if not item.get("cleanup_backlog")},{size})

    def test_backlog_is_outside_arrival_denominator(self):
        workload=make_workload(configurations("smoke")[0],7)
        self.assertEqual(sum(not item.get("cleanup_backlog",False) for item in workload["effects"]),workload["arrival_count"])
        self.assertEqual(sum(item.get("cleanup_backlog",False) for item in workload["effects"]),24)

    def test_no_refresh_resurrects_revoked_generation(self):
        workload=make_workload(configurations("main")[0],7)
        revoked={item["subject_id"] for item in workload["source_event_plan"] if item["kind"]=="invalidate"}
        self.assertFalse(any(item["subject_id"] in revoked for item in workload["source_event_plan"] if item["kind"]=="refresh"))


class MeasurementTests(unittest.TestCase):
    def measured(self,extra=None):
        workload={"warmup_s":1,"measurement_s":2,"effects":[
            {"effect_id":"w","phase":"warmup","arrival_offset_ms":100},
            {"effect_id":"a","phase":"measurement","arrival_offset_ms":1100},
            {"effect_id":"b","phase":"measurement","arrival_offset_ms":2900},
            {"effect_id":"c","phase":"measurement","arrival_offset_ms":2000}]}
        meta={"started_ns":0,"measurement_start_ns":1_000_000_000,"measurement_end_ns":3_000_000_000}
        events=[{"operation":"task_complete","effect_id":"w","start_ns":100_000_000,"end_ns":1_200_000_000},
            {"operation":"task_complete","effect_id":"a","start_ns":1_100_000_000,"end_ns":2_000_000_000},
            {"operation":"task_complete","effect_id":"b","start_ns":2_900_000_000,"end_ns":4_000_000_000}]
        if extra:events+=extra
        safety={"independent_effect_ids":["a","b","c"],"final_eligible_effect_ids":["a","b","c"]}
        return measured_metrics(workload,meta,events,[],[],{},safety)

    def test_window_goodput_excludes_drain_but_includes_in_window_warmup_completion(self):
        report=self.measured()
        self.assertEqual(report["measurement_window_completed"],2)
        self.assertEqual(report["measurement_goodput_per_s"],1)
        self.assertEqual(report["measurement_cohort_completed"],2)

    def test_incomplete_is_retained_in_denominator(self):
        report=self.measured()
        self.assertEqual(report["measurement_arrivals"],3)
        self.assertEqual(report["measurement_cohort_incomplete"],1)
        self.assertAlmostEqual(report["measurement_cohort_completion_fraction"],2/3)

    def test_blocked_is_separate_from_incomplete(self):
        report=self.measured([{"operation":"task_blocked","effect_id":"c","start_ns":2_000_000_000,"end_ns":2_500_000_000}])
        self.assertEqual(report["measurement_cohort_blocked"],1)
        self.assertEqual(report["measurement_cohort_incomplete"],0)

    def test_small_sample_p99_not_reported(self):
        self.assertIsNone(self.measured()["arrival_to_completion_p99_ms"])

    def test_cleanup_root_disjointness_is_not_erased_by_other_planned_updates(self):
        workload={"warmup_s":1,"measurement_s":2,"registry":{
            "artifact_parents":{"cleaned":[],"other":[]},"artifact_obligations":{},
            "effect_artifacts":{"a":["other"]},"effect_obligations":{}},
            "effects":[{"effect_id":"a","phase":"measurement","arrival_offset_ms":1100}]}
        meta={"started_ns":0,"measurement_start_ns":1_000_000_000,"measurement_end_ns":3_000_000_000}
        events=[{"operation":"task_complete","effect_id":"a","start_ns":1_100_000_000,"end_ns":2_000_000_000}]
        cleanup=[{"start_ns":1_400_000_000,"end_ns":1_500_000_000,"response":{"ok":True,
            "result":{"root":"a:cleaned","cancelled_effects":["backlog"]}}}]
        safety={"independent_effect_ids":[],"final_eligible_effect_ids":["a"]}
        report=measured_metrics(workload,meta,events,[],cleanup,{},safety)
        self.assertEqual(report["independent_tasks_overlapping_cleanup"],0)
        self.assertEqual(report["root_disjoint_tasks_overlapping_cleanup"],1)
        cleanup[0]["response"]["result"]["root"]="a:other"
        report=measured_metrics(workload,meta,events,[],cleanup,{},safety)
        self.assertEqual(report["root_disjoint_tasks_overlapping_cleanup"],0)

    def backlog_report(self, second_batch):
        workload={"warmup_s":1,"measurement_s":2,"cleanup_backlog":2,
            "cleanup_phase_contract":{"healthy_scheduled_effects":["a"]},"registry":{
            "artifact_parents":{"cleanup_root":[],"other":[]},"artifact_obligations":{},
            "effect_artifacts":{"a":["other"],"b1":["cleanup_root"],"b2":["cleanup_root"]},
            "effect_obligations":{}},"effects":[
                {"effect_id":"a","phase":"measurement","arrival_offset_ms":1600},
                {"effect_id":"b1","cleanup_backlog":True},
                {"effect_id":"b2","cleanup_backlog":True}]}
        meta={"started_ns":0,"measurement_start_ns":1_000_000_000,"measurement_end_ns":3_000_000_000}
        events=[{"operation":"task_complete","effect_id":"a","start_ns":1_600_000_000,"end_ns":1_900_000_000}]
        cleanup=[{"start_ns":1_400_000_000,"end_ns":1_500_000_000,"response":{"ok":True,
            "result":{"root":"a:cleanup_root","cancelled_effects":["b1"]},"metrics":{"transaction_ms":4}}}]
        if second_batch:
            cleanup.append({"start_ns":2_000_000_000,"end_ns":2_100_000_000,"response":{"ok":True,
                "result":{"root":"a:cleanup_root","cancelled_effects":["b2"]},"metrics":{"transaction_ms":6}}})
        safety={"independent_effect_ids":["a"],"final_eligible_effect_ids":["a"]}
        return measured_metrics(workload,meta,events,[],cleanup,{},safety)

    def test_partial_backlog_cleanup_has_no_uncensored_clearance_time(self):
        report=self.backlog_report(False)
        self.assertEqual(report["backlog_cleaned_before_final_drain"],1)
        self.assertFalse(report["backlog_cleanup_fully_observed_before_drain"])
        self.assertIsNone(report["backlog_cleanup_elapsed_ms"])
        self.assertEqual(report["backlog_root_disjoint_tasks_overlapping_window"],0)
        self.assertEqual(report["healthy_phase_cohort_count"],1)
        self.assertEqual(report["healthy_phase_cohort_completed"],1)
        self.assertEqual(report["healthy_phase_latency_max_ms"],300)

    def test_clearance_window_includes_interbatch_gaps_but_rpc_overlap_does_not(self):
        report=self.backlog_report(True)
        self.assertTrue(report["backlog_cleanup_fully_observed_before_drain"])
        self.assertEqual(report["backlog_cleanup_elapsed_ms"],700)
        self.assertEqual(report["backlog_cleanup_transaction_total_ms"],10)
        self.assertEqual(report["backlog_cleanup_transaction_max_ms"],6)
        self.assertEqual(report["root_disjoint_tasks_overlapping_cleanup"],0)
        self.assertEqual(report["backlog_root_disjoint_tasks_overlapping_window"],1)
        self.assertEqual(report["backlog_root_disjoint_completions_during_window"],1)
        self.assertEqual(report["backlog_root_disjoint_tasks_overlapping_rpc"],0)
        self.assertEqual(report["backlog_root_disjoint_completions_during_rpc"],0)
        self.assertEqual(report["backlog_overlap_latency_max_ms"],300)


if __name__=="__main__":
    unittest.main()
