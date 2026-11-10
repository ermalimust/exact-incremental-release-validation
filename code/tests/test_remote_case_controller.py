"""Controller state witnesses; synthetic fixtures are not application results."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import remote_case_controller as controller

TEST_ROOT = Path(__file__).resolve().parents[2] / "build/remote_controller_test_tmp"
TEST_ROOT.mkdir(parents=True, exist_ok=True)


class ControllerStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root = Path(self.temp.name)
        self.run = self.root / "case"
        self.run.mkdir()
        self.workflow = self.root / "workflow"
        self.workflow.mkdir()
        controller.save(self.workflow / "workflow_manifest.json", {"artifacts": {}})
        self.workload = {"effects": [{"effect_id": "e"}],
            "registry": {"artifact_parents": {"root": []}, "artifact_obligations": {},
                         "effect_artifacts": {"e": ["root"]}, "effect_obligations": {}},
            "controlled_revocation": {"kind": "invalidate", "subject_id": "a:root"}}
        controller.save(self.run / "workload.json", self.workload)
        self.bootstrap_record = {"registry": self.workload["registry"], "supports": {"e": ["a:root"]},
                                 "expires_at": 4102444800.0, "subject_expiries": {"a:root": 4102444800.0,
                                 "o:remote_case:expected": 4102444800.0}, "accounts": {}, "effects": self.workload["effects"]}
        self.meta = {"controller_schema": controller.SCHEMA, "status": "initialized", "policy": "adaptive_delta",
                     "scenario": "baseline_withdrawal", "workers": 1,
                     "bootstrap_workload_sha256": controller.canonical_sha(self.bootstrap_record),
                     "workload_sha256": controller.sha(self.run / "workload.json"),
                     "workflow_manifest_sha256": controller.sha(self.workflow / "workflow_manifest.json")}
        controller.save(self.run / "run_meta.json", self.meta)
        controller.save(self.run / "source_events.json", [])
        controller.save(self.run / "cleanup_events.json", [])
        self.prepared = {"effects": [{"effect_id": "e", "state": "pending"}],
                         "tokens": [{"effect_id": "e", "nonce": "n", "state": "issued"}],
                         "stages": [{"effect_id": "e"}], "ledger": [], "cleanup_queue": [],
                         "metadata": {"workload": self.bootstrap_record},
                         "adaptive_metadata": {"policy": "adaptive_delta"}}

    def tearDown(self):
        self.temp.cleanup()

    def state(self, status):
        self.meta["status"] = status
        if status in ("intervened", "collected"):
            self.meta["gateway_origin"] = "http://localhost:1"
        controller.save(self.run / "run_meta.json", self.meta)

    def prepare_replies(self, final):
        return [{"ok": True, "result": self.prepared}, final]

    def audit_fixture(self):
        self.state("collected")
        worker = self.run / "workers/0"
        worker.mkdir(parents=True)
        controller.save(worker / "journal_0.json", {"e": {"nonce": "n"}})
        controller.save(self.run / "gateway_snapshot.json", {})

    def test_existing_case_cannot_be_overwritten(self):
        with self.assertRaises(FileExistsError):
            controller.init_run(self.run, self.workflow, "all_valid", "full_sql", 1)
        self.assertEqual(controller.read(self.run / "run_meta.json"), self.meta)

    def test_missing_prepare_token_cannot_admit_intervention(self):
        self.prepared["tokens"] = []
        with patch.object(controller, "rpc", side_effect=self.prepare_replies(None)) as request:
            with self.assertRaisesRegex(ValueError, "prepare barrier"):
                controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "initialized")
        self.assertEqual(controller.read(self.run / "source_events.json"), [])

    def test_acknowledged_intervention_is_recorded_before_settlement_release(self):
        with patch.object(controller, "rpc", side_effect=self.prepare_replies({"ok": True, "result": 1})):
            result = controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")
        self.assertTrue(result["settlement_may_start"])
        event = controller.read(self.run / "source_events.json")[0]
        self.assertEqual(event["subject_id"], "a:root")
        self.assertTrue(event["reply"]["ok"])
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "intervened")

    def test_rejected_intervention_cannot_be_relabelled_complete_or_replayed(self):
        with patch.object(controller, "rpc", side_effect=self.prepare_replies({"ok": False, "reason": "rejected"})):
            with self.assertRaisesRegex(ValueError, "not admitted"):
                controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "intervention_failed")
        with self.assertRaisesRegex(ValueError, "case status"):
            controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")

    def test_lost_intervention_reply_retains_uncertain_intent_without_replay(self):
        with patch.object(controller, "rpc", side_effect=self.prepare_replies(OSError("lost reply"))):
            with self.assertRaises(OSError):
                controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "intervention_pending")
        self.assertTrue((self.run / "intervention_intent.json").exists())
        with self.assertRaisesRegex(ValueError, "case status"):
            controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")

    def test_cleanup_stops_at_declared_batch_budget(self):
        self.state("intervened")
        replies = [{"ok": True, "result": self.prepared}] + [{"ok": True, "result": {"has_more": True}}] * 3
        with patch.object(controller, "rpc", side_effect=replies) as request:
            result = controller.cleanup_run(self.run, "http://localhost:1", "TEST_TOKEN", 2, 3, 0)
        self.assertTrue(result["has_more"])
        self.assertEqual(request.call_count, 4)
        self.assertEqual([call.args[2] for call in request.call_args_list], ["inspect", "cleanup", "cleanup", "cleanup"])
        self.assertEqual(len(controller.read(self.run / "cleanup_events.json")), 3)
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "intervened")

    def test_collect_refuses_pending_execution_and_retains_snapshot(self):
        self.state("intervened")
        with patch.object(controller, "rpc", return_value={"ok": True, "result": self.prepared}):
            with self.assertRaisesRegex(ValueError, "incomplete"):
                controller.collect_run(self.run, "http://localhost:1", "TEST_TOKEN")
        self.assertTrue((self.run / "gateway_snapshot.json").exists())
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "intervened")

    def test_terminal_snapshot_is_collected_not_completed(self):
        self.state("intervened")
        snapshot = copy.deepcopy(self.prepared)
        snapshot.update(effects=[{"effect_id": "e", "state": "settled"}], ledger=[{"effect_id": "e"}], stages=[])
        with patch.object(controller, "rpc", return_value={"ok": True, "result": snapshot}):
            controller.collect_run(self.run, "http://localhost:1", "TEST_TOKEN")
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "collected")

    def test_failed_audit_never_marks_durable_run_completed(self):
        self.audit_fixture()
        def reject(view, workflow):
            self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "collected")
            self.assertTrue(controller.read(view / "run_meta.json")["audit_view_only"])
            raise AssertionError("wrong report bytes")
        with patch.object(controller, "audit_run", side_effect=reject):
            with self.assertRaisesRegex(AssertionError, "wrong report bytes"):
                controller.audit_collected_run(self.run, self.workflow)
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "collected")
        self.assertFalse((self.run / "independent_audit.json").exists())
        self.assertFalse(list(self.run.glob(".audit_view_*")))

    def test_only_successful_independent_audit_sets_completed(self):
        self.audit_fixture()
        def accept(view, workflow):
            self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "collected")
            return {"status": "passed", "settled": 1}
        with patch.object(controller, "audit_run", side_effect=accept):
            controller.audit_collected_run(self.run, self.workflow)
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "completed")
        self.assertEqual(controller.read(self.run / "independent_audit.json")["status"], "passed")

    def test_controller_commands_cannot_overlap(self):
        with controller.controller_lock(self.run):
            with self.assertRaises(FileExistsError):
                with controller.controller_lock(self.run):
                    self.fail("overlapping controller acquired lock")
        self.assertFalse((self.run / ".controller.lock").exists())

    def test_same_policy_and_effect_ids_do_not_accept_another_case(self):
        wrong = copy.deepcopy(self.prepared)
        expiries = wrong["metadata"]["workload"]["subject_expiries"]
        expiries["o:remote_case:other"] = expiries.pop("o:remote_case:expected")
        with patch.object(controller, "rpc", return_value={"ok": True, "result": wrong}) as request:
            with self.assertRaisesRegex(ValueError, "different case"):
                controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(controller.read(self.run / "source_events.json"), [])
        self.assertEqual(controller.read(self.run / "run_meta.json")["status"], "initialized")

    def test_cleanup_and_collect_refuse_a_changed_origin_without_network_action(self):
        self.state("intervened")
        for action in (controller.cleanup_run, controller.collect_run):
            with self.subTest(action=action.__name__), patch.object(controller, "rpc") as request:
                with self.assertRaisesRegex(ValueError, "origin differs"):
                    action(self.run, "http://localhost:2", "TEST_TOKEN")
                request.assert_not_called()

    def test_cleanup_and_collect_recheck_fingerprint_at_bound_origin(self):
        self.state("intervened")
        wrong = copy.deepcopy(self.prepared)
        wrong["metadata"]["workload"]["expires_at"] += 1
        for action in (controller.cleanup_run, controller.collect_run):
            with self.subTest(action=action.__name__), patch.object(controller, "rpc", return_value={"ok": True, "result": wrong}) as request:
                with self.assertRaisesRegex(ValueError, "different case"):
                    action(self.run, "http://localhost:1", "TEST_TOKEN")
                self.assertEqual(request.call_count, 1)
                self.assertEqual(request.call_args.args[2], "inspect")

    def test_wrong_policy_and_credential_bearing_origin_are_rejected(self):
        wrong = copy.deepcopy(self.prepared)
        wrong["adaptive_metadata"]["policy"] = "full_sql"
        with patch.object(controller, "rpc", return_value={"ok": True, "result": wrong}):
            with self.assertRaisesRegex(ValueError, "policy"):
                controller.intervene_run(self.run, "http://localhost:1", "TEST_TOKEN")
        with patch.object(controller, "rpc") as request:
            with self.assertRaisesRegex(ValueError, "without credentials"):
                controller.intervene_run(self.run, "http://user:secret@localhost:1", "TEST_TOKEN")
            request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
