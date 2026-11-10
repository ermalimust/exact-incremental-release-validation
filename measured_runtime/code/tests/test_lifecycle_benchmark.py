"""Protocol-level checks for paired lifecycle workload and its external audit."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lifecycle_benchmark import (AdaptiveGateway, POLICIES, analyze, audit_run, digest, history_gap_check, run_plan,
                                 synthetic_plan, workflow_plan)


class LifecycleBenchmarkTests(unittest.TestCase):
    def test_ratio_controls_updates_not_releases(self):
        for ratio, count in [(.25, 64), (1, 16), (16, 1)]:
            plan = synthetic_plan(19, 32, ratio, epochs=2)
            self.assertEqual(sum(len(e["effects"]) for e in plan["schedule"]), 32)
            self.assertEqual([len(e["mutations"]) for e in plan["schedule"]], [count, count])
            targets = [m["subject_id"] for b in plan["schedule"] for m in b["mutations"]]
            self.assertEqual(sum(s.startswith("a:") for s in targets), len(targets)//2)
        self.assertEqual(digest(synthetic_plan(19,32,1)), digest(synthetic_plan(19,32,1)))
        self.assertNotEqual(digest(synthetic_plan(19,32,1)), digest(synthetic_plan(20,32,1)))
        with self.assertRaises(ValueError):synthetic_plan(1,32,3)

    def test_all_policies_same_external_lifecycle_and_no_double_count(self):
        with tempfile.TemporaryDirectory(prefix="lifecycle-functional-") as scratch:
            plan = synthetic_plan(123, 8, 2, epochs=2, group_size=2)
            results = [run_plan(Path(scratch)/policy, plan, policy) for policy in POLICIES]
            summary = analyze(results)
            self.assertEqual(summary["completed_runs"], 3)
            for result in results:
                self.assertEqual(result["audit"]["ledger_rows"], 4)
                self.assertEqual(result["phase_totals"]["refresh"]["count"], 2)
                self.assertEqual(result["phase_totals"]["stage"]["count"], 4)
                self.assertEqual(result["phase_totals"]["issue"]["count"], 4)
                self.assertEqual(result["phase_totals"]["settle"]["count"], 4)
                self.assertAlmostEqual(result["one_time_setup"]["wall_ms"]+result["operational_lifecycle"]["wall_ms"],
                                       result["full_lifecycle"]["wall_ms"], places=6)
                self.assertLessEqual(result["operational_writer_ms"], result["operational_lifecycle"]["wall_ms"]+1)
            altered = copy.deepcopy(results)
            altered[0]["input_sha256"] = "incorrect"
            with self.assertRaises(AssertionError):analyze(altered)
            with self.assertRaisesRegex(AssertionError, "duplicate paired run"):
                analyze(results+[copy.deepcopy(results[0])])

    def test_withdrawal_is_independently_rejected_and_reclaimed(self):
        with tempfile.TemporaryDirectory(prefix="lifecycle-withdrawal-") as scratch:
            plan = synthetic_plan(124, 8, 2, epochs=1, group_size=2)
            plan["schedule"][0]["mutations"] = [{"kind":"invalidate", "subject_id":"a:support:00000"}]
            results = []
            for policy in POLICIES:
                result = run_plan(Path(scratch)/policy, plan, policy)
                self.assertEqual(result["audit"]["expected_accepted"], [])
                self.assertEqual(len(result["audit"]["expected_blocked"]), 2)
                self.assertEqual(result["phase_totals"]["cleanup"]["count"], 1)
                results.append(result)
            self.assertEqual(analyze(results)["status"], "passed")

    def test_old_minimum_extension_and_shortening_are_current_predicate(self):
        for extension in (True, False):
            with tempfile.TemporaryDirectory(prefix="lifecycle-deadline-") as scratch:
                plan = synthetic_plan(125, 8, 2, epochs=1, group_size=2)
                subject = "a:support:00000"
                plan["deadline_overrides"] = {subject: 5.0}
                plan["schedule"][0]["mutations"] = [{"kind":"refresh", "subject_id":subject,
                                                      "deadline":50.0 if extension else 3.0}]
                plan["schedule"][0]["settle_at"] = 6.0
                if not extension:plan["post_settlement_invalidation"] = subject
                for policy in POLICIES:
                    result = run_plan(Path(scratch)/policy, plan, policy)
                    self.assertEqual(result["audit"]["ledger_rows"], 2 if extension else 0)
                    if extension and policy == "adaptive_delta":
                        self.assertEqual(result["validation_paths"], {"fallback_deadline": 2})

    def test_audit_catches_tampered_acceptance_without_relying_on_flag(self):
        with tempfile.TemporaryDirectory(prefix="lifecycle-oracle-") as scratch:
            run = Path(scratch)/"run"
            plan = synthetic_plan(126,8,2,epochs=1,group_size=2)
            run_plan(run,plan,"adaptive_delta",keep_database=True)
            # The event oracle independently derives eligibility before ledger checks.
            decisions = json.loads((run/"decisions.json").read_text(encoding="utf-8"))
            next(event for event in decisions if event["kind"] == "settle")["accepted"] = False
            with self.assertRaisesRegex(AssertionError,"admissibility"):
                audit_run(plan,run/"gateway.sqlite",decisions,run)

    def test_audit_rejects_omitted_reordered_and_duplicated_planned_events(self):
        with tempfile.TemporaryDirectory(prefix="lifecycle-event-audit-") as scratch:
            run = Path(scratch)/"run"
            plan = synthetic_plan(127,8,2,epochs=1,group_size=2)
            run_plan(run,plan,"adaptive_delta",keep_database=True)
            original = json.loads((run/"decisions.json").read_text(encoding="utf-8"))
            self.assertEqual([event["kind"] for event in original], ["refresh", "settle", "settle"])
            wrong_deadline, wrong_time, wrong_subject = [copy.deepcopy(original) for _ in range(3)]
            wrong_deadline[0]["deadline"] += 1
            wrong_time[0]["at"] += 1
            wrong_subject[0]["subject_id"] = "o:unrelated:000"
            variants = {
                "omitted_mutation": original[1:],
                "reordered_mutation": [original[1], original[0], original[2]],
                "omitted_settlement": original[:-1],
                "duplicated_settlement": original+[original[-1]],
                "wrong_deadline": wrong_deadline,
                "wrong_time": wrong_time,
                "wrong_subject": wrong_subject,
            }
            for name, decisions in variants.items():
                with self.subTest(name=name), self.assertRaisesRegex(AssertionError, "planned event"):
                    audit_run(plan,run/"gateway.sqlite",decisions,run)
            duplicated_plan = copy.deepcopy(plan)
            duplicated_plan["schedule"][0]["effects"].append(plan["schedule"][0]["effects"][0])
            with self.assertRaisesRegex(AssertionError,"exactly one settlement"):
                audit_run(duplicated_plan,run/"gateway.sqlite",original,run)

    def test_audit_checks_both_receipt_addressed_payload_bindings(self):
        with tempfile.TemporaryDirectory(prefix="lifecycle-payload-audit-") as scratch:
            run = Path(scratch)/"run"
            plan = synthetic_plan(128,8,2,epochs=1,group_size=2)
            run_plan(run,plan,"adaptive_delta",keep_database=True)
            decisions = json.loads((run/"decisions.json").read_text(encoding="utf-8"))
            effect = plan["workload"]["effects"][0]
            # Ledger has no payload_hash: follow its effect_id and nonce to the
            # two stored hashes used to authorize that exact receipt.
            for table in ("effects", "tokens"):
                db = sqlite3.connect(run/"gateway.sqlite")
                try:
                    db.execute(f"UPDATE {table} SET payload_hash=? WHERE effect_id=?", ("tampered", effect["effect_id"]))
                    db.commit()
                    with self.subTest(table=table), self.assertRaisesRegex(AssertionError, "payload hash"):
                        audit_run(plan,run/"gateway.sqlite",decisions,run)
                    db.execute(f"UPDATE {table} SET payload_hash=? WHERE effect_id=?", (digest(effect["payload"]), effect["effect_id"]))
                    db.commit()
                finally:
                    db.close()
            altered_plan = copy.deepcopy(plan)
            altered_plan["workload"]["effects"][0]["payload"]["altered"] = True
            with self.assertRaisesRegex(AssertionError,"payload hash"):
                audit_run(altered_plan,run/"gateway.sqlite",decisions,run)
            self.assertEqual(audit_run(plan,run/"gateway.sqlite",decisions,run)["status"], "passed")

    def test_history_gap_requires_acceptance_for_every_policy(self):
        real_settle = AdaptiveGateway.settle
        def wrong_receipt(gate, *args, **kwargs):
            receipt = real_settle(gate, *args, **kwargs)
            return {**receipt, "effect_id": "wrong-action"}
        for policy in POLICIES:
            with tempfile.TemporaryDirectory(prefix="lifecycle-history-audit-") as scratch:
                with patch("lifecycle_benchmark.POLICIES", [policy]), patch.object(AdaptiveGateway, "settle", wrong_receipt):
                    with self.assertRaisesRegex(AssertionError, "not accepted"):
                        history_gap_check(Path(scratch)/"run", changes=1)


if __name__ == "__main__":unittest.main()
