"""Pointwise policy equivalence and bounded-history counterexamples.

All policies receive independently constructed, identical admitted histories.
The Boolean oracle below reads declared events, never the validator's delta set.
"""
from __future__ import annotations

import random
import sys
import os
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adaptive_gateway import AdaptiveGateway, POLICIES
from durable_gateway import GateRejected


class DeltaEquivalenceTests(unittest.TestCase):
    def make_gate(self, policy="adaptive_delta", *, support_size=4,
                  expiry=1000.0, history_limit=64, delta_budget=32):
        scratch = Path(os.environ.get("WASF_TEST_TMP", Path(__file__).resolve().parents[2] / "build" / "delta_test_tmp"))
        scratch.mkdir(parents=True, exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(directory.cleanup)
        timestamp = [1.0]
        gate = AdaptiveGateway(Path(directory.name) / "gate.sqlite", policy,
                               clock=lambda: timestamp[0], history_limit=history_limit,
                               delta_budget=delta_budget)
        self.addCleanup(gate.close)
        gate.create_account("payer", 10000)
        gate.create_account("recipient", 0)
        support = [f"s{i:04d}" for i in range(support_size)]
        for sid in support + ["unrelated", "addition"]:
            gate.put_subject(sid, expiry)
        gate.create_effect("effect", "payer", "recipient", 1, support)
        gate.stage("effect", {"output_sha256": "f" * 64})
        return gate, timestamp

    def accept(self, gate, token):
        try:
            return True, gate.settle(token)
        except GateRejected as exc:
            return False, exc.reason

    def test_benign_refresh_preserves_acceptance(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                token = gate.issue("effect", ttl=100)
                clock[0] = 2
                gate.refresh("s0000", 2000)
                clock[0] = 3
                self.assertTrue(self.accept(gate, token)[0])

    def test_relevant_shortened_deadline_is_rechecked(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                token = gate.issue("effect", ttl=100)
                clock[0] = 2
                gate.refresh("s0000", 3)
                clock[0] = 4
                accepted, reason = self.accept(gate, token)
                self.assertFalse(accepted)
                self.assertEqual(reason, "support_expired")

    def test_expiry_without_mutation_is_rejected(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy, expiry=5)
                token = gate.issue("effect", ttl=100)
                clock[0] = 5
                self.assertEqual(self.accept(gate, token), (False, "support_expired"))

    def test_old_minimum_extension_uses_full_and_accepts(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                gate.refresh("s0000", 5)
                token = gate.issue("effect", ttl=100)
                clock[0] = 2
                gate.refresh("s0000", 50)
                clock[0] = 8
                self.assertTrue(self.accept(gate, token)[0])
                if policy != "full_sql":
                    self.assertIn("fallback", gate.last_metrics["validation_path"])

    def test_token_ttl_cannot_be_extended_by_refresh(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                token = gate.issue("effect", ttl=5)
                clock[0] = 2
                gate.refresh("s0000", 2000)
                clock[0] = 6
                self.assertEqual(self.accept(gate, token), (False, "token_expired"))

    def test_root_invalidation_blocks_before_cleanup(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                token = gate.issue("effect", ttl=100)
                gate.invalidate("s0000")
                clock[0] = 2
                self.assertEqual(self.accept(gate, token), (False, "support_invalidated"))
                self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM stages").fetchone()[0], 1)

    def test_pruned_relevant_invalidation_falls_back(self):
        gate, clock = self.make_gate(history_limit=2)
        token = gate.issue("effect", ttl=100)
        gate.invalidate("s0000")
        for _ in range(3):
            gate.refresh("unrelated", 2000)
        self.assertEqual(self.accept(gate, token), (False, "support_invalidated"))
        self.assertEqual(gate.last_metrics["validation_path"], "fallback_history")

    def test_missing_retained_record_falls_back(self):
        gate, _ = self.make_gate()
        token = gate.issue("effect", ttl=100)
        gate.invalidate("s0000")
        gate.refresh("unrelated", 2000)
        gate.db.execute("DELETE FROM mutation_history WHERE subject_id='s0000'")
        self.assertEqual(self.accept(gate, token), (False, "support_invalidated"))
        self.assertEqual(gate.last_metrics["validation_path"], "fallback_gap")

    def test_large_unrelated_interval_falls_back_and_accepts(self):
        gate, _ = self.make_gate(delta_budget=2)
        token = gate.issue("effect", ttl=100)
        for _ in range(3):
            gate.refresh("unrelated", 2000)
        self.assertTrue(self.accept(gate, token)[0])
        self.assertEqual(gate.last_metrics["validation_path"], "fallback_budget")

    def test_budget_is_capped_by_support_size(self):
        gate, _ = self.make_gate(support_size=2, delta_budget=256)
        token = gate.issue("effect", ttl=100)
        for _ in range(3):
            gate.refresh("unrelated", 2000)
        self.assertTrue(self.accept(gate, token)[0])
        self.assertEqual(gate.last_metrics["validation_path"], "fallback_budget")

    def test_unrelated_update_uses_exact_empty_delta(self):
        gate, _ = self.make_gate()
        token = gate.issue("effect", ttl=100)
        gate.refresh("unrelated", 2000)
        self.assertTrue(self.accept(gate, token)[0])
        self.assertEqual(gate.last_metrics["validation_path"], "delta")
        self.assertEqual(gate.last_metrics["changed_checked"], 0)

    def test_guarded_baseline_reuses_unchanged_certificate(self):
        for policy in ("guarded_full", "adaptive_delta"):
            with self.subTest(policy=policy):
                gate, _ = self.make_gate(policy)
                token = gate.issue("effect", ttl=100)
                self.assertTrue(self.accept(gate, token)[0])
                self.assertEqual(gate.last_metrics["validation_path"], "unchanged")

    def test_all_policies_reject_changed_contract(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, _ = self.make_gate(policy)
                token = gate.issue("effect", ttl=100)
                gate.extend_contract("effect", ["addition"])
                self.assertEqual(self.accept(gate, token), (False, "contract_changed"))

    def test_clock_regression_is_not_hidden_by_fast_path(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                token = gate.issue("effect", ttl=100)
                clock[0] = 0
                self.assertEqual(self.accept(gate, token), (False, "clock_regression"))

    def test_receipt_retry_after_revoke_and_ttl_is_same_effect(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                token = gate.issue("effect", ttl=5)
                receipt = gate.settle(token)
                gate.invalidate("s0000")
                clock[0] = 100
                self.assertEqual(gate.settle(token), receipt)
                self.assertEqual(gate.balance("recipient"), 1)

    def test_invalidation_is_permanent_generation(self):
        gate, _ = self.make_gate()
        gate.invalidate("s0000")
        with self.assertRaises(GateRejected):
            gate.refresh("s0000", 2000)
        with self.assertRaises(GateRejected):
            gate.put_subject("s0000", 2000)

    def test_history_floor_and_highwater_survive_reopen(self):
        gate, clock = self.make_gate(history_limit=2)
        token = gate.issue("effect", ttl=100)
        gate.invalidate("s0000")
        for _ in range(3):
            gate.refresh("unrelated", 2000)
        path = gate.path
        gate.close()
        with AdaptiveGateway(path, initialize=False, clock=lambda: clock[0]) as restarted:
            self.assertEqual(self.accept(restarted, token), (False, "support_invalidated"))
            self.assertEqual(restarted.last_metrics["validation_path"], "fallback_history")

    def test_sink_rollback_does_not_consume_certificate(self):
        gate, _ = self.make_gate()
        token = gate.issue("effect", ttl=100)
        def fail(phase):
            if phase == "after_debit":
                raise RuntimeError("injected sink fault")
        gate.fault_hook = fail
        with self.assertRaises(RuntimeError):
            gate.settle(token)
        self.assertEqual(gate.balance("payer"), 10000)
        self.assertEqual(gate.balance("recipient"), 0)
        gate.fault_hook = None
        gate.settle(token)
        self.assertEqual(gate.balance("recipient"), 1)

    def test_bounded_cleanup_preserves_unrelated_effect(self):
        gate, _ = self.make_gate()
        for i in range(5):
            eid = f"dependent{i}"
            gate.create_effect(eid, "payer", "recipient", 1, ["s0000"])
            gate.stage(eid, {"i": i})
            gate.issue(eid)
        gate.create_effect("unaffected", "payer", "recipient", 1, ["unrelated"])
        gate.stage("unaffected", {"i": "safe"})
        safe_token = gate.issue("unaffected")
        stale = gate.issue("effect")
        gate.invalidate("s0000")
        first = gate.cleanup(batch_size=2)
        self.assertTrue(first["has_more"])
        self.assertLessEqual(len(first["scanned_effects"]), 2)
        self.assertFalse(self.accept(gate, stale)[0])
        self.assertTrue(self.accept(gate, safe_token)[0])
        for _ in range(10):
            if not gate.cleanup(batch_size=2)["has_more"]:
                break
        self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM stages").fetchone()[0], 0)

    def test_extension_to_revoked_root_requeues_completed_cleanup(self):
        gate, _ = self.make_gate()
        gate.create_effect("aaa_later", "payer", "recipient", 1, ["unrelated"])
        gate.stage("aaa_later", {"later": True})
        gate.invalidate("s0000")
        self.assertFalse(gate.cleanup(batch_size=2)["has_more"])
        gate.extend_contract("aaa_later", ["s0000"])
        result = gate.cleanup(batch_size=2)
        self.assertIn("aaa_later", result["cancelled_effects"])
        self.assertIsNone(gate.db.execute("SELECT 1 FROM stages WHERE effect_id='aaa_later'").fetchone())

    def test_independent_randomized_current_predicate_equivalence(self):
        # A seed changes update identities, update count, validity, and time;
        # acceptance oracle is recomputed from those events, not implementation.
        for seed in range(12):
            rng = random.Random(70411 + seed)
            events = []
            state = {f"s{i:04d}": [True, 1000.0] for i in range(4)}
            state["unrelated"] = [True, 1000.0]
            for _ in range(rng.randrange(0, 12)):
                sid = rng.choice(list(state))
                if not state[sid][0]:
                    continue
                if rng.random() < .15:
                    events.append(("invalidate", sid, None))
                    state[sid][0] = False
                else:
                    deadline = rng.choice([10.0, 25.0, 1000.0, 2000.0])
                    events.append(("refresh", sid, deadline))
                    state[sid][1] = deadline
            settle_time = rng.choice([5.0, 10.0, 20.0, 30.0])
            expected = all(valid and settle_time < deadline
                           for sid, (valid, deadline) in state.items() if sid != "unrelated")
            outcomes = []
            for policy in POLICIES:
                with self.subTest(seed=seed, policy=policy):
                    gate, clock = self.make_gate(policy, history_limit=4, delta_budget=3)
                    token = gate.issue("effect", ttl=100)
                    clock[0] = 2
                    for kind, sid, deadline in events:
                        if kind == "invalidate":
                            gate.invalidate(sid)
                        else:
                            gate.refresh(sid, deadline)
                    clock[0] = settle_time
                    actual = self.accept(gate, token)[0]
                    outcomes.append(actual)
                    self.assertEqual(actual, expected)
            self.assertEqual(len(set(outcomes)), 1)


if __name__ == "__main__":
    unittest.main()
