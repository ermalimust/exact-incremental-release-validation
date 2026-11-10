import dataclasses
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from integrated_controller import IntegratedController, Registry, registry_from_legacy_trace
from unified_replay import generate_trace


def registry():
    return Registry(
        {"source": (), "middle": ("source",), "leaf": ("middle",), "independent": ()},
        {"source": ("q",), "leaf": ("local",), "independent": ("other",)},
        {"dependent": ("leaf",), "independent_effect": ("independent",)})


def initialized(policy="support_epoch"):
    c = IntegratedController(registry(), policy)
    for oid in ("q", "local", "other"):
        c.resolve(oid)
    c.set_ready("dependent")
    c.set_ready("independent_effect")
    return c


class IntegratedSafetyTests(unittest.TestCase):
    def test_root_revocation_blocks_before_cleanup(self):
        for policy in ("support_epoch", "full_recheck", "global_epoch"):
            with self.subTest(policy=policy):
                c = initialized(policy)
                token = c.issue("dependent", 1.0)
                c.invalidate("source")
                self.assertIn("leaf", c.staged_artifacts())
                self.assertFalse(c.settle("dependent", token, 2.0)[0])
                self.assertEqual(c.settlements, [])
                self.assertEqual(c.rollback_pending(), {"source", "middle", "leaf"})
                self.assertEqual(c.staged_artifacts(), {"independent"})

    def test_unrelated_revocation_does_not_stale_support_token(self):
        for policy, expected in (("support_epoch", True), ("full_recheck", True),
                                 ("global_epoch", False)):
            with self.subTest(policy=policy):
                c = initialized(policy)
                token = c.issue("independent_effect", 1)
                c.invalidate("source")
                result = c.settle("independent_effect", token, 2)
                self.assertEqual(result[0], expected)
                if not expected:
                    self.assertEqual(result[1], "stale_global")
                    self.assertTrue(c.settle("independent_effect",
                        c.issue("independent_effect", 2), 2)[0])

    def test_unsafe_ablations_have_actual_counterexamples(self):
        for policy in ("own_only", "no_revalidate"):
            c = initialized(policy)
            token = c.issue("dependent", 1)
            c.invalidate("source")
            self.assertTrue(c.settle("dependent", token, 2)[0])

    def test_expiry_checked_at_settlement_including_equality(self):
        for policy in ("support_epoch", "global_epoch", "full_recheck"):
            c = initialized(policy)
            c.resolve("q", valid_until=2)
            token = c.issue("dependent", 1)
            self.assertEqual(c.settle("dependent", token, 2), (False, "expired_evidence"))
        c = initialized("no_expiry")
        c.resolve("q", valid_until=2)
        self.assertTrue(c.settle("dependent", c.issue("dependent", 1), 2)[0])

    def test_conservative_extension_revokes_old_record(self):
        c = initialized()
        token = c.issue("dependent", 1)
        c.extend("dependent", ("extra",))
        self.assertEqual(c.settle("dependent", token, 2), (False, "stale_contract"))
        self.assertIsNone(c.issue("dependent", 2))
        c.resolve("extra")
        self.assertTrue(c.settle("dependent", c.issue("dependent", 3), 3)[0])

    def test_record_replay_and_forgery(self):
        c = initialized()
        token = c.issue("dependent", 1)
        forged = dataclasses.replace(token, valid_until=9)
        self.assertEqual(c.settle("dependent", forged, 2), (False, "unknown_token"))
        self.assertEqual(c.settle("independent_effect", token, 2), (False, "wrong_effect"))
        self.assertTrue(c.settle("dependent", token, 2)[0])
        self.assertEqual(c.settle("dependent", token, 3), (False, "replay"))

    def test_invalid_evidence_cannot_resurrect_derived_artifact(self):
        c = initialized()
        c.resolve("q", "invalid")
        with self.assertRaises(ValueError):
            c.resolve("q", "valid")
        self.assertIsNone(c.issue("dependent", 2))
        self.assertIn("source", c.rollback_pending())

    def test_later_revocation_does_not_undo_prior_settlement(self):
        c = initialized()
        self.assertTrue(c.settle("dependent", c.issue("dependent", 1), 1)[0])
        c.invalidate("source")
        c.rollback_pending()
        self.assertEqual(c.status("dependent"), "settled")
        self.assertEqual(len(c.settlements), 1)

    def test_caller_cannot_mutate_registered_graph(self):
        r = registry()
        c = IntegratedController(r)
        r.artifact_parents["leaf"] = ()
        self.assertIn("a:source", c._base_support["dependent"])

    def test_cycles_and_unknown_dependencies_rejected(self):
        with self.assertRaises(ValueError):
            IntegratedController(Registry({"a": ("b",), "b": ("a",)}, {}, {"e": ("a",)}))
        with self.assertRaises(ValueError):
            IntegratedController(Registry({"a": ("missing",)}, {}, {"e": ("a",)}))

    def test_regression_original_seed_blocks_previously_released_effect(self):
        trace = generate_trace(20260700)
        c = IntegratedController(registry_from_legacy_trace(trace))
        # Feed observed evidence only; no future validity enters the controller.
        events = [(o.terminal_time, 0, "resolve", o) for o in trace.obligations]
        events += [(f.reveal_time, 1, "invalidate", f) for f in trace.failures]
        events += [(e.readiness_time, 2, "ready", e) for e in trace.effects]
        for time, _, kind, obj in sorted(events, key=lambda row: (row[0], row[1])):
            if time > 5.784095:
                break
            if kind == "resolve":
                c.resolve(obj.obligation_id, "valid" if obj.valid else "invalid")
            elif kind == "invalidate":
                c.invalidate(obj.root_artifact)
            else:
                c.set_ready(obj.effect_id)
        self.assertIn("wf1:s5", c.staged_artifacts())  # cleanup has not run
        self.assertIsNone(c.issue("effect:wf1", 5.784095))
        self.assertIn("wf1:s5", c.rollback_pending())

    def test_parallel_duplicate_settlement_consumes_exactly_once(self):
        c = initialized()
        token = c.issue("dependent", 1)
        barrier = threading.Barrier(8)
        results = []
        def worker():
            barrier.wait()
            results.append(c.settle("dependent", token, 2)[0])
        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(c.settlements), 1)

    def test_revoke_settle_race_has_consistent_linearization(self):
        for _ in range(30):
            c = initialized()
            token = c.issue("dependent", 1)
            barrier = threading.Barrier(2)
            def revoke():
                barrier.wait()
                c.invalidate("source")
            def settle():
                barrier.wait()
                c.settle("dependent", token, 2)
            ts = [threading.Thread(target=revoke), threading.Thread(target=settle)]
            for t in ts: t.start()
            for t in ts: t.join(timeout=5)
            self.assertFalse(any(t.is_alive() for t in ts))
            relevant = [r["event"] for r in c.audit
                        if r["event"] in {"invalidate", "settle"}]
            if c.settlements:
                self.assertEqual(relevant, ["settle", "invalidate"])


if __name__ == "__main__":
    unittest.main()

