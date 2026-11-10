"""Hand-written oracle cases and metamorphic checks of the shared-trace suite."""
import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from experiment_suite import (ArtifactDeclaration as A, EffectDeclaration as E,
    InputEvent as V, EventTrace, PrefixOracle, generate_event_trace, replay,
    SAFE_POLICIES, make_registry)


def hand_trace(events):
    return EventTrace(7, "manual", (A("root", 0, (), ("source",)),
        A("child", 1, ("root",), ("local",)), A("unrelated", 2, (), ())),
        (E("effect", 1, ("child",), ()),), tuple(events))


BASE = (V(1, 0, "resolve", "source", "valid"),
        V(1, 1, "resolve", "local", "valid"),
        V(2, 2, "readiness", "effect", "ready"))


class OracleTests(unittest.TestCase):
    def test_cross_workflow_ancestor_invalidation_is_unsafe_before_cleanup(self):
        trace = hand_trace(BASE + (V(3, 3, "issue", "effect"),
            V(4, 4, "invalidate", "root"), V(5, 5, "settle", "effect")))
        verdict = PrefixOracle(trace).evaluate("effect", 5)
        self.assertFalse(verdict.safe)
        self.assertEqual(verdict.reasons, ("invalid_artifact",))
        self.assertEqual(verdict.support_artifacts, ("child", "root"))
        self.assertEqual(verdict.support_obligations, ("local", "source"))

    def test_future_revocation_is_not_backdated(self):
        trace = hand_trace(BASE + (V(3, 3, "settle", "effect"),
            V(4, 4, "invalidate", "root"), V(5, 5, "settle", "effect")))
        oracle = PrefixOracle(trace)
        self.assertTrue(oracle.evaluate("effect", 3).safe)
        self.assertFalse(oracle.evaluate("effect", 5).safe)

    def test_local_valid_does_not_hide_unresolved_parent(self):
        trace = hand_trace((BASE[1], BASE[2], V(3, 3, "settle", "effect")))
        verdict = PrefixOracle(trace).evaluate("effect", 2)
        self.assertEqual(verdict.reasons, ("unresolved_obligation",))

    def test_expiry_is_checked_at_exact_boundary(self):
        trace = hand_trace((V(1, 0, "resolve", "source", "valid", 4), BASE[1], BASE[2], V(4, 4, "settle", "effect")))
        self.assertEqual(PrefixOracle(trace).evaluate("effect", 3).reasons, ("expired_evidence",))

    def test_readiness_retraction(self):
        trace = hand_trace(BASE + (V(3, 3, "readiness", "effect", "not_ready"), V(4, 4, "settle", "effect")))
        self.assertEqual(PrefixOracle(trace).evaluate("effect", 4).reasons, ("not_ready",))

    def test_unrelated_invalidation_does_not_change_truth(self):
        trace = hand_trace(BASE + (V(3, 3, "invalidate", "unrelated"), V(4, 4, "settle", "effect")))
        self.assertTrue(PrefixOracle(trace).evaluate("effect", 4).safe)
        self.assertEqual(PrefixOracle(trace).contaminated_artifacts(4), {"unrelated"})

    def test_invalid_evidence_identity_cannot_resurrect(self):
        trace = hand_trace(BASE + (V(3, 3, "resolve", "source", "invalid"), V(4, 4, "resolve", "source", "valid"), V(5, 5, "settle", "effect")))
        with self.assertRaises(ValueError):
            PrefixOracle(trace).evaluate("effect", 5)
        with self.assertRaises(ValueError):
            PrefixOracle(trace).settlement_truth()

    def test_benign_relevant_refresh_shows_version_conservatism(self):
        trace = hand_trace(BASE + (V(3, 3, "issue", "effect"), V(4, 4, "resolve", "source", "valid"), V(5, 5, "settle", "effect")))
        truth = PrefixOracle(trace).settlement_truth()
        strong, _, _ = replay(trace, "full_recheck", truth)
        versions, outcomes, _ = replay(trace, "support_epoch", truth)
        self.assertEqual(strong["accepted"], 1)
        self.assertEqual(versions["accepted"], 0)
        self.assertTrue(outcomes[0]["oracle_safe"])
        self.assertEqual(versions["safe_stale_support_rejections"], 1)

    def test_cleanup_truth_is_independent_fixed_point(self):
        trace = hand_trace(BASE + (V(3, 3, "invalidate", "root"), V(4, 4, "rollback")))
        self.assertEqual(PrefixOracle(trace).contaminated_artifacts(4), {"root", "child"})

    def test_streaming_matches_reconstructing_every_prefix(self):
        trace = generate_event_trace(20261027, "dense", 24)
        oracle = PrefixOracle(trace)
        for index, verdict in oracle.settlement_truth().items():
            self.assertEqual(verdict, oracle.evaluate(trace.events[index].subject, index))

    def test_trace_is_immutable_deterministic_and_hash_binds_graph(self):
        trace = generate_event_trace(20261027, "sparse", 24)
        self.assertEqual(trace.digest(), generate_event_trace(20261027, "sparse", 24).digest())
        changed = dataclasses.replace(trace, effects=trace.effects[:-1])
        self.assertNotEqual(trace.digest(), changed.digest())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            trace.seed = 0

    def test_safe_policies_and_unsafe_ablation_on_same_race(self):
        trace = hand_trace(BASE + (V(3, 3, "issue", "effect"), V(4, 4, "invalidate", "root"), V(5, 5, "settle", "effect"), V(6, 6, "rollback")))
        truth = PrefixOracle(trace).settlement_truth()
        for policy in SAFE_POLICIES:
            result, outcomes, _ = replay(trace, policy, truth)
            self.assertEqual(result["false_accepts"], 0)
            self.assertFalse(outcomes[0]["accepted"])
            self.assertEqual(result["rollback_residual_sum"], 0)
        result, _, _ = replay(trace, "no_revalidate", truth)
        self.assertEqual(result["false_accepts"], 1)

    def test_unrelated_revocation_rejects_only_global_epoch(self):
        trace = hand_trace(BASE + (V(3, 3, "issue", "effect"), V(4, 4, "invalidate", "unrelated"), V(5, 5, "settle", "effect")))
        truth = PrefixOracle(trace).settlement_truth()
        for policy in ("support_epoch", "full_recheck"):
            summary, _, _ = replay(trace, policy, truth)
            self.assertEqual(summary["accepted"], 1)
        summary, outcomes, _ = replay(trace, "global_epoch", truth)
        self.assertEqual(summary["accepted"], 0)
        self.assertEqual(outcomes[0]["controller_reason"], "stale_global")

    def test_no_expiry_ablation_is_actually_exercised(self):
        trace = hand_trace((V(1, 0, "resolve", "source", "valid", 4), BASE[1], BASE[2], V(3, 3, "issue", "effect"), V(5, 5, "settle", "effect")))
        truth = PrefixOracle(trace).settlement_truth()
        safe, _, _ = replay(trace, "support_epoch", truth)
        unsafe, _, _ = replay(trace, "no_expiry", truth)
        self.assertEqual(safe["false_accepts"], 0)
        self.assertEqual(unsafe["false_accepts"], 1)

    def test_all_valid_negative_control(self):
        trace = generate_event_trace(20261027, "all_valid", 24)
        truth = PrefixOracle(trace).settlement_truth()
        self.assertTrue(all(verdict.safe for verdict in truth.values()))
        for policy in SAFE_POLICIES:
            summary, _, _ = replay(trace, policy, truth)
            self.assertEqual(summary["safe_coverage"], 1)
            self.assertEqual(summary["false_accepts"], 0)

    def test_dense_workload_retains_uncontaminated_population(self):
        trace = generate_event_trace(20261027, "dense", 120)
        truth = PrefixOracle(trace).settlement_truth()
        finals = [v for i, v in truth.items() if trace.events[i].attempt == 1]
        fraction = sum(v.safe for v in finals) / len(finals)
        self.assertGreaterEqual(fraction, .4)
        self.assertLess(fraction, .9)


if __name__ == "__main__":
    unittest.main()
