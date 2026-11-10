"""Candidate/row bounds and tombstone semantics, independent of token volume.

These are functional checks with temporary databases, not timing measurements.
The SQLite authorizer forbids token-table accesses during cleanup so a hidden
scan or per-token update cannot pass merely because one wall-clock run is fast.
"""
from pathlib import Path
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adaptive_gateway import AdaptiveGateway, POLICIES
from durable_gateway import GateRejected


class CleanupWorkBoundTests(unittest.TestCase):
    def make_gate(self, policy="adaptive_delta"):
        if os.environ.get("WASF_TEST_TMP"):
            Path(os.environ["WASF_TEST_TMP"]).mkdir(parents=True, exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=os.environ.get("WASF_TEST_TMP"))
        self.addCleanup(directory.cleanup)
        clock = [1.0]
        gate = AdaptiveGateway(Path(directory.name) / "gate.sqlite", policy,
                               clock=lambda: clock[0])
        self.addCleanup(gate.close)
        gate.create_account("payer", 10000)
        gate.create_account("recipient", 0)
        gate.put_subject("root", 1000.0)
        gate.put_subject("safe", 1000.0)
        return gate, clock

    def effect(self, gate, eid, subject="root", tokens=1, payload=None):
        gate.create_effect(eid, "payer", "recipient", 1, [subject])
        gate.stage(eid, {"effect": eid} if payload is None else payload)
        return [gate.issue(eid, ttl=100) for _ in range(tokens)]

    def cleanup_without_token_access(self, gate, batch_size):
        touched = []
        def authorize(action, table, column, _database, _trigger):
            if table in {"tokens", "network_tokens", "adaptive_tokens"}:
                touched.append((action, table, column))
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        gate.db.set_authorizer(authorize)
        before = gate.db.total_changes
        try:
            result = gate.cleanup(batch_size)
        finally:
            gate.db.set_authorizer(None)
        self.assertFalse(touched)
        self.assertEqual(gate.db.total_changes - before,
                         gate.last_metrics["cleanup_logical_row_changes"])
        if batch_size is not None:
            self.assertLessEqual(len(result["scanned_effects"]), batch_size)
            self.assertLessEqual(gate.last_metrics["cleanup_logical_row_changes"], 2 * batch_size + 2)
        return result, gate.last_metrics["cleanup_logical_row_changes"]

    def test_many_outstanding_tokens_do_not_increase_cleanup_rows(self):
        for policy in POLICIES:
            for count in (1, 100):
                with self.subTest(policy=policy, tokens=count):
                    gate, _ = self.make_gate(policy)
                    nonces = self.effect(gate, "target", tokens=count)
                    gate.invalidate("root")
                    result, changes = self.cleanup_without_token_access(gate, 1)
                    self.assertEqual(result["cancelled_effects"], ["target"])
                    self.assertEqual(changes, 4)
                    self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM tokens WHERE state='issued'").fetchone()[0], count)
                    for nonce in nonces:
                        with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
                            gate.settle(nonce)
                    self.assertEqual(gate.balance("recipient"), 0)
                    self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM ledger").fetchone()[0], 0)

    def test_expired_tokens_remain_raw_and_cannot_resurrect_effect(self):
        gate, clock = self.make_gate()
        nonces = self.effect(gate, "target", tokens=100)
        clock[0] = 200
        gate.invalidate("root")
        _, changes = self.cleanup_without_token_access(gate, 1)
        self.assertEqual(changes, 4)
        snapshot = gate.inspect()
        self.assertEqual(snapshot["cleanup_token_invalidation"], "effect_tombstone")
        self.assertEqual({t["state"] for t in snapshot["tokens"]}, {"issued"})
        self.assertEqual(snapshot["effects"][0]["state"], "cancelled")
        for nonce in (nonces[0], nonces[-1]):
            with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
                gate.settle(nonce)
        with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
            gate.issue("target")
        with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
            gate.stage("target", {"new": "bytes"})

    def test_unrelated_historical_tokens_are_never_scanned(self):
        gate, _ = self.make_gate()
        historical = self.effect(gate, "historical", "safe", tokens=1000)
        prior = gate.settle(historical[0])
        token = self.effect(gate, "target")[0]
        gate.invalidate("root")
        _, changes = self.cleanup_without_token_access(gate, 1)
        self.assertEqual(changes, 4)
        self.assertEqual(gate.settle(historical[0]), prior)
        self.assertEqual(gate.balance("recipient"), 1)
        with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
            gate.settle(token)

    def test_receipt_replay_survives_shared_invalidation_and_cleanup(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                committed = self.effect(gate, "a_committed", tokens=3)
                receipt = gate.settle(committed[0])
                pending = self.effect(gate, "b_pending", tokens=3)
                safe = self.effect(gate, "safe_effect", "safe")[0]
                gate.invalidate("root")
                first, changes = self.cleanup_without_token_access(gate, 1)
                self.assertEqual(first["scanned_effects"], ["a_committed"])
                self.assertEqual(first["cancelled_effects"], [])
                self.assertEqual(changes, 2)
                self.assertTrue(first["has_more"])
                second, changes = self.cleanup_without_token_access(gate, 1)
                self.assertEqual(second["cancelled_effects"], ["b_pending"])
                self.assertEqual(changes, 4)
                self.assertFalse(second["has_more"])
                gate.settle(safe)
                clock[0] = 500
                self.assertEqual(gate.settle(committed[0]), receipt)
                for nonce in pending:
                    with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
                        gate.settle(nonce)
                self.assertEqual(gate.balance("recipient"), 2)

    def test_cleanup_tombstone_and_stage_removal_roll_back_together(self):
        gate, _ = self.make_gate()
        nonce = self.effect(gate, "target", tokens=20)[0]
        gate.invalidate("root")
        def fail(phase):
            if phase == "cleanup_before_commit":
                raise RuntimeError("cleanup interruption")
        gate.fault_hook = fail
        with self.assertRaisesRegex(RuntimeError, "cleanup interruption"):
            gate.cleanup(1)
        self.assertEqual(gate.db.execute("SELECT state FROM effects WHERE effect_id='target'").fetchone()[0], "pending")
        self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM stages").fetchone()[0], 1)
        self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM cleanup_queue").fetchone()[0], 1)
        self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM audit WHERE kind='cleanup'").fetchone()[0], 0)
        with self.assertRaisesRegex(GateRejected, "support_invalidated"):
            gate.settle(nonce)
        gate.fault_hook = None
        self.cleanup_without_token_access(gate, 1)
        with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
            gate.settle(nonce)

    def test_tombstone_and_raw_tokens_survive_reopen(self):
        gate, clock = self.make_gate()
        nonces = self.effect(gate, "target", tokens=100)
        gate.invalidate("root")
        self.cleanup_without_token_access(gate, 1)
        path = gate.path
        gate.close()
        with AdaptiveGateway(path, initialize=False, clock=lambda: clock[0]) as reopened:
            for nonce in (nonces[0], nonces[-1]):
                with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
                    reopened.settle(nonce)
            self.assertEqual(reopened.db.execute("SELECT COUNT(*) FROM tokens WHERE state='issued'").fetchone()[0], 100)

    def test_existing_multi_nonce_database_needs_no_schema_migration(self):
        gate, clock = self.make_gate()
        nonces = self.effect(gate, "target", tokens=100)
        schema = list(gate.db.execute("SELECT name,sql FROM sqlite_master ORDER BY name"))
        path = gate.path
        gate.close()
        # Reopening without schema initialization consumes the existing token
        # representation; the fix does not require a per-token migration.
        with AdaptiveGateway(path, initialize=False, clock=lambda: clock[0]) as reopened:
            reopened.invalidate("root")
            _, changes = self.cleanup_without_token_access(reopened, 1)
            self.assertEqual(changes, 4)
            self.assertEqual([tuple(row) for row in reopened.db.execute("SELECT name,sql FROM sqlite_master ORDER BY name")],
                             [tuple(row) for row in schema])
            for nonce in (nonces[0], nonces[-1]):
                with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
                    reopened.settle(nonce)

    def test_candidate_access_and_row_count_bound_with_large_payloads(self):
        gate, _ = self.make_gate()
        for i in range(7):
            self.effect(gate, f"target{i}", tokens=3, payload={"bytes": "x" * 8192})
        gate.invalidate("root")
        visited = []
        counts = []
        while True:
            result, changes = self.cleanup_without_token_access(gate, 3)
            visited.extend(result["scanned_effects"])
            counts.append(changes)
            if not result["has_more"]:
                break
        self.assertEqual(len(visited), 7)
        self.assertEqual(len(set(visited)), 7)
        self.assertEqual(counts, [8, 8, 4])
        plan = " ".join(str(tuple(row)) for row in gate.db.execute(
            "EXPLAIN QUERY PLAN SELECT effect_id FROM effect_support "
            "WHERE subject_id=? AND effect_id>? ORDER BY effect_id LIMIT ?",
            ("root", "", 4)))
        self.assertIn("SEARCH", plan)
        self.assertIn("support_by_subject", plan)
        self.assertNotIn("SCAN", plan)


if __name__ == "__main__":
    unittest.main()
