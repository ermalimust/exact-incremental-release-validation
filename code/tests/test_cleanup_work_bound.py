"""Candidate/row bounds and tombstone semantics, independent of token volume.

These are functional checks with temporary databases, not timing measurements.
The SQLite authorizer forbids token-table accesses during cleanup so a hidden
scan or per-token update cannot pass merely because one wall-clock run is fast.
"""
from pathlib import Path
from contextlib import closing
import copy
import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from adaptive_gateway import AdaptiveGateway, POLICIES, bootstrap as adaptive_bootstrap
from durable_gateway import DurableGateway, GateRejected
from integrated_controller import Registry
from lifecycle_benchmark import compile_plan, register, synthetic_plan
from network_gateway import NetworkGateway, bootstrap as network_bootstrap
from persistent_workflow import compile_registry


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


class EffectIdentityDomainTests(unittest.TestCase):
    """Registration rejects the cleanup sentinel; legacy rows are not renamed."""

    # Reuse fixture helpers without inheriting the original test methods again.
    make_gate = CleanupWorkBoundTests.make_gate
    effect = CleanupWorkBoundTests.effect
    cleanup_without_token_access = CleanupWorkBoundTests.cleanup_without_token_access

    def test_direct_registration_rejects_empty_and_nonstring_ids_atomically(self):
        factories = [DurableGateway] + [
            lambda path, policy=policy: AdaptiveGateway(path, policy)
            for policy in POLICIES]
        for make in factories:
            with make(":memory:") as gate:
                gate.create_account("payer", 10)
                gate.create_account("recipient", 0)
                gate.put_subject("root", 1000.0)
                for bad_id in ("", None, 0, False, b"", b"effect"):
                    with self.subTest(factory=make, effect_id=repr(bad_id)):
                        with self.assertRaisesRegex(ValueError, "non-empty string"):
                            gate.create_effect(bad_id, "payer", "recipient", 1, ["root"])
                        self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0], 0)
                        self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM effect_support").fetchone()[0], 0)

    def test_registry_rejects_invalid_ids_in_both_effect_maps(self):
        for field in ("effect_artifacts", "effect_obligations"):
            for bad_id in ("", None, 0, False, b"effect"):
                with self.subTest(field=field, effect_id=repr(bad_id)):
                    registry = Registry({"root": ()}, {}, {"valid": ("root",)}, {})
                    getattr(registry, field)[bad_id] = ("root",) if field == "effect_artifacts" else ()
                    with self.assertRaisesRegex(ValueError, "non-empty string"):
                        compile_registry(registry)

    def test_bootstrap_rejects_bad_effect_list_before_database_creation(self):
        base = synthetic_plan(101, 4, 1, epochs=1, group_size=2)["workload"]
        modes = [(adaptive_bootstrap, policy) for policy in POLICIES]
        modes.append((network_bootstrap, "support_epoch"))
        with tempfile.TemporaryDirectory() as directory:
            for index, (bootstrap, policy) in enumerate(modes):
                for bad_index, bad_id in enumerate(("", None, 0, False, b"effect")):
                    with self.subTest(policy=policy, effect_id=repr(bad_id)):
                        workload = copy.deepcopy(base)
                        # Valid registry, then a bad *second* workload entry:
                        # no earlier account/effect may be partially persisted.
                        workload["effects"][1]["effect_id"] = bad_id
                        path = Path(directory) / f"{index}-{bad_index}.sqlite"
                        with self.assertRaisesRegex(ValueError, "non-empty string"):
                            bootstrap(path, workload, policy)
                        self.assertFalse(path.exists())

    def test_lifecycle_bulk_registration_rejects_bad_id_without_partial_rows(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                plan = synthetic_plan(102, 4, 1, epochs=1, group_size=2)
                declaration, supports = compile_plan(plan)
                plan["workload"]["effects"][1]["effect_id"] = ""
                with AdaptiveGateway(":memory:", policy, clock=lambda: 1.0) as gate:
                    with self.assertRaisesRegex(ValueError, "non-empty string"):
                        register(gate, plan, declaration, supports)
                    for table in ("accounts", "subjects", "effects", "effect_support", "stages", "tokens", "audit"):
                        self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0], 0)
                    self.assertIsNone(gate.db.execute("SELECT workload FROM network_meta").fetchone()[0])

    def test_legacy_empty_effect_database_is_rejected_without_rewriting_state(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                gate, clock = self.make_gate(policy)
                # Reproduce rows admitted by the old API using its unchanged
                # schema; current registration intentionally cannot create them.
                gate.db.execute("INSERT INTO effects VALUES ('',0,'payer','recipient',1,NULL,'pending')")
                gate.db.execute("INSERT INTO effect_support VALUES ('','root')")
                gate.stage("", {"legacy": "payload"})
                gate.issue("", ttl=100)
                gate.invalidate("root")
                before = gate.inspect()
                schema_before = [tuple(r) for r in gate.db.execute("SELECT name,sql FROM sqlite_master ORDER BY name")]
                path = gate.path
                gate.close()
                for initialize in (True, False):
                    with self.assertRaisesRegex(GateRejected, "invalid_persisted_effect_id"):
                        AdaptiveGateway(path, policy, initialize=initialize, clock=lambda: clock[0])
                with self.assertRaisesRegex(GateRejected, "invalid_persisted_effect_id"):
                    DurableGateway(path)
                with self.assertRaisesRegex(GateRejected, "invalid_persisted_effect_id"):
                    NetworkGateway(path, "full_recheck")
                with closing(sqlite3.connect(path)) as raw:
                    raw.row_factory = sqlite3.Row
                    for table in ("effects", "stages", "tokens", "ledger", "cleanup_queue", "effect_support"):
                        self.assertEqual([dict(r) for r in raw.execute("SELECT * FROM " + table)], before[table])
                    self.assertEqual([tuple(r) for r in raw.execute("SELECT name,sql FROM sqlite_master ORDER BY name")], schema_before)

    def test_legacy_null_effect_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-null.sqlite"
            with DurableGateway(path) as gate:
                gate.create_account("payer", 10)
                gate.create_account("recipient", 0)
                gate.db.execute("INSERT INTO effects VALUES (NULL,0,'payer','recipient',1,NULL,'pending')")
            with self.assertRaisesRegex(GateRejected, "invalid_persisted_effect_id"):
                DurableGateway(path)
            with closing(sqlite3.connect(path)) as raw:
                self.assertEqual(raw.execute("SELECT COUNT(*) FROM effects WHERE effect_id IS NULL").fetchone()[0], 1)

    def test_nonempty_identifiers_are_not_trimmed_or_skipped_by_pagination(self):
        identifiers = [" ", "-1", "0", "a", "normal:0001", "中文"]
        for policy in POLICIES:
            with self.subTest(policy=policy):
                declaration, supports = compile_registry(Registry(
                    {"root": ()}, {}, {eid: ("root",) for eid in identifiers}, {}))
                self.assertEqual(set(supports), set(identifiers))
                gate, _ = self.make_gate(policy)
                nonces = {eid: self.effect(gate, eid, tokens=2) for eid in identifiers}
                gate.invalidate("root")
                visited = []
                while True:
                    result, _ = self.cleanup_without_token_access(gate, 2)
                    visited.extend(result["scanned_effects"])
                    if not result["has_more"]:
                        break
                self.assertEqual(visited, sorted(identifiers))
                self.assertEqual(gate.db.execute("SELECT COUNT(*) FROM stages").fetchone()[0], 0)
                for tokens in nonces.values():
                    for nonce in tokens:
                        with self.assertRaisesRegex(GateRejected, "effect_cancelled"):
                            gate.settle(nonce)

    def test_legacy_identity_probes_use_primary_key_without_effect_scan(self):
        gate, _ = self.make_gate()
        statements = []
        gate.db.set_trace_callback(statements.append)
        try:
            gate._reject_legacy_empty_effect_ids()
        finally:
            gate.db.set_trace_callback(None)
        self.assertEqual(len(statements), 2)
        for statement in statements:
            plan = " ".join(str(tuple(r)) for r in gate.db.execute(
                "EXPLAIN QUERY PLAN " + statement))
            self.assertIn("SEARCH", plan)
            self.assertIn("sqlite_autoindex_effects_1", plan)
            self.assertNotIn("SCAN", plan)


if __name__ == "__main__":
    unittest.main()
