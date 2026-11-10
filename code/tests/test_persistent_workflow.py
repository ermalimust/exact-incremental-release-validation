"""End-to-end registered graph -> support -> durable gateway evidence."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from durable_gateway import GateRejected
from integrated_controller import Registry
from persistent_workflow import PersistentWorkflow, compile_registry

EVIDENCE = []


def registered_fixture():
    return Registry(
        artifact_parents={
            "wf0:root": (), "wf1:left": ("wf0:root",),
            "wf2:final": ("wf1:left",), "wf3:right": ("wf0:root",),
            "wf4:final": ("wf3:right",), "wf9:independent": (),
        },
        artifact_obligations={
            "wf0:root": ("origin-proof",), "wf1:left": ("left-proof",),
            "wf2:final": ("left-final-proof",), "wf3:right": ("right-proof",),
            "wf4:final": ("right-final-proof",), "wf9:independent": ("independent-proof",),
        },
        effect_artifacts={
            "release:origin": ("wf0:root",), "release:left": ("wf2:final",),
            "release:right": ("wf4:final",), "release:independent": ("wf9:independent",),
        },
        effect_obligations={"release:left": ("left-authorization",),
                            "release:right": ("right-authorization",)},
    )


class PersistentWorkflowTests(unittest.TestCase):
    affected = ("release:origin", "release:left", "release:right")

    def setUp(self):
        self.scratch = Path(__file__).resolve().parents[2] / "results" / "persistent_workflow_test_runs"
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="trial_", dir=self.scratch)
        self.path = Path(self.temp.name) / "integrated.sqlite"
        self.registry = registered_fixture()
        self.workflow = PersistentWorkflow(self.path, self.registry)
        self.workflow.create_account("payer", 100)
        self.workflow.create_account("recipient", 0)
        for artifact in self.workflow.artifacts:
            self.workflow.admit_valid_artifact(artifact, expires_at=1000.0)
        for obligation in self.workflow.obligations:
            self.workflow.admit_valid_obligation(obligation, expires_at=1000.0)
        amounts = {"release:origin": 10, "release:left": 20,
                   "release:right": 30, "release:independent": 5}
        for effect, amount in amounts.items():
            self.workflow.configure_effect(effect, "payer", "recipient", amount,
                                           {"action": "transfer", "effect": effect})
        self.tokens = {effect: self.workflow.issue(effect, now=100.0, ttl=500.0)
                       for effect in amounts}

    def tearDown(self):
        try:
            self.workflow.close()
        except sqlite3.ProgrammingError:
            pass
        self.assertEqual(self.scratch.resolve(), Path(self.temp.name).resolve().parent)
        self.temp.cleanup()

    def assert_denied(self, reason, fn, *args, **kwargs):
        with self.assertRaises(GateRejected) as error:
            fn(*args, **kwargs)
        self.assertEqual(reason, error.exception.reason)

    def exercise_revoked_root(self):
        before_cleanup = self.workflow.inspect()
        self.assertEqual(4, len(before_cleanup["stages"]))
        self.assertEqual([], before_cleanup["ledger"])
        for effect in self.affected:
            self.assert_denied("support_invalidated", self.workflow.settle,
                               effect, self.tokens[effect], now=101.0)
        blocked = self.workflow.inspect()
        self.assertEqual(before_cleanup["accounts"], blocked["accounts"])
        self.assertEqual(4, len(blocked["stages"]))
        self.workflow.settle("release:independent", self.tokens["release:independent"], now=101.0)
        independent = self.workflow.inspect()
        self.assertEqual(3, len(independent["stages"]))
        balances = {row["account_id"]: row["balance"] for row in independent["accounts"]}
        self.assertEqual({"payer": 95, "recipient": 5}, balances)
        cleaned = self.workflow.cleanup_invalidated()
        self.assertCountEqual(self.affected, cleaned["cancelled_effects"])
        self.assertEqual(3, cleaned["stage_rows_deleted"])
        self.assertEqual([], cleaned["already_committed_effects"])
        final = self.workflow.inspect()
        self.assertEqual([], final["stages"])
        self.assertEqual(1, len(final["ledger"]))
        self.assertEqual("release:independent", final["ledger"][0]["effect_id"])
        self.assertEqual(0, self.workflow.cleanup_invalidated()["stage_rows_deleted"])
        return {"state_after_root_tombstone_before_cleanup": before_cleanup,
                "state_after_three_denied_settlements": blocked,
                "state_after_independent_settlement": independent,
                "cleanup": cleaned, "final_state": final}

    def record(self, **details):
        EVIDENCE.append({"test": self._testMethodName, **details})

    def test_01_complete_transitive_support_covers_two_cross_workflow_paths(self):
        left = {"a:wf0:root", "a:wf1:left", "a:wf2:final", "o:origin-proof",
                "o:left-proof", "o:left-final-proof", "o:left-authorization"}
        right = {"a:wf0:root", "a:wf3:right", "a:wf4:final", "o:origin-proof",
                 "o:right-proof", "o:right-final-proof", "o:right-authorization"}
        self.assertEqual(left, set(self.workflow.support("release:left")))
        self.assertEqual(right, set(self.workflow.support("release:right")))
        self.assertNotIn("a:wf0:root", self.workflow.support("release:independent"))
        persisted = self.workflow.inspect()
        for effect in ("release:left", "release:right"):
            actual = {row["subject_id"] for row in persisted["effect_support"] if row["effect_id"] == effect}
            self.assertEqual(set(self.workflow.support(effect)), actual)
        self.record(cross_workflow_paths=[["wf0:root", "wf1:left", "wf2:final"],
                                         ["wf0:root", "wf3:right", "wf4:final"]], state=persisted)

    def test_02_root_invalidation_after_issue_blocks_descendants_before_cleanup(self):
        self.assertEqual(1, self.workflow.invalidate_artifact("wf0:root"))
        self.record(invalidated_subject="a:wf0:root", **self.exercise_revoked_root())

    def test_03_ancestor_obligation_invalidation_blocks_both_paths(self):
        self.assertEqual(1, self.workflow.invalidate_obligation("origin-proof"))
        self.record(invalidated_subject="o:origin-proof", **self.exercise_revoked_root())

    def test_04_close_reopen_reloads_graph_and_revalidates_old_tokens(self):
        digest = self.workflow.registry_digest
        self.workflow.close()
        self.workflow = PersistentWorkflow(self.path)
        self.assertEqual(digest, self.workflow.registry_digest)
        self.workflow.invalidate_artifact("wf0:root")
        self.workflow.close()
        self.workflow = PersistentWorkflow(self.path)
        self.record(reopen_count=2, **self.exercise_revoked_root())

    def test_05_process_exit_after_invalidation_retains_tombstone_and_cleanup(self):
        self.workflow.close()
        script = """
import os, sys
from persistent_workflow import PersistentWorkflow
workflow = PersistentWorkflow(sys.argv[1])
workflow.invalidate_obligation('origin-proof')
os._exit(92)
"""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        child = subprocess.run([sys.executable, "-c", script, str(self.path)], env=env,
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(92, child.returncode, child.stderr)
        self.workflow = PersistentWorkflow(self.path)
        self.record(real_process_exit_code=child.returncode, **self.exercise_revoked_root())

    def test_06_branch_local_invalidation_preserves_other_registered_path(self):
        self.workflow.invalidate_artifact("wf1:left")
        self.assert_denied("support_invalidated", self.workflow.settle,
                           "release:left", self.tokens["release:left"], now=101.0)
        for effect in ("release:origin", "release:right", "release:independent"):
            self.workflow.settle(effect, self.tokens[effect], now=101.0)
        cleanup = self.workflow.cleanup_invalidated()
        self.assertEqual(["release:left"], cleanup["cancelled_effects"])
        self.assertEqual(1, cleanup["stage_rows_deleted"])
        state = self.workflow.inspect()
        balances = {row["account_id"]: row["balance"] for row in state["accounts"]}
        self.assertEqual({"payer": 55, "recipient": 45}, balances)
        self.assertEqual(3, len(state["ledger"]))
        self.assertEqual([], state["stages"])
        self.record(cleanup=cleanup, final_state=state)

    def test_07_registry_mutation_and_replacement_cannot_omit_ancestor(self):
        self.registry.artifact_parents["wf2:final"] = ()
        self.assertIn("a:wf0:root", self.workflow.support("release:left"))
        self.assert_denied("registered_graph_is_immutable", PersistentWorkflow, self.path, self.registry)
        self.workflow.invalidate_artifact("wf0:root")
        self.assert_denied("support_invalidated", self.workflow.settle,
                           "release:left", self.tokens["release:left"], now=101.0)
        self.record(state=self.workflow.inspect())

    def test_08_invalid_graphs_and_missing_evidence_are_rejected(self):
        with self.assertRaises(ValueError):
            compile_registry(Registry({"a": ("b",), "b": ("a",)}, {}, {"e": ("a",)}))
        with self.assertRaises(ValueError):
            compile_registry(Registry({"a": ("missing",)}, {}, {"e": ("a",)}))
        other_path = Path(self.temp.name) / "missing_evidence.sqlite"
        with PersistentWorkflow(other_path, registered_fixture()) as other:
            other.create_account("payer", 100)
            other.create_account("recipient", 0)
            self.assert_denied("unknown_subject", other.configure_effect,
                               "release:left", "payer", "recipient", 20, {"action": "transfer"})
            state = other.inspect()
            self.assertEqual([], state["effects"])
            self.assertEqual([], state["ledger"])
        self.record(missing_evidence_state=state, rejected_invalid_graphs=["cycle", "unknown_parent"])

    def test_09_appended_support_revocation_cleans_current_affected_contracts(self):
        original = set(self.workflow.support("release:left"))
        self.assertNotIn("o:independent-proof", original)
        self.assertEqual(1, self.workflow.gateway.extend_contract(
            "release:left", ["o:independent-proof"]))
        self.tokens["release:left"] = self.workflow.issue("release:left", now=100.5, ttl=500.0)
        extended = self.workflow.inspect()
        persisted = {r["subject_id"] for r in extended["effect_support"]
                     if r["effect_id"] == "release:left"}
        self.assertEqual(original | {"o:independent-proof"}, persisted)
        self.workflow.invalidate_obligation("independent-proof")
        self.workflow.close()
        self.workflow = PersistentWorkflow(self.path)
        affected = ("release:left", "release:independent")
        for effect in affected:
            self.assert_denied("support_invalidated", self.workflow.settle,
                               effect, self.tokens[effect], now=101.0)
        before_cleanup = self.workflow.inspect()
        self.assertEqual(4, len(before_cleanup["stages"]))
        cleanup = self.workflow.cleanup_invalidated()
        self.assertCountEqual(affected, cleanup["cancelled_effects"])
        self.assertEqual(2, cleanup["stage_rows_deleted"])
        after_cleanup = self.workflow.inspect()
        self.assertEqual({"release:origin", "release:right"},
                         {s["effect_id"] for s in after_cleanup["stages"]})
        self.assertEqual([], after_cleanup["ledger"])
        for effect in ("release:origin", "release:right"):
            self.workflow.settle(effect, self.tokens[effect], now=102.0)
        final = self.workflow.inspect()
        balances = {row["account_id"]: row["balance"] for row in final["accounts"]}
        self.assertEqual({"payer": 60, "recipient": 40}, balances)
        self.assertEqual(2, len(final["ledger"]))
        self.assertEqual([], final["stages"])
        self.record(extended_contract_state=extended, state_before_cleanup=before_cleanup,
                    cleanup=cleanup, state_after_cleanup=after_cleanup, final_state=final,
                    reopened_after_invalidation=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PersistentWorkflowTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    code_dir = Path(__file__).resolve().parents[1]
    sources = [Path(__file__).resolve(), code_dir / "persistent_workflow.py", code_dir / "durable_gateway.py"]
    report = {
        "scope": "Fixed trusted Registry -> compiled complete transitive supports -> durable local SQLite ledger",
        "validation_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(), "sqlite_version": sqlite3.sqlite_version,
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "successful": result.wasSuccessful(),
        "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
        "test_evidence": EVIDENCE,
        "limitations": [
            "Registry completeness and admitted evidence truth are trusted inputs.",
            "The registered graph is fixed; dynamic graph updates are outside this bridge's scope.",
            "This is a local transactional ledger, not blockchain coupling or distributed finality.",
            "Timestamp is evaluated after write-lock acquisition, not a physical COMMIT deadline.",
            "Cleanup deletes actual staged effect payload rows; subject tombstones remain durable.",
            "Unrelated logical authority is preserved, but SQLite still physically serializes writers.",
        ],
    }
    if args.results:
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
