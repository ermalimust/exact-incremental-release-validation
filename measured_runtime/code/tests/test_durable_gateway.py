#!/usr/bin/env python3
"""Executable local-gateway validation; no chain or network is contacted."""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
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
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from durable_gateway import DurableGateway, GateRejected


EVIDENCE: list[dict] = []


class DurableGatewayTests(unittest.TestCase):
    def setUp(self):
        self.scratch_root = Path(__file__).resolve().parents[2] / "results" / "gateway_test_runs"
        self.scratch_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="trial_", dir=self.scratch_root)
        self.path = Path(self.temp.name) / "gateway.sqlite"
        self.gate = DurableGateway(self.path)
        self.gate.create_account("payer", 100)
        self.gate.create_account("recipient", 0)
        self.gate.put_subject("root:a:g0", 200.0)
        self.gate.put_subject("root:b:g0", 200.0)
        self.gate.create_effect("effect:a", "payer", "recipient", 30, ["root:a:g0"])
        self.gate.stage("effect:a", {"operation": "transfer", "invoice": "a"})

    def tearDown(self):
        try:
            self.gate.close()
        except sqlite3.ProgrammingError:
            pass
        resolved = Path(self.temp.name).resolve()
        self.assertEqual(self.scratch_root.resolve(), resolved.parent)
        self.temp.cleanup()

    def issue(self, **kwargs):
        return self.gate.issue("effect:a", now=100.0, ttl=90.0, **kwargs)

    def denied(self, reason, fn, *args, **kwargs):
        with self.assertRaises(GateRejected) as error:
            fn(*args, **kwargs)
        self.assertEqual(reason, error.exception.reason)

    def assert_funds(self, payer, recipient, ledger_count):
        state = self.gate.inspect()
        actual = {row["account_id"]: row["balance"] for row in state["accounts"]}
        self.assertEqual({"payer": payer, "recipient": recipient}, actual)
        self.assertEqual(100, sum(actual.values()))
        self.assertEqual(ledger_count, len(state["ledger"]))
        return state

    def record(self, *, state=None, **details):
        EVIDENCE.append({"test": self._testMethodName, "state": state or self.gate.inspect(), **details})

    def test_01_success_atomic_transfer_and_stage_removal(self):
        receipt = self.gate.settle(self.issue(), now=101.0)
        state = self.assert_funds(70, 30, 1)
        self.assertEqual([], state["stages"])
        self.assertEqual("settled", state["effects"][0]["state"])
        self.assertEqual("consumed", state["tokens"][0]["state"])
        self.assertEqual(receipt, state["ledger"][0])
        self.record(state=state)

    def test_02_late_invalidation_blocks_without_cleanup(self):
        token = self.issue()
        self.assertEqual(1, self.gate.invalidate("root:a:g0"))
        self.denied("support_invalidated", self.gate.settle, token, now=101.0)
        state = self.assert_funds(100, 0, 0)
        self.assertEqual(1, len(state["stages"]))
        self.record(state=state, denial="support_invalidated", cleanup_completed=False)

    def test_03_expired_evidence_rejected_at_boundary(self):
        token = self.issue()
        self.denied("support_expired", self.gate.settle, token, now=200.0)
        self.record(state=self.assert_funds(100, 0, 0), denial="support_expired")

    def test_04_token_expiry_before_evidence_expiry(self):
        token = self.gate.issue("effect:a", now=100.0, ttl=2.0)
        self.denied("token_expired", self.gate.settle, token, now=102.0)
        self.record(state=self.assert_funds(100, 0, 0), denial="token_expired")

    def test_05_contract_extension_invalidates_old_token(self):
        old = self.issue()
        self.assertEqual(1, self.gate.extend_contract("effect:a", ["root:b:g0"]))
        self.denied("contract_changed", self.gate.settle, old, now=101.0)
        fresh = self.gate.issue("effect:a", now=102.0)
        self.gate.settle(fresh, now=103.0)
        self.record(state=self.assert_funds(70, 30, 1), old_token_denial="contract_changed")

    def test_06_unrelated_invalidation_preserves_authority(self):
        token = self.issue()
        self.gate.invalidate("root:b:g0")
        self.gate.settle(token, now=101.0)
        self.record(state=self.assert_funds(70, 30, 1))

    def test_07_duplicate_retry_and_other_token_cannot_double_spend(self):
        token = self.issue()
        other_token = self.gate.issue("effect:a", now=100.5)
        receipt = self.gate.settle(token, now=101.0)
        self.gate.invalidate("root:a:g0")
        replay = self.gate.settle(token, now=500.0)
        self.assertEqual(receipt, replay)
        self.denied("effect_settled", self.gate.settle, other_token, now=102.0)
        self.denied("token_effect_mismatch", self.gate.settle, token,
                    expected_effect_id="different-effect", now=102.0)
        self.denied("unknown_token", self.gate.settle, "forged-token", now=102.0)
        self.record(state=self.assert_funds(70, 30, 1), exact_retry_receipt_equal=True,
                    other_token_denial="effect_settled", copied_token_denial="token_effect_mismatch")

    def test_08_cleanup_physically_deletes_stage_and_is_idempotent(self):
        token = self.issue()
        self.gate.invalidate("root:a:g0")
        before = len(self.gate.inspect()["stages"])
        deleted = self.gate.cleanup("effect:a")
        self.assertEqual(1, before)
        self.assertEqual(1, deleted)
        self.assertEqual(0, self.gate.cleanup("effect:a"))
        state = self.assert_funds(100, 0, 0)
        self.assertEqual([], state["stages"])
        self.denied("token_revoked", self.gate.settle, token, now=101.0)
        self.record(state=state, actual_stages_before=before, sql_delete_rowcount=deleted,
                    actual_stages_after=len(state["stages"]))

    def test_09_tombstone_and_payload_cannot_be_resurrected(self):
        self.gate.invalidate("root:a:g0")
        self.denied("invalidated_subject_tombstone", self.gate.put_subject, "root:a:g0", 300.0)
        self.denied("payload_is_immutable", self.gate.stage, "effect:a", {"invoice": "modified"})
        self.denied("subject_generation_is_immutable", self.gate.put_subject, "root:b:g0", 300.0)
        self.record(state=self.assert_funds(100, 0, 0))

    def test_10_close_reopen_before_commit_preserves_authority(self):
        token = self.issue()
        self.gate.close()
        self.gate = DurableGateway(self.path)
        self.gate.settle(token, now=101.0)
        self.record(state=self.assert_funds(70, 30, 1))

    def test_11_close_reopen_after_commit_retries_same_receipt(self):
        token = self.issue()
        receipt = self.gate.settle(token, now=101.0)
        self.gate.close()
        self.gate = DurableGateway(self.path)
        self.assertEqual(receipt, self.gate.settle(token, now=102.0))
        self.record(state=self.assert_funds(70, 30, 1), exact_retry_receipt_equal=True)

    def crash_process(self, phase):
        token = self.issue()
        self.gate.close()
        program = """
import os, sys
from durable_gateway import DurableGateway
def crash(phase):
    if phase == sys.argv[3]:
        os._exit(91)
with DurableGateway(sys.argv[1], fault_hook=crash) as gate:
    gate.settle(sys.argv[2], now=101.0)
"""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        child = subprocess.run([sys.executable, "-c", program, str(self.path), token, phase],
                               env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(91, child.returncode, child.stderr)
        self.gate = DurableGateway(self.path)
        return token, child.returncode

    def test_12_process_death_after_debit_rolls_back(self):
        token, exit_code = self.crash_process("after_debit")
        recovered = self.assert_funds(100, 0, 0)
        self.assertEqual("issued", recovered["tokens"][0]["state"])
        self.assertEqual(1, len(recovered["stages"]))
        self.gate.settle(token, now=102.0)
        self.record(state=self.assert_funds(70, 30, 1), recovered_before_retry=recovered,
                    injected_process_exit_code=exit_code, crash_phase="after_debit")

    def test_13_process_death_before_commit_rolls_back_all_rows(self):
        token, exit_code = self.crash_process("before_commit")
        recovered = self.assert_funds(100, 0, 0)
        self.assertEqual("pending", recovered["effects"][0]["state"])
        self.assertEqual("issued", recovered["tokens"][0]["state"])
        self.assertEqual(1, len(recovered["stages"]))
        self.gate.settle(token, now=102.0)
        self.record(state=self.assert_funds(70, 30, 1), recovered_before_retry=recovered,
                    injected_process_exit_code=exit_code, crash_phase="before_commit")

    def test_14_process_death_after_commit_preserves_exactly_one_transfer(self):
        token, exit_code = self.crash_process("after_commit")
        recovered = self.assert_funds(70, 30, 1)
        self.assertEqual([], recovered["stages"])
        self.assertEqual(recovered["ledger"][0], self.gate.settle(token, now=102.0))
        self.record(state=self.assert_funds(70, 30, 1), recovered_before_retry=recovered,
                    injected_process_exit_code=exit_code, crash_phase="after_commit")

    def test_15_insufficient_funds_cannot_partially_commit(self):
        self.gate.create_effect("effect:b", "payer", "recipient", 110, ["root:b:g0"])
        self.gate.stage("effect:b", {"invoice": "b"})
        token = self.gate.issue("effect:b", now=100.0)
        self.denied("insufficient_funds", self.gate.settle, token, now=101.0)
        self.record(state=self.assert_funds(100, 0, 0), denial="insufficient_funds")

    def test_16_concurrent_settlers_cannot_double_spend(self):
        tokens = []
        for suffix in ("b", "c"):
            eid = f"effect:{suffix}"
            self.gate.create_effect(eid, "payer", "recipient", 70, ["root:b:g0"])
            self.gate.stage(eid, {"invoice": suffix})
            tokens.append(self.gate.issue(eid, now=100.0))
        barrier = threading.Barrier(2)

        def run(token):
            with DurableGateway(self.path) as gate:
                barrier.wait(timeout=10)
                try:
                    gate.settle(token, now=101.0)
                    return "settled"
                except GateRejected as exc:
                    return exc.reason

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(run, tokens))
        self.assertCountEqual(["settled", "insufficient_funds"], outcomes)
        self.record(state=self.assert_funds(30, 70, 1), concurrent_outcomes=outcomes)

    def test_17_concurrent_duplicate_retry_has_one_ledger_row(self):
        token = self.issue()
        barrier = threading.Barrier(4)

        def run(_):
            with DurableGateway(self.path) as gate:
                barrier.wait(timeout=10)
                return gate.settle(token, now=101.0)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            receipts = list(pool.map(run, range(4)))
        self.assertTrue(all(receipt == receipts[0] for receipt in receipts))
        self.record(state=self.assert_funds(70, 30, 1), concurrent_retries=4,
                    unique_receipts=len({r["receipt_id"] for r in receipts}))

    def test_18_lock_wait_rechecks_clock_after_acquisition(self):
        token = self.issue()
        entered = threading.Event()
        clock_read = threading.Event()
        start = threading.Event()
        clock_value = [101.0]

        def clock():
            clock_read.set()
            return clock_value[0]

        def worker():
            with DurableGateway(self.path, clock=clock) as gate:
                entered.set()
                start.wait(timeout=10)
                try:
                    gate.settle(token)
                    return "settled"
                except GateRejected as exc:
                    return exc.reason

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(worker)
            self.assertTrue(entered.wait(timeout=10))
            self.gate.db.execute("BEGIN IMMEDIATE")
            try:
                start.set()
                self.assertFalse(clock_read.wait(timeout=0.08))
                clock_value[0] = 200.0
            finally:
                self.gate.db.execute("COMMIT")
            outcome = future.result(timeout=10)
        self.assertEqual("support_expired", outcome)
        self.assertTrue(clock_read.is_set())
        self.record(state=self.assert_funds(100, 0, 0), clock_before_wait=101.0,
                    clock_after_lock_acquired=200.0, outcome=outcome)

    def test_19_invalidation_settlement_races_are_serializable(self):
        records = []
        for i in range(24):
            race_path = Path(self.temp.name) / f"race_{i}.sqlite"
            with DurableGateway(race_path) as setup:
                setup.create_account("payer", 100)
                setup.create_account("recipient", 0)
                setup.put_subject("root", 200.0)
                setup.create_effect("e", "payer", "recipient", 30, ["root"])
                setup.stage("e", {"i": i})
                token = setup.issue("e", now=100.0)
            barrier = threading.Barrier(2)

            def settle():
                with DurableGateway(race_path) as gate:
                    barrier.wait(timeout=10)
                    try:
                        gate.settle(token, now=101.0)
                        return "settled_before_invalidation"
                    except GateRejected as exc:
                        return exc.reason

            def invalidate():
                with DurableGateway(race_path) as gate:
                    barrier.wait(timeout=10)
                    return gate.invalidate("root")

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                a = pool.submit(settle)
                b = pool.submit(invalidate)
                outcome, epoch = a.result(timeout=10), b.result(timeout=10)
            with DurableGateway(race_path) as verify:
                state = verify.inspect()
                balances = {r["account_id"]: r["balance"] for r in state["accounts"]}
                self.assertEqual(100, sum(balances.values()))
                self.assertEqual(1, epoch)
                if outcome == "settled_before_invalidation":
                    self.assertEqual({"payer": 70, "recipient": 30}, balances)
                    self.assertEqual(1, len(state["ledger"]))
                    self.denied("cannot_rollback_settled_effect", verify.cleanup, "e")
                else:
                    self.assertEqual("support_invalidated", outcome)
                    self.assertEqual({"payer": 100, "recipient": 0}, balances)
                    self.assertEqual(0, len(state["ledger"]))
                records.append({"trial": i, "outcome": outcome, "state": state})
        self.record(race_trials=records,
                    outcome_counts={label: sum(r["outcome"] == label for r in records)
                                    for label in ("settled_before_invalidation", "support_invalidated")},
                    qualification="Finite race trials admit only the two legal serial outcomes; not an exhaustive proof.")

    def test_20_commit_then_invalidation_is_irreversible(self):
        token = self.issue()
        self.gate.settle(token, now=101.0)
        self.gate.invalidate("root:a:g0")
        self.denied("cannot_rollback_settled_effect", self.gate.cleanup, "effect:a")
        self.record(state=self.assert_funds(70, 30, 1),
                    limitation="Invalidation after committed settlement cannot undo the transfer.")

    def test_21_shared_support_cleanup_removes_three_real_stages(self):
        affected = ["effect:a", "effect:child1", "effect:child2"]
        for eid in affected[1:]:
            self.gate.create_effect(eid, "payer", "recipient", 10, ["root:a:g0"])
            self.gate.stage(eid, {"materialized_child": eid})
        self.gate.create_effect("effect:unrelated", "payer", "recipient", 10, ["root:b:g0"])
        self.gate.stage("effect:unrelated", {"invoice": "unrelated"})
        tokens = {eid: self.gate.issue(eid, now=100.0) for eid in affected + ["effect:unrelated"]}
        before = self.gate.inspect()
        self.gate.invalidate("root:a:g0")
        for eid in affected:
            self.denied("support_invalidated", self.gate.settle, tokens[eid], now=101.0)
        self.gate.settle(tokens["effect:unrelated"], now=101.0)
        removed = sum(self.gate.cleanup(eid) for eid in affected)
        state = self.assert_funds(90, 10, 1)
        self.assertEqual(3, removed)
        self.assertEqual([], state["stages"])
        self.assertEqual(3, sum(e["state"] == "cancelled" for e in state["effects"]))
        self.record(state=state, state_before=before, actual_affected_stages_deleted=removed,
                    note="Support sets are explicitly supplied; the gateway does not discover transitive lineage.")

    def test_22_payload_hash_binding_rejects_staging_corruption(self):
        token = self.issue()
        # Deliberate fault injection tests the hash binding. Direct SQL access
        # remains outside the trusted API and is not an adversary claim.
        self.gate.db.execute("UPDATE stages SET payload=? WHERE effect_id='effect:a'",
                             ('{"invoice":"tampered"}',))
        self.denied("payload_changed", self.gate.settle, token, now=101.0)
        self.record(state=self.assert_funds(100, 0, 0), denial="payload_changed",
                    qualification="Fault injection; arbitrary privileged DB writes are not in the threat model.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path)
    args = parser.parse_args()
    started = time.perf_counter()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DurableGatewayTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {
        "implementation": "Local SQLite transactional reference; not blockchain validation",
        "validation_utc": datetime.now(timezone.utc).isoformat(),
        "clock_semantics": "time.time read after BEGIN IMMEDIATE; explicit now is a model linearization timestamp",
        "sqlite_version": sqlite3.sqlite_version,
        "python_version": platform.python_version(),
        "journal_mode": "WAL", "synchronous": "FULL",
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
        "successful": result.wasSuccessful(),
        "source_sha256": {
            str(path.name): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (Path(__file__).resolve(), Path(__file__).resolve().parents[1] / "durable_gateway.py")
        },
        "validation_wall_seconds_not_a_benchmark": time.perf_counter() - started,
        "test_evidence": EVIDENCE,
        "limitations": [
            "SQLite's single writer physically serializes settlement and invalidation.",
            "Evidence truth, support completeness, trusted clock, and exclusive gateway authority are assumptions.",
            "Synthetic account balances represent integer units and are not real assets.",
            "Process exit and reopen do not reproduce power loss, hardware failure, or distributed chain finality.",
            "Post-commit invalidation cannot reverse an already committed transfer.",
            "Finite concurrency trials are tests, not an exhaustive correctness proof or throughput benchmark.",
        ],
    }
    if args.results:
        args.results.parent.mkdir(parents=True, exist_ok=True)
        args.results.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        summary = args.results.with_name(args.results.stem + "_summary.csv")
        with summary.open("w", newline="", encoding="utf-8") as stream:
            fields = ["test", "payer_balance", "recipient_balance", "ledger_rows", "stage_rows", "token_rows"]
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            for evidence in EVIDENCE:
                state = evidence["state"]
                balances = {r["account_id"]: r["balance"] for r in state["accounts"]}
                writer.writerow({"test": evidence["test"], "payer_balance": balances["payer"],
                                 "recipient_balance": balances["recipient"], "ledger_rows": len(state["ledger"]),
                                 "stage_rows": len(state["stages"]), "token_rows": len(state["tokens"])})
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
