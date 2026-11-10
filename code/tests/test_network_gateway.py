"""Executable safety and actual loopback/crash checks for network_gateway."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from urllib.request import Request, ProxyHandler, build_opener
import uuid

CODE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE))
from network_gateway import NetworkGateway, bootstrap, POLICIES
from durable_gateway import GateRejected


def workload():
    return {
        "registry": {"artifact_parents": {"root": [], "child": ["root"], "other": []},
                     "artifact_obligations": {"root": ["source"]},
                     "effect_artifacts": {"pay": ["child"], "otherpay": ["other"]},
                     "effect_obligations": {}},
        "accounts": {"payer": 100, "recipient": 0},
        "effects": [{"effect_id": eid, "payer": "payer", "recipient": "recipient", "amount": 10,
                     "payload": {"effect": eid, "result": 42}} for eid in ("pay", "otherpay")],
        "extra_subjects": ["o:extension"],
        "expires_at": time.time() + 3600,
    }


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.base = CODE.parent / "results" / "gateway_test_scratch"
        self.base.mkdir(parents=True, exist_ok=True)
        self.path = self.base / uuid.uuid4().hex
        self.path.mkdir()
        self.children = []

    def tearDown(self):
        for process in self.children:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        target = self.path.resolve()
        if target.parent != self.base.resolve():
            raise RuntimeError("scratch path escaped test root")
        shutil.rmtree(target)

    def new(self, policy="support_epoch", data=None):
        db = self.path / (policy + ".sqlite")
        bootstrap(db, data or workload(), policy)
        return db

    def test_relevant_refresh_distinguishes_policies(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                with NetworkGateway(self.new(policy), policy) as gate:
                    token = gate.issue("pay")
                    gate.refresh("a:root")
                    if policy == "full_recheck":
                        self.assertEqual(gate.settle(token)["amount"], 10)
                    else:
                        with self.assertRaisesRegex(GateRejected, "support_epoch_changed"):
                            gate.settle(token)
                        gate.settle(gate.issue("pay"))
                    self.assertEqual(gate.balance("payer"), 90)

    def test_unrelated_refresh_only_global_cancels(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                with NetworkGateway(self.new(policy), policy) as gate:
                    token = gate.issue("pay")
                    gate.refresh("a:other")
                    if policy == "global_epoch":
                        with self.assertRaisesRegex(GateRejected, "global_epoch_changed"):
                            gate.settle(token)
                    else:
                        gate.settle(token)

    def test_root_invalidation_blocks_before_cleanup(self):
        for policy in POLICIES:
            with self.subTest(policy=policy):
                with NetworkGateway(self.new(policy), policy) as gate:
                    token = gate.issue("pay")
                    gate.invalidate("a:root")
                    self.assertEqual(len(gate.inspect()["stages"]), 2)
                    with self.assertRaises(GateRejected):
                        gate.settle(token)
                    result = gate.cleanup()
                    self.assertEqual(result, {"cancelled_effects": ["pay"], "stage_rows_deleted": 1})
                    gate.settle(gate.issue("otherpay"))
                    self.assertEqual(gate.balance("payer"), 90)

    def test_no_invalid_resurrection(self):
        with NetworkGateway(self.new()) as gate:
            gate.invalidate("a:root")
            with self.assertRaisesRegex(GateRejected, "tombstone"):
                gate.refresh("a:root")

    def test_append_contract_stales_token_and_changes_cleanup_support(self):
        with NetworkGateway(self.new()) as gate:
            token = gate.issue("pay")
            gate.extend_contract("pay", ["o:extension"])
            with self.assertRaisesRegex(GateRejected, "contract_changed"):
                gate.settle(token)
            gate.invalidate("o:extension")
            self.assertEqual(gate.cleanup()["cancelled_effects"], ["pay"])

    def test_unrelated_append_stales_global(self):
        with NetworkGateway(self.new("global_epoch"), "global_epoch") as gate:
            token = gate.issue("pay")
            gate.extend_contract("otherpay", ["o:extension"])
            with self.assertRaisesRegex(GateRejected, "global_epoch_changed"):
                gate.settle(token)

    def test_payload_digest_and_expected_effect(self):
        with NetworkGateway(self.new()) as gate:
            token = gate.issue("pay")
            with self.assertRaisesRegex(GateRejected, "token_effect_mismatch"):
                gate.settle(token, expected_effect_id="otherpay")
            gate.db.execute("UPDATE stages SET payload='{}' WHERE effect_id='pay'")
            with self.assertRaisesRegex(GateRejected, "payload_changed"):
                gate.settle(token)
            self.assertEqual(gate.balance("payer"), 100)

    def test_dynamic_stage_is_real_and_immutable(self):
        data = workload()
        data["stage_at_bootstrap"] = False
        with NetworkGateway(self.new(data=data)) as gate:
            self.assertEqual(gate.inspect()["stages"], [])
            with self.assertRaisesRegex(GateRejected, "payload_not_staged"):
                gate.issue("pay")
            gate.stage("pay", {"computed_result": 10})
            with self.assertRaisesRegex(GateRejected, "payload_is_immutable"):
                gate.stage("pay", {"computed_result": 11})
            gate.settle(gate.issue("pay"))
            self.assertEqual(gate.inspect()["stages"], [])

    def test_restart_preserves_global_tokens_and_idempotence(self):
        db = self.new("global_epoch")
        with NetworkGateway(db, "global_epoch") as gate:
            token = gate.issue("pay")
            gate.refresh("a:other")
        with NetworkGateway(db, "global_epoch") as gate:
            with self.assertRaisesRegex(GateRejected, "global_epoch_changed"):
                gate.settle(token)
            token = gate.issue("pay")
            receipt = gate.settle(token)
        with NetworkGateway(db, "global_epoch") as gate:
            gate.invalidate("a:root")
            self.assertEqual(gate.settle(token), receipt)
            state = gate.inspect()
            self.assertEqual(len(state["ledger"]), 1)
            self.assertEqual(len([r for r in state["audit"] if r["kind"] == "settle"]), 1)
            self.assertEqual(gate.balance("payer"), 90)

    def test_expiry_equality_and_refresh_deadline_semantics(self):
        for policy in POLICIES:
            data = workload()
            data["expires_at"] = 100.0
            with NetworkGateway(self.new(policy, data), policy, clock=lambda: 10.0) as gate:
                token = gate.issue("pay", now=90.0, ttl=50.0)
                with self.assertRaises(GateRejected):
                    gate.settle(token, now=100.0)
                for sid in ("a:root", "a:child", "o:source"):
                    gate.refresh(sid, expires_at=130.0)
                if policy == "full_recheck":
                    gate.settle(token, now=110.0)
                else:
                    with self.assertRaises(GateRejected):
                        gate.settle(token, now=110.0)

    def test_failed_settlement_rolls_back_balances_and_audit(self):
        db = self.new()
        def fail(phase):
            if phase == "before_commit":
                raise RuntimeError("controlled rollback")
        with NetworkGateway(db, fault_hook=fail) as gate:
            token = gate.issue("pay")
            with self.assertRaisesRegex(RuntimeError, "controlled rollback"):
                gate.settle(token)
            state = gate.inspect()
            self.assertEqual(gate.balance("payer"), 100)
            self.assertEqual(state["ledger"], [])
            self.assertFalse(any(r["kind"] == "settle" for r in state["audit"]))

    def test_rejection_records_actual_evaluation_prefix(self):
        db = self.new()
        with NetworkGateway(db) as gate:
            token = gate.issue("pay")
            gate.refresh("a:root")
            prefix = gate.inspect()["audit"][-1]["seq"]
            try:
                gate.settle(token)
            except GateRejected as error:
                reason = error.reason
            # A separate admitted mutation may be logged before the rejection.
            with NetworkGateway(db) as other:
                other.invalidate("a:other")
            gate.log_reject("settle", {"nonce": token, "expected_effect_id": "pay"}, reason)
            rejection = gate.inspect()["audit"][-1]
            self.assertEqual(rejection["kind"], "reject")
            self.assertEqual(rejection["payload"]["evaluated_prefix_seq"], prefix)
            self.assertLess(rejection["payload"]["evaluated_at"], rejection["at_time"])

    def start_server(self, db, policy):
        ready = self.path / (uuid.uuid4().hex + ".json")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen([sys.executable, str(CODE / "network_gateway.py"), "--db", str(db),
                                    "--policy", policy, "--ready-file", str(ready)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        self.children.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ready.exists():
                try:
                    state = json.loads(ready.read_text(encoding="utf-8"))
                    return process, f"http://127.0.0.1:{state['port']}/rpc"
                except json.JSONDecodeError:
                    pass
            if process.poll() is not None:
                self.fail("gateway exited before ready")
            time.sleep(0.01)
        self.fail("gateway startup timed out")

    def rpc(self, url, operation, **arguments):
        request = {"operation": operation, "arguments": arguments,
                   "request_id": uuid.uuid4().hex, "actor_id": "test-worker"}
        with build_opener(ProxyHandler({})).open(Request(url, data=json.dumps(request).encode(), headers={"Content-Type": "application/json"}), timeout=10) as response:
            return json.load(response)

    def test_real_http_stage_settle_and_reject_audit(self):
        data = workload()
        data["stage_at_bootstrap"] = False
        db = self.new(data=data)
        _, url = self.start_server(db, "support_epoch")
        self.assertTrue(self.rpc(url, "ping")["ok"])
        self.assertFalse(self.rpc(url, "issue", effect_id="pay")["ok"])
        self.assertTrue(self.rpc(url, "stage", effect_id="pay", payload={"sum": 42})["ok"])
        token = self.rpc(url, "issue", effect_id="pay")["result"]
        result = self.rpc(url, "settle", nonce=token, expected_effect_id="pay")
        self.assertTrue(result["ok"])
        self.assertEqual(self.rpc(url, "settle", nonce=token)["result"], result["result"])
        state = self.rpc(url, "inspect")["result"]
        self.assertTrue(any(row["kind"] == "reject" and row["payload"]["reason"] == "payload_not_staged" for row in state["audit"]))

    def test_real_process_crashes_and_restart_exactly_once(self):
        for phase in ("after_debit", "before_commit", "after_commit"):
            with self.subTest(phase=phase):
                phase_dir = self.path / phase
                phase_dir.mkdir()
                db = phase_dir / "gateway.sqlite"
                bootstrap(db, workload(), "support_epoch")
                process, url = self.start_server(db, "support_epoch")
                token = self.rpc(url, "issue", effect_id="pay")["result"]
                marker = phase_dir / "crash.json"
                with self.assertRaises(Exception):
                    self.rpc(url, "settle", nonce=token, expected_effect_id="pay", fault_phase=phase, fault_marker=str(marker))
                self.assertEqual(process.wait(timeout=5), 91)
                self.assertTrue(marker.exists())
                with NetworkGateway(db) as gate:
                    state = gate.inspect()
                    committed = phase == "after_commit"
                    self.assertEqual(len(state["ledger"]), int(committed))
                    self.assertEqual(gate.balance("payer"), 90 if committed else 100)
                    self.assertEqual(len([r for r in state["audit"] if r["kind"] == "settle"]), int(committed))
                _, url = self.start_server(db, "support_epoch")
                self.assertTrue(self.rpc(url, "settle", nonce=token, expected_effect_id="pay")["ok"])
                self.assertTrue(self.rpc(url, "settle", nonce=token, expected_effect_id="pay")["ok"])
                state = self.rpc(url, "inspect")["result"]
                self.assertEqual(len(state["ledger"]), 1)
                self.assertEqual(len([r for r in state["audit"] if r["kind"] == "settle"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
