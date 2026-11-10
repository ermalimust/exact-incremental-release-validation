"""Independent-oracle mutation tests; fixtures are not experimental results."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ghcn_release_audit import audit_run, expected_cohorts, supports_from_manifest_registry, check_registry_against_file_manifests, check_release_bindings
from ghcn_oracle import verify_release_payloads

TEST_ROOT = Path(__file__).resolve().parents[2] / "build/ghcn_audit_test_tmp"
TEST_ROOT.mkdir(parents=True, exist_ok=True)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class CohortTests(unittest.TestCase):
    def setUp(self):
        self.registry = {"artifact_parents": {"raw": [], "qc": ["raw"], "baseline": ["qc"], "report": ["baseline"], "other": []},
                         "artifact_obligations": {"qc": ["qc_approval"]},
                         "effect_artifacts": {"dependent": ["report"], "independent": ["other"]},
                         "effect_obligations": {"dependent": ["publication_approval"]}}

    def test_transitive_artifact_and_obligation_closure(self):
        self.assertEqual(supports_from_manifest_registry(self.registry)["dependent"],
                         {"a:raw", "a:qc", "a:baseline", "a:report", "o:qc_approval", "o:publication_approval"})

    def test_withdrawal_blocks_only_transitive_cohort(self):
        _, settled, blocked = expected_cohorts({"registry": self.registry}, [{"kind": "invalidate", "subject_id": "a:baseline"}])
        self.assertEqual(settled, {"independent"})
        self.assertEqual(blocked, {"dependent"})

    def test_benign_or_unrelated_refresh_never_changes_acceptance(self):
        for target in ("o:qc_approval", "o:unrelated"):
            _, settled, blocked = expected_cohorts({"registry": self.registry}, [{"kind": "refresh", "subject_id": target}])
            self.assertEqual(settled, {"dependent", "independent"})
            self.assertFalse(blocked)

    def test_compiled_registry_cannot_omit_real_manifest_ancestor(self):
        manifest = {"artifacts": {"raw": {"generation": "r", "inputs": [], "operation": "source"},
                                  "report": {"generation": "v", "inputs": [{"artifact_id": "raw"}], "operation": "station_report"}},
                    "release_artifacts": ["report"]}
        registry = {"artifact_parents": {"raw@r": [], "report@v": ["raw@r"]}, "artifact_obligations": {},
                    "effect_artifacts": {"publish:report": ["report@v"]},
                    "effect_obligations": {"publish:report": ["author_release_approval:report"]}}
        check_registry_against_file_manifests(registry, manifest)
        registry["artifact_parents"]["report@v"] = []
        with self.assertRaisesRegex(AssertionError, "actual manifest ancestry"):
            check_registry_against_file_manifests(registry, manifest)


class ReleaseMutationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root = Path(self.temp.name)
        self.run, self.artifacts = self.root / "case", self.root / "artifacts"
        content = b'{"actual_observation_summary":1}'
        self.artifacts.mkdir()
        (self.artifacts / "report.dat").write_bytes(content)
        self.payload = {"artifact_id": "report", "generation": "fixed-generation",
                        "content_sha256": hashlib.sha256(content).hexdigest(), "result": json.loads(content)}
        payload_hash = hashlib.sha256(json.dumps(self.payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        eid = "publish:report"
        aid = "report@fixed-generation"
        effect = {"effect_id": eid, "payer": "a", "recipient": "b", "amount": 1, "payload": self.payload,
                  "artifact_path": "report.dat", "generation": "fixed-generation"}
        workload = {"effects": [effect], "accounts": {"a": 10, "b": 0},
                    "registry": {"artifact_parents": {aid: []}, "artifact_obligations": {},
                                 "effect_artifacts": {eid: [aid]}, "effect_obligations": {eid: ["author_release_approval:report"]}}}
        save(self.artifacts / "workflow_manifest.json", {"artifacts": {"report": {
            "artifact_id": "report", "generation": "fixed-generation", "inputs": [], "operation": "source",
            "path": "report.dat", "sha256": self.payload["content_sha256"]}}, "release_artifacts": ["report"]})
        receipt = {"effect_id": eid, "nonce": "nonce", "receipt_id": "receipt", "payer": "a", "recipient": "b", "amount": 1, "settled_at": 1.0}
        self.snapshot = {"ledger": [receipt], "effect_support": [{"effect_id": eid, "subject_id": "a:" + aid}, {"effect_id": eid, "subject_id": "o:author_release_approval:report"}],
                         "stages": [], "cleanup_queue": [], "effects": [{"effect_id": eid, "payload_hash": payload_hash, "state": "settled"}],
                         "tokens": [{"nonce": "nonce", "effect_id": eid, "state": "consumed", "payload_hash": payload_hash}],
                         "accounts": [{"account_id": "a", "balance": 9}, {"account_id": "b", "balance": 1}],
                         "audit": [{"seq": 1, "kind": "issue", "effect_id": eid, "payload": {}},
                                   {"seq": 2, "kind": "settle", "effect_id": eid, "payload": {"validation_metrics": {"validation_path": "full"}}}]}
        save(self.run / "run_meta.json", {"status": "completed", "policy": "full_sql", "scenario": "all_valid"})
        save(self.run / "workload.json", workload)
        save(self.run / "source_events.json", [])
        save(self.run / "gateway_snapshot.json", self.snapshot)
        save(self.run / "workers/0/journal_0.json", {eid: {"nonce": "nonce", "receipt": receipt}})
        self.published = self.run / "workers/0/published" / (hashlib.sha256(eid.encode()).hexdigest() + ".json")
        self.published.parent.mkdir(parents=True)
        self.published.write_bytes(content)

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_fixture(self):
        self.assertEqual(audit_run(self.run, self.artifacts)["settled"], 1)

    def test_wrong_actual_published_bytes_rejected(self):
        self.published.write_bytes(b"wrong bytes")
        with self.assertRaisesRegex(AssertionError, "published report bytes"):
            audit_run(self.run, self.artifacts)

    def test_wrong_balance_rejected(self):
        self.snapshot["accounts"][0]["balance"] = 10
        save(self.run / "gateway_snapshot.json", self.snapshot)
        with self.assertRaisesRegex(AssertionError, "balance"):
            audit_run(self.run, self.artifacts)

    def test_duplicate_ledger_rejected(self):
        self.snapshot["ledger"].append(copy.deepcopy(self.snapshot["ledger"][0]))
        save(self.run / "gateway_snapshot.json", self.snapshot)
        with self.assertRaisesRegex(AssertionError, "duplicate ledger"):
            audit_run(self.run, self.artifacts)

    def test_stage_residue_rejected(self):
        self.snapshot["stages"] = [{"effect_id": "release"}]
        save(self.run / "gateway_snapshot.json", self.snapshot)
        with self.assertRaisesRegex(AssertionError, "residue"):
            audit_run(self.run, self.artifacts)

    def test_underdeclared_database_support_rejected(self):
        self.snapshot["effect_support"] = []
        save(self.run / "gateway_snapshot.json", self.snapshot)
        with self.assertRaisesRegex(AssertionError, "independently traversed"):
            audit_run(self.run, self.artifacts)

    def withdrawn_fixture(self, state="issued", tombstone_semantics=True):
        eid, aid = "publish:report", "report@fixed-generation"
        self.published.unlink()
        self.snapshot["ledger"] = []
        self.snapshot["effects"][0]["state"] = "cancelled"
        self.snapshot["tokens"][0]["state"] = state
        self.snapshot["accounts"][0]["balance"] = 10
        self.snapshot["accounts"][1]["balance"] = 0
        if tombstone_semantics:
            self.snapshot["cleanup_token_invalidation"] = "effect_tombstone"
        self.snapshot["audit"] = [
            {"seq": 1, "kind": "issue", "effect_id": eid, "payload": {}},
            {"seq": 2, "kind": "invalidate", "subject_id": "a:" + aid, "payload": {}},
            {"seq": 3, "kind": "cleanup", "payload": {"cancelled_effects": [eid]}}]
        save(self.run / "gateway_snapshot.json", self.snapshot)
        save(self.run / "source_events.json", [{"kind": "invalidate", "subject_id": "a:" + aid,
                                                "reply": {"ok": True}}])
        save(self.run / "workers/0/journal_0.json", {eid: {"nonce": "nonce", "blocked": "effect_cancelled"}})

    def test_cancelled_effect_with_raw_issued_token_is_verified(self):
        self.withdrawn_fixture()
        result = audit_run(self.run, self.artifacts)
        self.assertEqual(result["blocked"], 1)
        self.assertEqual(self.snapshot["tokens"][0]["state"], "issued")

    def test_old_eager_revocation_snapshot_remains_verifiable(self):
        self.withdrawn_fixture(state="revoked", tombstone_semantics=False)
        self.assertEqual(audit_run(self.run, self.artifacts)["blocked"], 1)

    def test_raw_issued_token_without_declared_tombstone_semantics_is_rejected(self):
        self.withdrawn_fixture(tombstone_semantics=False)
        with self.assertRaisesRegex(AssertionError, "cancellation representation"):
            audit_run(self.run, self.artifacts)

    def test_cancelled_effect_cannot_hide_consumed_token_without_ledger(self):
        self.withdrawn_fixture(state="consumed")
        with self.assertRaisesRegex(AssertionError, "cancellation representation"):
            audit_run(self.run, self.artifacts)

    def test_cancelled_token_cannot_belong_to_another_effect(self):
        self.withdrawn_fixture()
        self.snapshot["tokens"][0]["effect_id"] = "other"
        save(self.run / "gateway_snapshot.json", self.snapshot)
        with self.assertRaisesRegex(AssertionError, "different effect"):
            audit_run(self.run, self.artifacts)

    def test_tombstone_metadata_cannot_hide_pending_effect(self):
        self.withdrawn_fixture()
        self.snapshot["effects"][0]["state"] = "pending"
        save(self.run / "gateway_snapshot.json", self.snapshot)
        with self.assertRaisesRegex(AssertionError, "not cleaned up"):
            audit_run(self.run, self.artifacts)


class ReleaseIdentityTests(unittest.TestCase):
    """Self-consistent bytes must not borrow another report's authority."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TEST_ROOT)
        self.root = Path(self.temp.name)
        self.expected = {}
        self.manifest = {"artifacts": {}, "release_artifacts": ["station_a", "station_b"]}
        self.workload = {"effects": [], "registry": {"effect_artifacts": {}}}
        for aid, value in (("station_a", 11), ("station_b", 29)):
            result = {"station": aid, "observation_summary": value}
            content = json.dumps(result, sort_keys=True).encode()
            path, generation = aid + ".json", "generation_" + aid
            (self.root / path).write_bytes(content)
            sha = hashlib.sha256(content).hexdigest()
            self.expected[aid] = result
            self.manifest["artifacts"][aid] = {"artifact_id": aid, "generation": generation,
                                               "path": path, "sha256": sha}
            self.workload["effects"].append({"effect_id": "publish:" + aid, "generation": generation,
                "artifact_path": path, "payload": {"artifact_id": aid, "generation": generation,
                                                    "content_sha256": sha, "result": result}})
            self.workload["registry"]["effect_artifacts"]["publish:" + aid] = [aid + "@" + generation]

    def tearDown(self):
        self.temp.cleanup()

    def assert_both_reject(self, workload=None, manifest=None):
        workload = self.workload if workload is None else workload
        manifest = self.manifest if manifest is None else manifest
        with self.assertRaises(AssertionError):
            check_release_bindings(workload, manifest, self.root)
        with self.assertRaises(AssertionError):
            verify_release_payloads(manifest, workload, self.expected, self.root)

    def swap_report_contents(self):
        a, b = self.workload["effects"]
        for key in ("payload", "generation", "artifact_path"):
            a[key], b[key] = b[key], a[key]

    def test_valid_bindings_in_independent_oracles(self):
        check_release_bindings(self.workload, self.manifest, self.root)
        verify_release_payloads(self.manifest, self.workload, self.expected, self.root)

    def test_swapped_self_consistent_reports_cannot_borrow_authority(self):
        self.swap_report_contents()
        # Each payload still matches real file bytes. The effect IDs and their
        # authorized roots are unchanged, so the identity boundary must fail.
        for effect in self.workload["effects"]:
            content = (self.root / effect["artifact_path"]).read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), effect["payload"]["content_sha256"])
            self.assertEqual(json.loads(content), effect["payload"]["result"])
        self.assert_both_reject()

    def test_relabelled_swapped_payload_does_not_hide_wrong_generation(self):
        self.swap_report_contents()
        for effect in self.workload["effects"]:
            effect["payload"]["artifact_id"] = effect["effect_id"].removeprefix("publish:")
        self.assert_both_reject()

    def test_manifest_generation_path_and_hash_are_bound(self):
        for field in ("generation", "artifact_path", "payload_generation", "content_sha256"):
            with self.subTest(field=field):
                bad = copy.deepcopy(self.workload)
                effect = bad["effects"][0]
                if field == "payload_generation":
                    effect["payload"]["generation"] = "wrong"
                elif field == "content_sha256":
                    effect["payload"][field] = "f" * 64
                else:
                    effect[field] = "wrong"
                self.assert_both_reject(workload=bad)

    def test_swapped_registry_roots_rejected(self):
        roots = self.workload["registry"]["effect_artifacts"]
        roots["publish:station_a"], roots["publish:station_b"] = roots["publish:station_b"], roots["publish:station_a"]
        self.assert_both_reject()

    def test_duplicate_effect_or_declared_release_cannot_hide_missing_report(self):
        bad = copy.deepcopy(self.workload)
        bad["effects"][1] = copy.deepcopy(bad["effects"][0])
        self.assert_both_reject(workload=bad)
        bad_manifest = copy.deepcopy(self.manifest)
        bad_manifest["release_artifacts"].append("station_a")
        self.assert_both_reject(manifest=bad_manifest)


if __name__ == "__main__":
    unittest.main()
