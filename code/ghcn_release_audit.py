"""Independent audit of real-data release cases; no gateway/controller imports."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def supports_from_manifest_registry(registry):
    supports = {}
    for eid, roots in registry["effect_artifacts"].items():
        seen, stack = set(), list(roots)
        subjects = {"o:" + oid for oid in registry["effect_obligations"].get(eid, [])}
        while stack:
            aid = stack.pop()
            if aid in seen:
                continue
            if aid not in registry["artifact_parents"]:
                raise AssertionError("unknown artifact in registry")
            seen.add(aid)
            subjects.add("a:" + aid)
            subjects.update("o:" + oid for oid in registry["artifact_obligations"].get(aid, []))
            stack.extend(registry["artifact_parents"][aid])
        supports[eid] = subjects
    return supports


def expected_cohorts(workload, source_events):
    support = supports_from_manifest_registry(workload["registry"])
    invalid = {event["subject_id"] for event in source_events if event["kind"] == "invalidate"}
    blocked = {eid for eid, subjects in support.items() if invalid & subjects}
    return support, set(support) - blocked, blocked


def check_registry_against_file_manifests(registry, manifest):
    """Check the compiled boundary independently of the adapter/compiler code."""
    records = manifest["artifacts"]
    identity = {aid: aid + "@" + record["generation"] for aid, record in records.items()}
    expected_parents = {identity[aid]: sorted(identity[parent["artifact_id"]] for parent in record["inputs"])
                        for aid, record in records.items()}
    actual_parents = {aid: sorted(parents) for aid, parents in registry["artifact_parents"].items()}
    if actual_parents != expected_parents:
        raise AssertionError("compiled registry omits or changes actual manifest ancestry")
    expected_artifact_obligations = {identity[aid]: ["author_policy_acceptance:" + aid]
                                     for aid, record in records.items() if record["operation"] == "policy"}
    if registry["artifact_obligations"] != expected_artifact_obligations:
        raise AssertionError("compiled policy obligation mismatch")
    expected_effects = {"publish:" + aid: [identity[aid]] for aid in manifest["release_artifacts"]}
    if registry["effect_artifacts"] != expected_effects:
        raise AssertionError("compiled release generation mismatch")
    expected_approvals = {"publish:" + aid: ["author_release_approval:" + aid] for aid in manifest["release_artifacts"]}
    if registry["effect_obligations"] != expected_approvals:
        raise AssertionError("compiled release obligation mismatch")


def check_release_bindings(workload, manifest, artifact_root):
    """Bind every declared action, including blocked ones, to its own report."""
    release_ids = manifest["release_artifacts"]
    effect_ids = [effect["effect_id"] for effect in workload["effects"]]
    expected_ids = {"publish:" + aid for aid in release_ids}
    if (len(release_ids) != len(set(release_ids)) or
            len(effect_ids) != len(set(effect_ids)) or set(effect_ids) != expected_ids):
        raise AssertionError("release effect identity coverage mismatch")
    artifact_root = Path(artifact_root).resolve()
    for effect in workload["effects"]:
        payload = effect["payload"]
        aid, eid = payload["artifact_id"], effect["effect_id"]
        if aid not in release_ids or eid != "publish:" + aid:
            raise AssertionError("effect identity does not bind its payload artifact")
        record = manifest["artifacts"][aid]
        if record["artifact_id"] != aid:
            raise AssertionError("manifest artifact identity mismatch")
        if (effect["generation"] != record["generation"] or
                payload["generation"] != record["generation"]):
            raise AssertionError("payload or effect generation differs from manifest")
        if effect["artifact_path"] != record["path"] or payload["content_sha256"] != record["sha256"]:
            raise AssertionError("payload path or hash differs from manifest")
        if workload["registry"]["effect_artifacts"].get(eid) != [aid + "@" + record["generation"]]:
            raise AssertionError("payload artifact differs from authorized manifest root")
        source = (artifact_root / record["path"]).resolve()
        if not source.is_relative_to(artifact_root):
            raise AssertionError("report artifact path escapes workflow root")
        content = source.read_bytes()
        if hashlib.sha256(content).hexdigest() != record["sha256"] or json.loads(content) != payload["result"]:
            raise AssertionError("actual report artifact does not match manifest-bound payload")


def audit_run(folder, artifact_root):
    folder, artifact_root = Path(folder), Path(artifact_root)
    meta, workload = read(folder / "run_meta.json"), read(folder / "workload.json")
    snapshot, events = read(folder / "gateway_snapshot.json"), read(folder / "source_events.json")
    file_manifest = artifact_root / "workflow_manifest.json"
    if not file_manifest.exists():
        raise AssertionError("actual file manifest required for registry audit")
    manifest = read(file_manifest)
    check_registry_against_file_manifests(workload["registry"], manifest)
    check_release_bindings(workload, manifest, artifact_root)
    if meta["status"] != "completed":
        raise AssertionError("run not completed")
    supports, expected_settled, expected_blocked = expected_cohorts(workload, events)
    ledger = snapshot["ledger"]
    ledger_ids = [row["effect_id"] for row in ledger]
    if set(ledger_ids) != expected_settled or len(ledger_ids) != len(set(ledger_ids)):
        raise AssertionError("incorrect settled cohort or duplicate ledger effect")
    for key in ("nonce", "receipt_id"):
        if len({row[key] for row in ledger}) != len(ledger):
            raise AssertionError("duplicate ledger nonce/receipt")
    db_support = {}
    for row in snapshot["effect_support"]:
        db_support.setdefault(row["effect_id"], set()).add(row["subject_id"])
    if db_support != supports:
        raise AssertionError("gateway support differs from independently traversed registry")
    if snapshot["stages"] or snapshot["cleanup_queue"]:
        raise AssertionError("database stage or cleanup residue")
    effects = {item["effect_id"]: item for item in workload["effects"]}
    db_effects = {row["effect_id"]: row for row in snapshot["effects"]}
    tokens = {row["nonce"]: row for row in snapshot["tokens"]}
    expected_balances = dict(workload["accounts"])
    journals = {}
    published = []
    for journal_path in (folder / "workers").glob("*/journal_*.json"):
        states = read(journal_path)
        if journals.keys() & states.keys():
            raise AssertionError("worker assignment overlap")
        journals.update(states)
    if set(journals) != set(effects):
        raise AssertionError("missing worker journal")
    for row in ledger:
        eid, effect = row["effect_id"], effects[row["effect_id"]]
        if any(row[key] != effect[key] for key in ("payer", "recipient", "amount")):
            raise AssertionError("wrong account transfer")
        expected_balances[row["payer"]] -= row["amount"]
        expected_balances[row["recipient"]] += row["amount"]
        token = tokens[row["nonce"]]
        if token["state"] != "consumed" or token["effect_id"] != eid or journals[eid].get("nonce") != row["nonce"]:
            raise AssertionError("nonce not consumed exactly by its intended effect")
        if journals[eid].get("receipt") != row:
            raise AssertionError("worker receipt does not equal durable ledger receipt")
        canonical_payload = json.dumps(effect["payload"], sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
        payload_hash = hashlib.sha256(canonical_payload).hexdigest()
        if token["payload_hash"] != payload_hash or db_effects[eid]["payload_hash"] != payload_hash:
            raise AssertionError("contract payload digest mismatch")
        source = (artifact_root / effect["artifact_path"]).read_bytes()
        if hashlib.sha256(source).hexdigest() != effect["payload"]["content_sha256"] or json.loads(source) != effect["payload"]["result"]:
            raise AssertionError("actual report artifact does not match payload")
        name = hashlib.sha256(eid.encode()).hexdigest() + ".json"
        matches = list((folder / "workers").glob("*/published/" + name))
        if len(matches) != 1 or matches[0].read_bytes() != source:
            raise AssertionError("missing, duplicate or incorrect published report bytes")
        published.append(name)
        if db_effects[eid]["state"] != "settled":
            raise AssertionError("ledger/effect state mismatch")
    for eid in expected_blocked:
        if not journals[eid].get("blocked") or "receipt" in journals[eid]:
            raise AssertionError("withdrawn report was not blocked")
        if journals[eid]["blocked"] not in ("token_revoked", "effect_cancelled", "support_invalidated"):
            raise AssertionError("withdrawn report blocked for an unexpected reason")
        if db_effects[eid]["state"] != "cancelled":
            raise AssertionError("withdrawn report was not cleaned up")
        token = tokens[journals[eid]["nonce"]]
        if token["effect_id"] != eid:
            raise AssertionError("withdrawn token belongs to a different effect")
        # Old snapshots eagerly marked token rows revoked.  The bounded-work
        # revision retains raw token rows and rejects through the cancelled
        # effect tombstone, checked above.  This oracle does not import gateway
        # code or rewrite persisted token state to hide that distinction.
        lazy_cancelled = (snapshot.get("cleanup_token_invalidation") == "effect_tombstone"
                          and token["state"] == "issued")
        if token["state"] != "revoked" and not lazy_cancelled:
            raise AssertionError("withdrawn token lacks a valid cancellation representation")
    actual_balances = {row["account_id"]: row["balance"] for row in snapshot["accounts"]}
    if actual_balances != expected_balances:
        raise AssertionError("balance conservation or account mismatch")
    actual_published = [p.name for p in (folder / "workers").glob("*/published/*")]
    if sorted(actual_published) != sorted(published):
        raise AssertionError("extra published report")
    if list((folder / "workers").glob("*/staged/*")):
        raise AssertionError("local staging residue")
    audit = snapshot["audit"]
    settled_events = [row for row in audit if row["kind"] == "settle"]
    if {row["effect_id"] for row in settled_events} != expected_settled or len(settled_events) != len(expected_settled):
        raise AssertionError("audit/ledger settlement mismatch")
    mutation_rows = [row for row in audit if row["kind"] in ("invalidate", "refresh")]
    if len(mutation_rows) != len(events):
        raise AssertionError("source event/admission mismatch")
    for event in events:
        matching = [row for row in mutation_rows if row["kind"] == event["kind"] and row["subject_id"] == event["subject_id"]]
        if len(matching) != 1 or not event["reply"]["ok"]:
            raise AssertionError("unacknowledged intervention")
        if any(row["seq"] <= matching[0]["seq"] for row in settled_events):
            raise AssertionError("case barrier violated: settlement preceded intervention")
    issue_rows = [row for row in audit if row["kind"] == "issue"]
    if {row["effect_id"] for row in issue_rows} != set(effects) or len(issue_rows) != len(effects):
        raise AssertionError("all effects were not issued before intervention")
    if mutation_rows and max(row["seq"] for row in issue_rows) >= min(row["seq"] for row in mutation_rows):
        raise AssertionError("preparation barrier violated")
    cleanup_rows = [row for row in audit if row["kind"] == "cleanup"]
    # Validate authorization at each actual admitted audit prefix, not just
    # against terminal state; this remains independent of policy implementation.
    invalid = set()
    unsafe = 0
    for row in sorted(audit, key=lambda row: row["seq"]):
        if row["kind"] == "invalidate":
            invalid.add(row["subject_id"])
        if row["kind"] == "settle" and invalid & supports[row["effect_id"]]:
            unsafe += 1
    if unsafe:
        raise AssertionError("unsafe admitted-state settlement")
    paths = Counter(row["payload"].get("validation_metrics", {}).get("validation_path", "unknown") for row in settled_events)
    interleaved = bool(cleanup_rows and settled_events and min(x["seq"] for x in cleanup_rows) < max(x["seq"] for x in settled_events)
                       and max(x["seq"] for x in cleanup_rows) > min(x["seq"] for x in settled_events))
    return {"status": "passed", "policy": meta["policy"], "scenario": meta["scenario"],
            "requested": len(effects), "settled": len(expected_settled), "blocked": len(expected_blocked),
            "published_bytes_verified": len(published), "unsafe": unsafe, "duplicate_settlements": 0,
            "release_identity_bindings_verified": len(effects),
            "support_size_range": [min(map(len, supports.values())), max(map(len, supports.values()))],
            "validation_paths": dict(paths), "cleanup_batches": len(cleanup_rows),
            "cleanup_audit_interleaved_with_settlements": interleaved,
            "settled_effect_ids": sorted(expected_settled), "blocked_effect_ids": sorted(expected_blocked)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit_run(args.run, args.artifacts), sort_keys=True))
