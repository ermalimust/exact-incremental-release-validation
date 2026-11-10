"""Coordinate a small manifest-bound release case; never dispatch remote jobs.

Run init on the gateway host, serve the frozen gateway separately, and transfer
worker outputs explicitly. Only the final independent audit sets the durable
run status to completed. No token value is persisted in any case record.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from urllib.parse import urlsplit
import uuid

from adaptive_gateway import bootstrap, POLICIES
from ghcn_release_audit import (audit_run, check_registry_against_file_manifests,
                                check_release_bindings, expected_cohorts)
from workflow_release_worker import Client

SCENARIOS = ("all_valid", "unrelated_refresh", "benign_shared_refresh", "baseline_withdrawal")
SCHEMA = "remote-ghcn-case-v1"
CODE = Path(__file__).resolve().parent


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical_sha(value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def utc():
    return datetime.now(timezone.utc).isoformat()


def load_run(run, allowed):
    run = Path(run)
    meta = read(run / "run_meta.json")
    if meta.get("controller_schema") != SCHEMA or meta["status"] not in allowed:
        raise ValueError("case status must be one of " + ", ".join(sorted(allowed)))
    if sha(run / "workload.json") != meta["workload_sha256"]:
        raise ValueError("case workload changed after initialization")
    return run, meta, read(run / "workload.json")


@contextmanager
def controller_lock(run):
    """Serialize controller commands; worker processes continue independently."""
    lock = Path(run) / ".controller.lock"
    descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        os.write(descriptor, str(os.getpid()).encode())
        os.close(descriptor)
        descriptor = None
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        lock.unlink()


def gateway_origin(gateway):
    parsed = urlsplit(gateway)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            parsed.path not in ("", "/")):
        raise ValueError("gateway must be an HTTP(S) origin without credentials or query")
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    return f"{parsed.scheme}://{host}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"


def rpc(gateway, token_env, operation, **arguments):
    gateway = gateway_origin(gateway)
    client = Client(gateway, os.environ.get(token_env))
    try:
        return client.call(operation, "remote-case-controller", **arguments)
    finally:
        client.close()


def require_ok(reply, operation):
    if not reply.get("ok"):
        raise ValueError(operation + " rejected: " + str(reply.get("reason", "unknown")))
    return reply["result"]


def bound_snapshot(meta, gateway, token_env, allow_new_origin=False):
    origin = gateway_origin(gateway)
    bound = meta.get("gateway_origin")
    if (bound is None and not allow_new_origin) or (bound is not None and bound != origin):
        raise ValueError("gateway origin differs from the admitted case endpoint")
    snapshot = require_ok(rpc(origin, token_env, "inspect"), "inspect")
    if snapshot.get("adaptive_metadata", {}).get("policy") != meta["policy"]:
        raise ValueError("gateway policy does not match initialized case")
    initial = snapshot.get("metadata", {}).get("workload")
    if initial is None or canonical_sha(initial) != meta["bootstrap_workload_sha256"]:
        raise ValueError("gateway bootstrap fingerprint belongs to a different case")
    return snapshot


def init_run(run, workflow, scenario, policy, workers):
    run, workflow = Path(run), Path(workflow).resolve()
    if scenario not in SCENARIOS or policy not in POLICIES or not 1 <= workers <= 64:
        raise ValueError("invalid scenario, policy or worker count")
    if run.exists():
        raise FileExistsError("refusing to overwrite existing run: " + str(run))
    workload = read(workflow / "compatible_workload.json")
    manifest = read(workflow / "workflow_manifest.json")
    check_registry_against_file_manifests(workload["registry"], manifest)
    check_release_bindings(workload, manifest, workflow)
    case_id = str(uuid.uuid4())
    # Otherwise two fresh cases of the same frozen workflow have identical
    # bootstrap metadata. This registered marker is unrelated to every effect.
    marker = "o:remote_case:" + case_id
    workload["extra_subjects"] = sorted(set(workload.get("extra_subjects", [])) | {"o:unrelated_dataset_approval", marker})
    workload["case"] = scenario
    run.mkdir(parents=True)
    save(run / "workload.json", workload)
    save(run / "source_events.json", [])
    save(run / "cleanup_events.json", [])
    names = ("remote_case_controller.py", "adaptive_gateway.py", "network_gateway.py",
             "durable_gateway.py", "integrated_controller.py", "persistent_workflow.py",
             "workflow_release_worker.py", "continuous_worker.py", "ghcn_release_audit.py")
    meta = {"controller_schema": SCHEMA, "case_id": case_id, "case_marker_subject": marker,
            "status": "initializing", "scenario": scenario,
            "policy": policy, "workers": workers, "created_at": utc(),
            "physical_hosts": None, "scope": "release of already computed real-data reports",
            "deployment_note": "Host count and network deployment are not inferred by this controller.",
            "workflow_manifest_sha256": sha(workflow / "workflow_manifest.json"),
            "workload_sha256": sha(run / "workload.json"),
            "runtime_sha256": {name: sha(CODE / name) for name in names}}
    save(run / "run_meta.json", meta)
    try:
        result = bootstrap(run / "gateway.sqlite", workload, policy)
    except BaseException as error:
        meta.update(status="initialization_failed", failure_type=type(error).__name__)
        save(run / "run_meta.json", meta)
        raise
    meta.update(status="initialized", bootstrap_ms=result["bootstrap_ms"],
                bootstrap_workload_sha256=canonical_sha(result["metadata"]["workload"]))
    save(run / "run_meta.json", meta)
    return {"status": meta["status"], "run": str(run), "effects": len(workload["effects"]),
            "database": str(run / "gateway.sqlite")}


def prepare_barrier(snapshot, workload):
    expected = {effect["effect_id"] for effect in workload["effects"]}
    states = snapshot["effects"]
    tokens = snapshot["tokens"]
    if (snapshot["ledger"] or len(states) != len(expected) or
            {row["effect_id"] for row in states} != expected or
            any(row["state"] != "pending" for row in states) or
            len(snapshot["stages"]) != len(expected) or
            {row["effect_id"] for row in snapshot["stages"]} != expected or
            len(tokens) != len(expected) or {row["effect_id"] for row in tokens} != expected or
            len({row["nonce"] for row in tokens}) != len(tokens) or
            any(row["state"] != "issued" for row in tokens)):
        raise ValueError("prepare barrier incomplete or already settled; keep workers in prepare phase")


def intervention(workload, scenario):
    if scenario == "all_valid":
        return None
    if scenario == "unrelated_refresh":
        return {"kind": "refresh", "subject_id": "o:unrelated_dataset_approval"}
    if scenario == "benign_shared_refresh":
        matches = [aid for aid in workload["registry"]["artifact_parents"] if aid.startswith("policy:quality@")]
        if len(matches) != 1:
            raise ValueError("expected exactly one frozen shared quality policy")
        return {"kind": "refresh", "subject_id": "a:" + matches[0]}
    change = workload["controlled_revocation"]
    if change["kind"] != "invalidate":
        raise ValueError("baseline scenario must use the frozen controlled invalidation")
    return {key: change[key] for key in ("kind", "subject_id")}


def intervene_run(run, gateway, token_env):
    run, meta, workload = load_run(run, {"initialized"})
    snapshot = bound_snapshot(meta, gateway, token_env, allow_new_origin=True)
    prepare_barrier(snapshot, workload)
    save(run / "prepared_snapshot.json", snapshot)
    change = intervention(workload, meta["scenario"])
    meta.update(status="intervention_pending", prepared_at=utc(), attempted_gateway_origin=gateway_origin(gateway))
    save(run / "run_meta.json", meta)
    if change:
        event = {**change, "occurred_at": time.time(), "origin": "author-controlled intervention"}
        save(run / "intervention_intent.json", event)
        # An ambiguous request outcome cannot be automatically retried as a new
        # intervention. Retain intervention_pending and start a fresh case.
        reply = rpc(gateway, token_env, change["kind"], subject_id=change["subject_id"])
        event.update(reply=reply, acknowledged_at=time.time())
        save(run / "source_events.json", [event])
        if not reply.get("ok"):
            meta.update(status="intervention_failed", failure_reason=reply.get("reason", "unknown"))
            save(run / "run_meta.json", meta)
            raise ValueError("intervention was not admitted")
    meta.update(status="intervened", intervention_completed_at=utc(), gateway_origin=gateway_origin(gateway))
    save(run / "run_meta.json", meta)
    return {"status": meta["status"], "scenario": meta["scenario"], "settlement_may_start": True}


def cleanup_run(run, gateway, token_env, batch_size=32, max_batches=1, interval_ms=20):
    if not 1 <= batch_size <= 4096 or not 1 <= max_batches <= 1000 or not 0 <= interval_ms <= 10000:
        raise ValueError("cleanup requires bounded positive batch/count and interval 0..10000 ms")
    run, meta, _ = load_run(run, {"intervened"})
    bound_snapshot(meta, gateway, token_env)
    events = read(run / "cleanup_events.json")
    for number in range(max_batches):
        reply = rpc(gateway, token_env, "cleanup", batch_size=batch_size)
        events.append({"at_time": time.time(), "reply": reply})
        save(run / "cleanup_events.json", events)
        result = require_ok(reply, "cleanup")
        if not result["has_more"]:
            return {"status": "cleanup_drained", "has_more": False, "batches_this_call": number + 1}
        if number + 1 < max_batches:
            time.sleep(interval_ms / 1000)
    return {"status": "cleanup_remaining", "has_more": True, "batches_this_call": max_batches}


def completed_snapshot(snapshot, workload, events):
    _, settled, blocked = expected_cohorts(workload, events)
    states = snapshot["effects"]
    actual = {row["effect_id"]: row["state"] for row in states}
    expected = {**{eid: "settled" for eid in settled}, **{eid: "cancelled" for eid in blocked}}
    ledger = [row["effect_id"] for row in snapshot["ledger"]]
    if (len(states) != len(expected) or actual != expected or set(ledger) != settled or
            len(ledger) != len(set(ledger)) or snapshot["stages"] or snapshot["cleanup_queue"]):
        raise ValueError("execution or cleanup incomplete; snapshot retained without completing case")


def collect_run(run, gateway, token_env):
    run, meta, workload = load_run(run, {"intervened"})
    snapshot = bound_snapshot(meta, gateway, token_env)
    save(run / "gateway_snapshot.json", snapshot)
    completed_snapshot(snapshot, workload, read(run / "source_events.json"))
    (run / "workers").mkdir(exist_ok=True)
    meta.update(status="collected", snapshot_collected_at=utc())
    save(run / "run_meta.json", meta)
    return {"status": "collected", "next": "copy all declared worker output folders, then run audit"}


def audit_collected_run(run, workflow):
    run, meta, _ = load_run(run, {"collected"})
    workflow = Path(workflow)
    if sha(workflow / "workflow_manifest.json") != meta["workflow_manifest_sha256"]:
        raise ValueError("workflow manifest differs from initialization")
    workers = run / "workers"
    if not workers.is_dir() or {p.name for p in workers.iterdir() if p.is_dir()} != {str(i) for i in range(meta["workers"])}:
        raise ValueError("collect exactly the declared worker output directories first")
    for i in range(meta["workers"]):
        if not (workers / str(i) / f"journal_{i}.json").is_file():
            raise ValueError("missing declared worker journal")
    if workers.is_symlink() or any(path.is_symlink() for path in workers.rglob("*")):
        raise ValueError("worker evidence must contain ordinary copied files")
    try:
        # The unchanged formal-cohort auditor requires a completed execution
        # label. Supply it only in a disposable audit view of the collected
        # evidence. The durable run remains collected until all checks pass.
        with tempfile.TemporaryDirectory(prefix=".audit_view_", dir=run) as temporary:
            view = Path(temporary)
            for name in ("workload.json", "source_events.json", "gateway_snapshot.json"):
                shutil.copyfile(run / name, view / name)
            shutil.copytree(workers, view / "workers")
            candidate = dict(meta, status="completed", audit_view_only=True,
                             persistent_run_status_at_audit="collected")
            save(view / "run_meta.json", candidate)
            result = audit_run(view, workflow)
            if result.get("status") != "passed":
                raise AssertionError("independent audit did not pass")
    except Exception as error:
        save(run / "audit_failure.json", {"at": utc(), "type": type(error).__name__, "reason": str(error)})
        raise
    save(run / "independent_audit.json", result)
    meta.update(status="completed", audit_completed_at=utc(), independent_auditor_sha256=sha(CODE / "ghcn_release_audit.py"))
    save(run / "run_meta.json", meta)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="gateway-host initialization and fresh database bootstrap")
    init.add_argument("--run", type=Path, required=True)
    init.add_argument("--workflow", type=Path, required=True)
    init.add_argument("--scenario", choices=SCENARIOS, required=True)
    init.add_argument("--policy", choices=POLICIES, required=True)
    init.add_argument("--workers", type=int, required=True)
    for name in ("intervene", "cleanup", "collect"):
        command = commands.add_parser(name)
        command.add_argument("--run", type=Path, required=True)
        command.add_argument("--gateway", required=True)
        command.add_argument("--api-token-env", default="WASF_EXPERIMENT_TOKEN")
        if name == "cleanup":
            command.add_argument("--batch-size", type=int, default=32)
            command.add_argument("--max-batches", type=int, default=1)
            command.add_argument("--interval-ms", type=float, default=20)
    audit = commands.add_parser("audit")
    audit.add_argument("--run", type=Path, required=True)
    audit.add_argument("--workflow", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "init":
        result = init_run(args.run, args.workflow, args.scenario, args.policy, args.workers)
    else:
        with controller_lock(args.run):
            if args.command == "intervene":
                result = intervene_run(args.run, args.gateway, args.api_token_env)
            elif args.command == "cleanup":
                result = cleanup_run(args.run, args.gateway, args.api_token_env, args.batch_size, args.max_batches, args.interval_ms)
            elif args.command == "collect":
                result = collect_run(args.run, args.gateway, args.api_token_env)
            else:
                result = audit_collected_run(args.run, args.workflow)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
