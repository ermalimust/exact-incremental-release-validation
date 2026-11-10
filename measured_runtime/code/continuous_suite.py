"""Open-loop release experiment with randomized DAGs and concurrent cleanup.

An arrival manifest, including topology and source notification times, is frozen
once per seed/configuration and shared by every policy. This remains a one-host
experiment. Source time is controlled by this driver, not an external oracle.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import platform
import random
import subprocess
import sys
import threading
import time

from distributed_worker import process_payload, read_json, write_json

CODE = Path(__file__).resolve().parent
POLICIES = ("full_sql", "guarded_full", "adaptive_delta")


def rpc(port, operation, actor="coordinator", **arguments):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.request("POST", "/rpc", json.dumps({"operation": operation,
            "arguments": arguments, "actor_id": actor,
            "request_id": f"{actor}-{time.perf_counter_ns()}"}),
            {"Content-Type": "application/json"})
        return json.loads(connection.getresponse().read())
    finally:
        connection.close()


def make_workload(config, seed):
    rng = random.Random(seed)
    warmup, measurement = config.get("warmup_s", 2), config.get("measurement_s", 8)
    duration = warmup + measurement
    rate = config.get("arrival_rate", 20)
    count = int(duration * rate)
    fanout = config["fanout"]
    # Support cardinality = backbone nodes + private sample + private approval.
    support_size = config["support_size"]
    if support_size < 4:
        raise ValueError("support_size must be at least four")
    registry = {"artifact_parents": {}, "artifact_obligations": {},
                "effect_artifacts": {}, "effect_obligations": {}}
    groups = math.ceil(count / fanout)
    roots = []
    # Every DAG node is an ancestor of its group's declared root. The mandatory
    # parent is drawn from earlier nodes; extra random edges vary topology.
    # Declaring all sinks includes disconnected branches without hidden support.
    for group in range(groups):
        nodes = [f"g{group}:evidence:{i}" for i in range(support_size - 2)]
        used_as_parent = set()
        for index, node in enumerate(nodes):
            parents = [] if not index else [nodes[rng.randrange(index)]]
            if index > 2:
                parents += rng.sample(nodes[:index], min(rng.randrange(3), index))
            parents = sorted(set(parents))
            registry["artifact_parents"][node] = parents
            registry["artifact_obligations"][node] = []
            used_as_parent.update(parents)
        roots.append([node for node in nodes if node not in used_as_parent])
    effects = []
    for index in range(count):
        group = (index // fanout)
        eid = f"publish-{index:05d}"
        sample = f"sample:{index}"
        registry["artifact_parents"][sample] = roots[group]
        registry["artifact_obligations"][sample] = []
        registry["effect_artifacts"][eid] = [sample]
        registry["effect_obligations"][eid] = [f"approval:{index}"]
        arrival = (index + rng.uniform(0, .8)) / rate
        task = {"effect_id": eid, "payer": "budget", "recipient": "sink", "amount": 1,
                "input_values": [rng.randrange(-1000, 1001) for _ in range(256)],
                "calibration_factor": group + 1, "generation": f"group:{group}:v1",
                "arrival_offset_ms": round(arrival * 1000, 6),
                "phase": "warmup" if arrival < warmup else "measurement"}
        task["payload"] = process_payload(task)
        effects.append(task)

    # A cleanup queue is separately pre-staged, never counted as arrivals or as
    # useful completed work. Its shared revoked root is outside arrival support.
    backlog = int(config.get("cleanup_backlog", 0))
    registry["artifact_parents"]["cleanup_root"] = []
    registry["artifact_obligations"]["cleanup_root"] = []
    for index in range(backlog):
        eid = f"backlog-{index:05d}"
        registry["effect_artifacts"][eid] = ["cleanup_root"]
        registry["effect_obligations"][eid] = []
        task = {"effect_id": eid, "payer": "budget", "recipient": "sink", "amount": 1,
                "input_values": [index, index + 1], "calibration_factor": 1,
                "generation": "cleanup:v1", "cleanup_backlog": True, "phase": "backlog"}
        task["payload"] = process_payload(task)
        effects.append(task)

    # Keep an independent nonmutating half-cohort. For each update choose a
    # currently arriving group or a registered but unrelated evidence identity.
    extra = [f"a:unrelated:{i}" for i in range(32)]
    events = []
    mutation_rate = config.get("mutation_rate", 2)
    for index in range(int(measurement * mutation_rate)):
        offset = warmup + (index + rng.uniform(.1, .9)) / mutation_rate
        active_group = min(groups - 1, int(offset * rate) // fanout)
        relevant = index % 2 == 0 and active_group % 2 == 0
        target = (f"a:g{active_group}:evidence:{rng.randrange(support_size-2)}" if relevant
                  else rng.choice(extra))
        events.append({"kind": "refresh", "subject_id": target,
                       "offset_ms": round(offset * 1000, 6), "planned_relation": "active" if relevant else "unrelated"})
    # Revocations target even groups at the beginning of their remaining
    # arrivals, so blocked denominators persist alongside independent progress.
    candidates = [g for g in range(groups) if g % 2 == 0 and warmup < g * fanout / rate < duration - .2]
    rng.shuffle(candidates)
    revoked = set()
    for group in candidates[:max(1, min(3, len(candidates)))]:
        target = f"a:g{group}:evidence:0"
        offset = group * fanout / rate + .08 + rng.uniform(0, .10)
        events.append({"kind": "invalidate", "subject_id": target,
                       "offset_ms": round(offset * 1000, 6), "planned_relation": "active"})
        revoked.add(target)
    # Do not schedule a later benign refresh of a permanently revoked identity.
    events = [event for event in events if event["kind"] != "refresh" or event["subject_id"] not in revoked]
    if backlog:
        events.append({"kind": "invalidate", "subject_id": "a:cleanup_root",
                       "offset_ms": (warmup + measurement * .3) * 1000, "planned_relation": "backlog"})
    events.sort(key=lambda item: item["offset_ms"])
    workload = {"schema_version": 2, "seed": seed, "config": config, "mode": "continuous",
        "workers": config.get("workers", 4), "registry": registry, "effects": effects,
        "accounts": {"budget": len(effects) * 10, "sink": 0}, "extra_subjects": extra,
        "expires_at": 4102444800.0, "stage_at_bootstrap": False, "settlement_hold_ms": 0,
        "source_event_plan": events, "warmup_s": warmup, "measurement_s": measurement,
        "arrival_count": count, "cleanup_backlog": backlog}
    return workload


def configurations(suite):
    base = {"workers": 4, "arrival_rate": 20, "warmup_s": 2, "measurement_s": 8,
            "notification_delay_ms": 0, "cleanup_backlog": 0, "cleanup_batch": 32,
            "history_limit": 4096, "delta_budget": 256}
    rows = [("small_sparse", 16, 4, 2, 0, 32),
            ("large_sparse", 512, 4, 2, 0, 32),
            ("large_shared", 512, 32, 2, 0, 32),
            ("large_dense", 512, 32, 40, 0, 32),
            ("cleanup_bounded", 512, 32, 2, 512, 32),
            ("cleanup_unbounded", 512, 32, 2, 512, None)]
    result = [{**base, "name": name, "support_size": support, "fanout": fanout,
               "mutation_rate": mutation, "cleanup_backlog": backlog, "cleanup_batch": batch}
              for name, support, fanout, mutation, backlog, batch in rows]
    if suite == "smoke":
        return [{**result[4], "name": "smoke", "support_size": 32, "fanout": 8,
                 "warmup_s": .5, "measurement_s": 2, "cleanup_backlog": 24,
                 "cleanup_batch": 4, "mutation_rate": 4}]
    return result


def run_one(output, config, seed, policy):
    from adaptive_gateway import bootstrap
    name = f"{config['name']}_s{seed}_{policy}"
    run = output / name
    run.mkdir(parents=True, exist_ok=False)
    workload = make_workload(config, seed)
    digest = hashlib.sha256(json.dumps(workload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    workload.update(run_id=name, common_input_sha256=digest)
    write_json(run / "workload.json", workload)
    meta = {"run_id": name, "policy": policy, "seed": seed, "config": config,
            "common_input_sha256": digest, "planned_source_events": workload["source_event_plan"],
            "physical_hosts": 1, "transport": "HTTP over 127.0.0.1", "status": "starting"}
    write_json(run / "run_meta.json", meta)
    db, ready = run / "gateway.sqlite", run / "gateway_ready.json"
    begin = time.perf_counter_ns()
    try:
        bootstrap(db, workload, policy, history_limit=config["history_limit"], delta_budget=config["delta_budget"])
    except BaseException as exc:
        meta.update(status="failed", error=f"bootstrap: {exc!r}", finished_ns=time.perf_counter_ns())
        write_json(run / "run_meta.json", meta)
        return meta
    meta["bootstrap_ms"] = (time.perf_counter_ns() - begin) / 1e6
    processes, logs, source, cleaning, errors = [], [], [], [], []
    stop = threading.Event()
    cleanup_wakeup = threading.Event()
    gateway = None
    port = None

    def wait(predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while not predicate():
            if gateway is not None and gateway.poll() is not None:
                raise RuntimeError(f"gateway exited {gateway.returncode}")
            if time.monotonic() > deadline:
                raise TimeoutError("continuous-suite barrier timeout")
            time.sleep(.005)

    def source_loop(started):
        try:
            for event in workload["source_event_plan"]:
                target = started + int(event["offset_ms"] * 1e6)
                remaining = (target - time.perf_counter_ns()) / 1e9
                if remaining > 0 and stop.wait(remaining):
                    return
                occurred_at, occurred_ns = time.time(), time.perf_counter_ns()
                delay = config.get("notification_delay_ms", 0)
                if delay:
                    time.sleep(delay / 1000)
                answer = rpc(port, event["kind"], actor="source", subject_id=event["subject_id"])
                source.append({**event, "occurred_at": occurred_at, "occurred_ns": occurred_ns,
                    "admitted_reply_at": time.time(), "admitted_reply_ns": time.perf_counter_ns(),
                    "injected_notification_delay_ms": delay, "response": answer})
                if not answer["ok"]:
                    raise RuntimeError(f"source admission failed: {answer}")
                if event["kind"] == "invalidate":
                    cleanup_wakeup.set()
        except BaseException as exc:
            errors.append(repr(exc))

    def cleanup_loop(started):
        # Cleanup is triggered by acknowledged invalidation, not empty polling
        # writer transactions. Each batch releases the writer before the next.
        try:
            while not stop.is_set():
                if not cleanup_wakeup.wait(.05):
                    continue
                cleanup_wakeup.clear()
                while not stop.is_set():
                    begin = time.perf_counter_ns()
                    answer = rpc(port, "cleanup", actor="cleaner", batch_size=config["cleanup_batch"])
                    cleaning.append({"start_ns": begin, "end_ns": time.perf_counter_ns(), "response": answer})
                    if not answer["ok"]:
                        raise RuntimeError(f"cleanup failed: {answer}")
                    if not answer["result"].get("has_more", False):
                        break
        except BaseException as exc:
            errors.append(f"cleanup loop: {exc!r}")

    threads = []
    try:
        logfile = (run / "gateway.log").open("ab")
        logs.append(logfile)
        gateway = subprocess.Popen([sys.executable, str(CODE / "adaptive_gateway.py"), "--db", str(db),
            "--policy", policy, "--ready-file", str(ready), "--port", "0"],
            stdout=logfile, stderr=subprocess.STDOUT, cwd=CODE.parent)
        wait(lambda: ready.exists(), 30)
        port = read_json(ready)["port"]
        # Pre-staging the backlog is setup; its deletion overlaps measured work.
        for effect in workload["effects"]:
            if effect.get("cleanup_backlog"):
                answer = rpc(port, "stage", effect_id=effect["effect_id"], payload=effect["payload"])
                if not answer["ok"]:
                    raise RuntimeError(f"backlog stage failed: {answer}")
        for worker in range(workload["workers"]):
            logfile = (run / f"worker_{worker}.log").open("ab")
            logs.append(logfile)
            processes.append(subprocess.Popen([sys.executable, str(CODE / "continuous_worker.py"),
                "--run", str(run), "--worker", str(worker), "--port", str(port)],
                stdout=logfile, stderr=subprocess.STDOUT, cwd=CODE.parent))
        wait(lambda: all((run / f"ready_worker_{i}").exists() for i in range(workload["workers"])))
        started = time.perf_counter_ns() + 100_000_000
        meta.update(started_ns=started, start_epoch=time.time() + .1, status="running", gateway_port=port,
                    measurement_start_ns=started + int(workload["warmup_s"] * 1e9),
                    measurement_end_ns=started + int((workload["warmup_s"] + workload["measurement_s"]) * 1e9))
        write_json(run / "run_meta.json", meta)
        write_json(run / "start.json", {"start_perf_ns": started})
        for function in (source_loop, cleanup_loop):
            thread = threading.Thread(target=function, args=(started,), daemon=True)
            thread.start()
            threads.append(thread)
        wait(lambda: all((run / f"done_worker_{i}.json").exists() for i in range(workload["workers"])),
             timeout=workload["warmup_s"] + workload["measurement_s"] + 60)
        meta["workers_finished_ns"] = time.perf_counter_ns()
        threads[0].join(timeout=60)
        if threads[0].is_alive():
            raise TimeoutError("source injector did not finish")
        stop.set()
        threads[1].join(timeout=30)
        if threads[1].is_alive():
            raise TimeoutError("cleanup thread did not stop")
        if errors:
            raise RuntimeError("; ".join(errors))
        # Drain cleanup to verify no invalid staged payload survives the run.
        for _ in range(len(workload["effects"]) + 1):
            answer = rpc(port, "cleanup", actor="drain-cleaner", batch_size=config["cleanup_batch"])
            if not answer["ok"]:
                raise RuntimeError(f"cleanup drain failed: {answer}")
            if not answer["result"].get("has_more", False):
                break
        snapshot = rpc(port, "inspect")
        if not snapshot["ok"]:
            raise RuntimeError(f"snapshot failed: {snapshot}")
        write_json(run / "server_snapshot.json", snapshot["result"])
        meta.update(status="completed", finished_ns=time.perf_counter_ns(),
                    worker_pids=[read_json(run / f"done_worker_{i}.json")["pid"] for i in range(workload["workers"])])
    except BaseException as exc:
        meta.update(status="failed", error=repr(exc), finished_ns=time.perf_counter_ns())
    finally:
        stop.set()
        for thread in threads:
            thread.join(timeout=2)
        for process in processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
        if gateway is not None:
            if gateway.poll() is None:
                gateway.terminate()
            gateway.wait(timeout=10)
        for logfile in logs:
            logfile.close()
        meta["worker_exit_codes"] = [process.returncode for process in processes]
        write_json(run / "run_meta.json", meta)
        with (run / "client_events.jsonl").open("w", encoding="utf-8") as target:
            for path in sorted(run.glob("client_worker_*.jsonl")):
                target.write(path.read_text(encoding="utf-8"))
        for filename, records in (("source_events.jsonl", source), ("cleanup_events.jsonl", cleaning)):
            with (run / filename).open("w", encoding="utf-8") as target:
                for record in records:
                    target.write(json.dumps(record, sort_keys=True) + "\n")
    return meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--suite", choices=("smoke", "main"), default="smoke")
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--policies", nargs="+", choices=POLICIES, default=list(POLICIES))
    parser.add_argument("--configs", nargs="+")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "suite_manifest.json").exists():
        raise FileExistsError("Refusing to replace an existing experiment manifest")
    configs = [config for config in configurations(args.suite) if not args.configs or config["name"] in args.configs]
    if not configs:
        raise ValueError("no matching configurations")
    seeds = list(range(20261027, 20261027 + args.seeds))
    manifest = {"suite": args.suite, "requested_runs": len(configs) * len(seeds) * len(args.policies),
        "policies": args.policies, "seeds": seeds, "configurations": configs, "runs": [],
        "python": sys.version, "platform": platform.platform(), "processor": platform.processor(),
        "cpu_logical": os.cpu_count(), "physical_hosts": 1,
        "scope": "independent process workers and HTTP loopback; centralized SQLite writer",
        "source_hashes": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in
            (CODE / "continuous_suite.py", CODE / "continuous_worker.py", CODE / "adaptive_gateway.py",
             CODE / "durable_gateway.py", CODE / "distributed_worker.py", CODE / "network_gateway.py",
             CODE / "persistent_workflow.py", CODE / "integrated_controller.py")}}
    write_json(output / "suite_manifest.json", manifest)
    for config in configs:
        for seed in seeds:
            policies = list(args.policies)
            random.Random(seed + sum(map(ord, config["name"]))).shuffle(policies)
            for policy in policies:
                changed = [name for name, expected in manifest["source_hashes"].items()
                           if hashlib.sha256((CODE/name).read_bytes()).hexdigest() != expected]
                if changed:
                    manifest["aborted_reason"] = "runtime changed during cohort: " + ", ".join(changed)
                    write_json(output / "suite_manifest.json", manifest)
                    raise RuntimeError(manifest["aborted_reason"])
                result = run_one(output, config, seed, policy)
                manifest["runs"].append({key: result[key] for key in ("run_id", "status")})
                write_json(output / "suite_manifest.json", manifest)
                print(json.dumps({"progress": len(manifest["runs"]), "total": manifest["requested_runs"],
                    "run_id": result["run_id"], "status": result["status"], "error": result.get("error")}), flush=True)
                if result["status"] != "completed":
                    raise RuntimeError("Failed run retained; inspect before starting another cohort")


if __name__ == "__main__":
    main()
