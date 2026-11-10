"""Sequential one-host service cohort that crosses the retained-history limit.

The existing open-loop workload, worker, transport and independent oracle are
reused. This driver changes only predeclared load/duration/retention parameters.
No performance measurement may overlap another benchmark or build.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import statistics
import sys

from continuous_suite import CODE, POLICIES, configurations, run_one
from distributed_worker import write_json


def history_observation(run: Path, config: dict, policy: str) -> dict:
    snapshot = json.loads((run / "server_snapshot.json").read_text(encoding="utf-8"))
    source = [json.loads(line) for line in (run / "source_events.jsonl").read_text(encoding="utf-8").splitlines() if line]
    final_sequence = snapshot["adaptive_metadata"]["mutation_sequence"]
    if final_sequence != len(source):
        raise AssertionError("Mutation ordinal cannot identify pruning phase")
    admitted = [row for row in snapshot["audit"] if row["kind"] in ("refresh", "invalidate", "extend")]
    if len(admitted) != len(source):
        raise AssertionError("Unexpected admitted mutation outside the source plan")
    phases = {"before_limit": [], "after_limit": []}
    for ordinal, row in enumerate(source, 1):
        audit = admitted[ordinal - 1]
        payload = audit["payload"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if (payload["global_epoch"] != ordinal or audit["kind"] != row["kind"]
                or audit["subject_id"] != row["subject_id"]):
            raise AssertionError("Source ordering differs from admitted sequence")
        if not row["response"]["ok"]:
            raise AssertionError("Unacknowledged planned mutation")
        if row["kind"] == "refresh":
            phase = "before_limit" if ordinal <= config["history_limit"] else "after_limit"
            phases[phase].append(row["response"]["metrics"]["mutation_log_ms"])
    retained = len(snapshot["mutation_history"])
    floor = snapshot["adaptive_metadata"]["pruned_through"]
    if final_sequence <= 3 * config["history_limit"]:
        raise AssertionError("Cohort did not admit three retained-history capacities")
    if policy == "adaptive_delta":
        assert retained == config["history_limit"]
        assert floor == final_sequence - config["history_limit"]
    else:
        assert retained == floor == 0
    result = {
        "status": "passed", "policy": policy, "mutations": final_sequence,
        "history_limit": config["history_limit"], "retained_rows": retained,
        "pruned_through": floor,
        "history_capacities_admitted": final_sequence / config["history_limit"],
        "history_capacities_deleted": floor / config["history_limit"],
        "phase_definition": "Admitted mutation ordinal; all refresh/invalidation events advance the same sequence. Only refresh log intervals are summarized.",
        "refresh_history_component": {
            phase: {"n": len(values), "sum_ms": sum(values),
                    "mean_ms": statistics.fmean(values) if values else None}
            for phase, values in phases.items()},
        "scope": "History maintenance component, not full CPU or end-to-end service cost; complete service statistics use the independent continuous analysis."
    }
    write_json(run / "history_observation.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", type=int, default=5)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    base = next(item for item in configurations("main") if item["name"] == "large_dense")
    config = {**base, "name": "retention120s_u40_h1024", "measurement_s": 120,
              "mutation_rate": 40, "history_limit": 1024}
    if args.smoke:
        config.update(name="retention_smoke", measurement_s=2, warmup_s=.5,
                      mutation_rate=40, history_limit=16, support_size=16,
                      fanout=8, arrival_rate=10, workers=2)
    seeds = list(range(20261109, 20261109 + args.seeds))
    dependencies = ("retention_suite.py", "continuous_suite.py", "continuous_worker.py",
                    "adaptive_gateway.py", "durable_gateway.py", "distributed_worker.py",
                    "network_gateway.py", "persistent_workflow.py", "integrated_controller.py")
    hashes = {name: hashlib.sha256((CODE / name).read_bytes()).hexdigest() for name in dependencies}
    manifest = {"suite": "retention_service", "requested_runs": len(seeds) * len(POLICIES),
                "policies": list(POLICIES), "seeds": seeds, "configurations": [config],
                "runs": [], "source_hashes": hashes, "python": sys.version,
                "platform": platform.platform(), "cpu_logical": os.cpu_count(),
                "physical_hosts": 1, "scope": "Fixed offered load over multiple retained-history capacities; not a maximum-capacity or multi-host test"}
    write_json(output / "suite_manifest.json", manifest)
    for seed in seeds:
        policies = list(POLICIES)
        random.Random(seed + 91837).shuffle(policies)
        for policy in policies:
            for name, digest in hashes.items():
                if hashlib.sha256((CODE / name).read_bytes()).hexdigest() != digest:
                    raise RuntimeError("Frozen measurement source changed: " + name)
            result = run_one(output, config, seed, policy)
            manifest["runs"].append({key: result[key] for key in ("run_id", "status")})
            write_json(output / "suite_manifest.json", manifest)
            if result["status"] != "completed":
                raise RuntimeError("Failed run retained: " + json.dumps({key: result.get(key) for key in ("run_id", "status", "error")}))
            observation = history_observation(output / result["run_id"], config, policy)
            print(json.dumps({"progress": len(manifest["runs"]), "total": manifest["requested_runs"],
                              "run_id": result["run_id"], "status": result["status"],
                              "history_mutations": observation["mutations"],
                              "pruned_through": observation["pruned_through"]}), flush=True)


if __name__ == "__main__":
    main()
