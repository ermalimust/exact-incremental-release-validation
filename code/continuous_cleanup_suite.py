"""Follow-up cleanup stress with healthy, root-disjoint scheduled arrivals.

This separately declared cohort follows the zero-overlap 512-backlog matrix.
Only the workload factory and setup-stage connection reuse are adapted. The
release workers, gateway, runtime coordinator, and measured RPCs are unchanged.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import random
import sys
import time

import continuous_suite as runtime
from distributed_worker import write_json
from distributed_analysis import complete_supports

ORIGINAL_FACTORY = runtime.make_workload
ORIGINAL_RPC = runtime.rpc


def stress_workload(config, seed):
    workload = ORIGINAL_FACTORY(config, seed)
    for event in workload["source_event_plan"]:
        if event["subject_id"] == "a:cleanup_root":
            event["offset_ms"] = 6000.0
    workload["source_event_plan"].sort(key=lambda row:row["offset_ms"])
    supports = complete_supports(workload["registry"])
    changed = {row["subject_id"] for row in workload["source_event_plan"]}
    healthy = [row for row in workload["effects"] if not row.get("cleanup_backlog")
        and 6000 <= row["arrival_offset_ms"] < 6400]
    if len(healthy) != 8 or any(supports[row["effect_id"]] & changed for row in healthy):
        raise ValueError("stress phase must begin during eight scheduled mutation-disjoint arrivals")
    workload["cleanup_phase_contract"] = {"backlog_invalidation_offset_ms":6000,
        "healthy_arrival_interval_ms":[6000,6400],"healthy_scheduled_effects":[row["effect_id"] for row in healthy],
        "reason":"separate follow-up to zero successful root-disjoint overlap in original 512-backlog cohort"}
    return workload


class SetupStageConnection:
    """Reuse one setup-only HTTP connection; no measured request uses this path."""
    def __init__(self):
        self.connection, self.port = None, None

    def close(self):
        if self.connection is not None:
            self.connection.close()
        self.connection, self.port = None, None

    def __call__(self, port, operation, actor="coordinator", **arguments):
        if operation != "stage" or actor != "coordinator":
            return ORIGINAL_RPC(port,operation,actor=actor,**arguments)
        if self.port != port:
            self.close()
            self.connection = http.client.HTTPConnection("127.0.0.1",port,timeout=30)
            self.port = port
        self.connection.request("POST","/rpc",json.dumps({"operation":operation,"arguments":arguments,
            "actor_id":"setup-stager","request_id":f"setup-{time.perf_counter_ns()}"}),
            {"Content-Type":"application/json"})
        return json.loads(self.connection.getresponse().read())


def configurations():
    base=next(row for row in runtime.configurations("main") if row["name"]=="cleanup_bounded")
    return [{**base,"name":f"cleanup{backlog}_{mode}","cleanup_backlog":backlog,
             "cleanup_batch":batch,"setup_stage_transport":"persistent HTTP connection; outside measurement"}
        for backlog in (4096,16384) for mode,batch in (("bounded",32),("unbounded",None))]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--seeds",type=int,default=3)
    args=parser.parse_args()
    output=args.output.resolve()
    output.mkdir(parents=True,exist_ok=True)
    if (output/"suite_manifest.json").exists():
        raise FileExistsError("Refusing to replace an existing stress cohort")
    configs=configurations()
    seeds=list(range(20261027,20261027+args.seeds))
    dependencies=("continuous_cleanup_suite.py","continuous_suite.py","continuous_worker.py",
        "adaptive_gateway.py","durable_gateway.py","distributed_worker.py","network_gateway.py",
        "persistent_workflow.py","integrated_controller.py")
    manifest={"suite":"cleanup_stress","requested_runs":len(configs)*len(seeds),
        "policies":["adaptive_delta"],"seeds":seeds,"configurations":configs,"runs":[],
        "python":sys.version,"platform":platform.platform(),"processor":platform.processor(),
        "cpu_logical":os.cpu_count(),"physical_hosts":1,
        "scope":"follow-up to original zero-overlap result; processed batch bound plus one lookahead row; three exploratory seeds",
        "source_hashes":{name:hashlib.sha256((runtime.CODE/name).read_bytes()).hexdigest() for name in dependencies}}
    write_json(output/"suite_manifest.json",manifest)
    connection=SetupStageConnection()
    runtime.make_workload=stress_workload
    runtime.rpc=connection
    try:
        for backlog in (4096,16384):
            matching=[row for row in configs if row["cleanup_backlog"]==backlog]
            for seed in seeds:
                order=list(matching)
                random.Random(seed+backlog).shuffle(order)
                for config in order:
                    changed=[name for name,expected in manifest["source_hashes"].items()
                        if hashlib.sha256((runtime.CODE/name).read_bytes()).hexdigest()!=expected]
                    if changed:
                        manifest["aborted_reason"]="runtime changed: "+", ".join(changed)
                        write_json(output/"suite_manifest.json",manifest)
                        raise RuntimeError(manifest["aborted_reason"])
                    result=runtime.run_one(output,config,seed,"adaptive_delta")
                    connection.close()
                    manifest["runs"].append({key:result[key] for key in ("run_id","status")})
                    write_json(output/"suite_manifest.json",manifest)
                    print(json.dumps({"progress":len(manifest["runs"]),"total":manifest["requested_runs"],
                        "run_id":result["run_id"],"status":result["status"],"error":result.get("error")}),flush=True)
                    if result["status"]!="completed":
                        raise RuntimeError("Failed stress run retained")
    finally:
        connection.close()
        runtime.make_workload=ORIGINAL_FACTORY
        runtime.rpc=ORIGINAL_RPC


if __name__=="__main__":
    main()
