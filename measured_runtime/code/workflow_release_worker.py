"""Release prepared public-data workflow reports through a configurable gateway.

The scientific workflow must already have produced and verified its manifest.
This worker verifies real file bytes against the frozen payload before staging.
A receipt protects the ledger action; subsequent file publication is not part
of that database transaction. Independent hosts may use private networking or
an SSH tunnel and must receive the same frozen workflow/artifact files.
"""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit

from continuous_worker import write_json,read_json


def atomic_bytes(path,content):
    path.parent.mkdir(parents=True,exist_ok=True)
    temporary=path.with_suffix(path.suffix+".tmp")
    with temporary.open("wb") as f:
        f.write(content);f.flush();os.fsync(f.fileno())
    for attempt in range(50):
        try:
            os.replace(temporary,path)
            return
        except PermissionError:
            if attempt==49:raise
            time.sleep(.01)


class Client:
    def __init__(self,url,token=None):
        parts=urlsplit(url)
        if parts.scheme not in ("http","https"):
            raise ValueError("gateway must be an http(s) URL")
        self.host,self.port=parts.hostname,parts.port or (443 if parts.scheme=="https" else 80)
        self.secure=parts.scheme=="https"
        self.token,self.connection=token,None
    def call(self,operation,actor,**arguments):
        for attempt in range(40):
            started=time.perf_counter_ns()
            try:
                if self.connection is None:
                    klass=http.client.HTTPSConnection if self.secure else http.client.HTTPConnection
                    self.connection=klass(self.host,self.port,timeout=5)
                headers={"Content-Type":"application/json"}
                if self.token:headers["Authorization"]="Bearer "+self.token
                self.connection.request("POST","/rpc",json.dumps({"operation":operation,"arguments":arguments,
                                        "actor_id":actor,"request_id":f"{actor}-{started}"}),headers)
                answer=json.loads(self.connection.getresponse().read())
                answer["client_elapsed_ms"]=(time.perf_counter_ns()-started)/1e6
                return answer
            except (OSError,ValueError,http.client.HTTPException):
                if self.connection:self.connection.close()
                self.connection=None
                if attempt==39:raise
                time.sleep(.05)
    def close(self):
        if self.connection:self.connection.close()


def run(workload_path,artifact_root,output,gateway,worker=0,workers=1,phase="all",token=None):
    workload=read_json(Path(workload_path))
    artifact_root,output=Path(artifact_root).resolve(),Path(output)
    output.mkdir(parents=True,exist_ok=True)
    journal_path=output/f"journal_{worker}.json"
    journal=read_json(journal_path) if journal_path.exists() else {}
    client=Client(gateway,token)
    logs=[]
    for index,effect in enumerate(workload["effects"]):
        if index%workers!=worker:continue
        eid=effect["effect_id"]
        state=journal.setdefault(eid,{})
        name=hashlib.sha256(eid.encode()).hexdigest()+".json"
        stage,published=output/"staged"/name,output/"published"/name
        source=(artifact_root/effect["artifact_path"]).resolve()
        if not source.is_relative_to(artifact_root):
            raise ValueError("artifact path escaped workflow root")
        contents=source.read_bytes()
        if hashlib.sha256(contents).hexdigest()!=effect["payload"]["content_sha256"]:
            raise ValueError("manifest content hash mismatch")
        if json.loads(contents)!=effect["payload"]["result"]:
            raise ValueError("declared result differs from actual report")
        def request(operation,**arguments):
            answer=client.call(operation,f"workflow-{worker}",**arguments)
            logs.append({"operation":operation,"effect_id":eid,"at_time":time.time(),**answer})
            return answer
        if state.get("blocked"):continue
        if phase in ("prepare","all") and not state.get("nonce"):
            atomic_bytes(stage,contents)
            answer=request("stage",effect_id=eid,payload=effect["payload"])
            if answer["ok"]:answer=request("issue",effect_id=eid,ttl=300)
            if not answer["ok"]:
                state["blocked"]=answer.get("reason","unknown")
                stage.unlink(missing_ok=True)
            else:state["nonce"]=answer["result"]
            write_json(journal_path,journal)
        if phase in ("settle","all") and not state.get("blocked"):
            if not state.get("nonce"):
                raise ValueError("settlement phase requires a persisted nonce")
            answer=request("settle",nonce=state["nonce"],expected_effect_id=eid)
            if answer["ok"]:
                # Rebuild the same bytes after a restart if promotion had not
                # completed. Overwrite is idempotent by immutable content hash.
                atomic_bytes(published,contents)
                stage.unlink(missing_ok=True)
                state.update(receipt=answer["result"],published_sha256=hashlib.sha256(contents).hexdigest())
            else:
                state["blocked"]=answer.get("reason","unknown")
                stage.unlink(missing_ok=True)
            write_json(journal_path,journal)
    client.close()
    with (output/f"requests_{worker}_{phase}.jsonl").open("a",encoding="utf-8") as f:
        for row in logs:f.write(json.dumps(row,sort_keys=True)+"\n")
    return {"worker":worker,"phase":phase,"effects":len(journal),
            "settled":sum("receipt" in s for s in journal.values()),
            "blocked":sum("blocked" in s for s in journal.values())}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--workload",type=Path,required=True)
    p.add_argument("--artifact-root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--gateway",required=True)
    p.add_argument("--worker",type=int,default=0)
    p.add_argument("--workers",type=int,default=1)
    p.add_argument("--phase",choices=("prepare","settle","all"),default="all")
    p.add_argument("--api-token-env",default="WASF_EXPERIMENT_TOKEN")
    a=p.parse_args()
    if not 0<=a.worker<a.workers:raise ValueError("invalid worker assignment")
    print(json.dumps(run(a.workload,a.artifact_root,a.output,a.gateway,a.worker,a.workers,
                         a.phase,os.environ.get(a.api_token_env)),sort_keys=True))

