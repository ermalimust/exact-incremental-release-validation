"""Open-loop scheduled arrivals with process workers, HTTP, and durable journals."""
from __future__ import annotations
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import time


def process_payload(effect: dict) -> dict:
    values = effect["input_values"]
    factor = effect["calibration_factor"]
    corrected = [value * factor for value in values]
    return {"effect_id": effect["effect_id"], "generation": effect["generation"],
            "samples": len(corrected), "sum": sum(corrected),
            "sum_squares": sum(value * value for value in corrected),
            "result_sha256": hashlib.sha256(json.dumps(corrected, separators=(",", ":")).encode()).hexdigest()}


def write_json(path: Path, value):
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(value, f, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    # Antivirus/indexing on Windows may briefly hold the destination open.
    # Retain atomic replacement; bounded retry never converts a failed write
    # into a successful journal update.
    for attempt in range(50):
        try:
            os.replace(temp, path)
            break
        except PermissionError:
            if attempt == 49:
                raise
            time.sleep(.01)


def read_json(path: Path):
    # Windows scanners may briefly deny an otherwise completed atomic file.
    # Retry access errors only: malformed evidence is never silently repaired.
    for attempt in range(100):
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except PermissionError:
            if attempt == 99:
                raise
            time.sleep(.01)


class Client:
    def __init__(self, host, port, worker, run_dir):
        self.host, self.port, self.worker = host, port, worker
        self.log = (run_dir / f"client_worker_{worker}.jsonl").open("a", encoding="utf-8")
        self.connection = None
        self.counter = 0

    def event(self, value):
        self.log.write(json.dumps({"worker_id":self.worker, **value}, sort_keys=True) + "\n")
        self.log.flush()

    def rpc(self, operation, log_effect_id="", attempt=0, **arguments):
        self.counter += 1
        request_id = f"worker-{self.worker}-{os.getpid()}-{self.counter}"
        body = json.dumps({"operation":operation, "arguments":arguments,
                           "actor_id":f"worker-{self.worker}", "request_id":request_id})
        start = time.perf_counter_ns()
        try:
            if self.connection is None:
                self.connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
            self.connection.request("POST", "/rpc", body, {"Content-Type":"application/json"})
            response = self.connection.getresponse()
            answer = json.loads(response.read())
        except (OSError, ValueError, http.client.HTTPException) as exc:
            if self.connection:
                self.connection.close()
            self.connection = None
            answer = {"ok":False,"reason":"transport_error","detail":type(exc).__name__}
        end = time.perf_counter_ns()
        self.event({"effect_id":log_effect_id, "operation":operation,"request_id":request_id,
                    "start_ns":start,"end_ns":end,"attempt":attempt,
                    "arguments":arguments, **answer})
        return answer


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--worker", type=int, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    run = args.run
    workload = read_json(run / "workload.json")
    meta = read_json(run / "run_meta.json")
    tasks = [e for i,e in enumerate(workload["effects"]) if i % workload["workers"] == args.worker and not e.get("cleanup_backlog")]
    work = run / "worker_state" / str(args.worker)
    for name in ("staged","published"):
        (work/name).mkdir(parents=True,exist_ok=True)
    journal_path = work / "journal.json"
    journal = read_json(journal_path) if journal_path.exists() else {}
    client = Client("127.0.0.1", args.port, args.worker, run)
    (run/f"ready_worker_{args.worker}").write_text(str(os.getpid()))
    deadline = time.monotonic() + 180
    while not (run/"start.json").exists():
        if time.monotonic() > deadline:
            raise TimeoutError("start barrier")
        time.sleep(.002)
    start = read_json(run/"start.json")
    pause = (start["start_perf_ns"] - time.perf_counter_ns()) / 1e9
    if pause > 0:
        time.sleep(pause)
    terminal = {"support_invalidated","support_expired","effect_cancelled","insufficient_funds"}

    def save():
        write_json(journal_path,journal)

    def prepare(effect):
        eid = effect["effect_id"]
        state = journal.setdefault(eid,{})
        if state.get("terminal"):
            return False
        if "task_start_ns" not in state:
            state["task_start_ns"] = start["start_perf_ns"] + int(effect.get("arrival_offset_ms", 0) * 1e6)
            client.event({"operation":"task_start","effect_id":eid,
                          "start_ns":state["task_start_ns"],"end_ns":time.perf_counter_ns(), "scheduled_arrival_ns":state["task_start_ns"]})
        compute_start = time.perf_counter_ns()
        payload = process_payload(effect)
        compute_end = time.perf_counter_ns()
        client.event({"operation":"task_compute","effect_id":eid,
                      "start_ns":compute_start,"end_ns":compute_end})
        if payload != effect["payload"]:
            raise AssertionError("computed payload differs from frozen declared result")
        write_json(work/"staged"/(eid+".json"),payload)
        state["processing_done_ns"] = time.perf_counter_ns()
        save()
        # A durable nonce is sufficient to resume without re-staging a possibly
        # committed effect. The final receipt decides whether publication occurs.
        if state.get("nonce"):
            return True
        for attempt in range(30):
            result = client.rpc("stage",eid,attempt,effect_id=eid,payload=payload)
            if result["ok"]:
                return True
            if result.get("reason") != "transport_error":
                block(effect, result.get("reason", "stage_failure"))
                return False
            time.sleep(.05)
        raise TimeoutError("stage transport retries exhausted")

    def block(effect, reason):
        eid = effect["effect_id"]
        journal[eid]["terminal"] = reason
        journal[eid]["end_ns"] = time.perf_counter_ns()
        (work/"staged"/(eid+".json")).unlink(missing_ok=True)
        client.event({"operation":"task_blocked","effect_id":eid,"reason":reason,
                      "start_ns":journal[eid]["task_start_ns"],"end_ns":journal[eid]["end_ns"]})
        save()

    def issue(effect, attempt=0):
        eid = effect["effect_id"]
        state = journal[eid]
        if state.get("nonce"):
            return True
        state.setdefault("first_issue_ns",time.perf_counter_ns())
        result = client.rpc("issue",eid,attempt,effect_id=eid,ttl=30.0)
        if result["ok"]:
            state["nonce"] = result["result"]
            save()
            marker = run/"worker_crash_triggered"
            if meta.get("worker_crash") and args.worker == 0 and not marker.exists():
                marker.write_text(eid)
                os._exit(92)
            return True
        if result.get("reason") in terminal:
            block(effect,result["reason"])
        return False

    def finish(effect, initial_issued=False):
        eid = effect["effect_id"]
        state = journal[eid]
        if state.get("terminal"):
            return
        for attempt in range(30):
            if not issue(effect,attempt):
                if state.get("terminal"):
                    return
                time.sleep(.05)
                continue
            if workload["mode"] == "load" and attempt == 0:
                time.sleep(workload["settlement_hold_ms"]/1000)
            extra = {}
            if meta.get("gateway_fault") and eid == workload["effects"][0]["effect_id"]:
                marker = run/"fault_request_sent"
                if not marker.exists():
                    marker.write_text(meta["gateway_fault"])
                    extra = {"fault_phase":meta["gateway_fault"],
                             "fault_marker":str((run/"gateway_fault_reached").resolve())}
            answer = client.rpc("settle",eid,attempt,nonce=state["nonce"],
                                expected_effect_id=eid,**extra)
            if answer["ok"]:
                state["receipt"] = answer["result"]
                state["terminal"] = "completed"
                state["end_ns"] = time.perf_counter_ns()
                staged = work/"staged"/(eid+".json")
                if staged.exists():
                    os.replace(staged,work/"published"/(eid+".json"))
                client.event({"operation":"task_complete","effect_id":eid,
                              "start_ns":state["task_start_ns"],"end_ns":state["end_ns"],
                              "first_issue_ns":state["first_issue_ns"],"result":answer["result"]})
                save()
                return
            reason = answer.get("reason","unknown")
            if reason in terminal:
                block(effect,reason)
                return
            if reason != "transport_error":
                state.pop("nonce",None)
                save()
            time.sleep(.02 if reason != "transport_error" else .05)
        state["terminal"] = "retry_exhausted"
        save()
        client.event({"operation":"task_incomplete","effect_id":eid,"reason":"retry_exhausted",
                      "start_ns":state["task_start_ns"],"end_ns":time.perf_counter_ns()})

    if workload["mode"] == "coordinated":
        for effect in tasks:
            if prepare(effect):
                issue(effect)
        (run/f"issued_worker_{args.worker}").write_text("issued")
        while not (run/"settle.flag").exists():
            if time.monotonic() > deadline:
                raise TimeoutError("settlement barrier")
            time.sleep(.002)
        for effect in tasks:
            if effect["effect_id"] in journal:
                finish(effect,True)
    else:
        for effect in tasks:
            due = start["start_perf_ns"] + int(effect.get("arrival_offset_ms", 0) * 1e6)
            pause = (due - time.perf_counter_ns()) / 1e9
            if pause > 0:
                time.sleep(pause)
            if prepare(effect):
                finish(effect)
    client.log.close()
    write_json(run/f"done_worker_{args.worker}.json",
               {"worker_id":args.worker,"pid":os.getpid(),"effects":len(tasks),
                "completed":sum(x.get("terminal")=="completed" for x in journal.values()),
                "incomplete":sum(x.get("terminal")=="retry_exhausted" for x in journal.values())})


if __name__ == "__main__":
    main()

