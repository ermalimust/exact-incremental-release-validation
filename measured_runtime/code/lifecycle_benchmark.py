"""Paired complete release-lifecycle costs, including mutation maintenance.

Runs are serial direct calls on one persistent connection. No sleep, HTTP or
synthetic validator cost is introduced. Upstream scientific ETL is a frozen
input, not part of the timed release lifecycle. Workflow manifest validation,
support compilation and DB registration are reported as one-time setup; actual
report reads, stage/issue, admitted updates, settlement, file publication and
cleanup are in the operational window. Report writing and independent audit
are outside both windows. Full wall/process-CPU windows are not constructed by
adding nested instrumentation. Per-operation writer times sum distinct txns.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from contextlib import closing
import csv
import hashlib
import itertools
import json
import math
import os
from pathlib import Path
import platform
import random
import sqlite3
import statistics
import sys
import time

from adaptive_gateway import AdaptiveGateway, POLICIES
from durable_gateway import GateRejected
from integrated_controller import Registry
from persistent_workflow import compile_registry
from ghcn_workflow import compile_workload
from ghcn_release_audit import (supports_from_manifest_registry,
    check_registry_against_file_manifests, check_release_bindings)
from ghcn_oracle import verify as verify_scientific_outputs
from workflow_release_worker import atomic_bytes

CODE = Path(__file__).resolve().parent
DEPENDENCIES = ("lifecycle_benchmark.py", "adaptive_gateway.py", "network_gateway.py",
                "durable_gateway.py", "persistent_workflow.py", "integrated_controller.py",
                "ghcn_workflow.py", "ghcn_release_audit.py", "ghcn_oracle.py",
                "workflow_release_worker.py", "continuous_worker.py")
WORKFLOW_SCENARIOS = ("all_valid", "unrelated_refresh", "benign_shared_refresh",
                      "baseline_withdrawal")


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2,
                                   ensure_ascii=False, allow_nan=False)+"\n", encoding="utf-8")


def source_hashes():
    return {name: hashlib.sha256((CODE/name).read_bytes()).hexdigest() for name in DEPENDENCIES}


def snapshot_clock():
    return time.perf_counter_ns(), time.process_time_ns()


def elapsed(start, end):
    return {"wall_ms": (end[0]-start[0])/1e6, "cpu_ms": (end[1]-start[1])/1e6}


class Recorder:
    def __init__(self):
        self.rows = []

    def call(self, phase, fn, *, gate=None, effect_id=None, subject_id=None, allow_denial=False):
        start = snapshot_clock()
        value, reason = None, None
        try:
            value = fn()
        except GateRejected as error:
            if not allow_denial:
                raise
            reason = error.reason
        end = snapshot_clock()
        row = {"operation_index": len(self.rows), "phase": phase,
               "effect_id": effect_id, "subject_id": subject_id,
               "accepted": reason is None, "reason": reason, **elapsed(start, end)}
        if gate is not None:
            row["gateway"] = dict(gate.last_metrics)
        self.rows.append(row)
        return value, reason


def synthetic_plan(seed, support_size=512, ratio=1.0, epochs=4, group_size=16):
    updates = group_size/ratio
    if support_size < 1 or epochs < 1 or group_size < 1 or ratio <= 0 or not updates.is_integer():
        raise ValueError("positive dimensions and integral updates per epoch required")
    updates = int(updates)
    rng = random.Random(seed)
    artifacts = [f"support:{i:05d}" for i in range(support_size)]
    unrelated = [f"o:unrelated:{i:03d}" for i in range(16)]
    effects = []
    for i in range(epochs*group_size):
        eid = f"release:{i:05d}"
        effects.append({"effect_id": eid, "payer": "payer", "recipient": "sink", "amount": 1,
                        "payload": {"effect_id": eid, "seed": seed,
                                    "content_sha256": hashlib.sha256(f"{seed}:{i}".encode()).hexdigest()}})
    rng.shuffle(effects)
    registry = {"artifact_parents": {a: [] for a in artifacts}, "artifact_obligations": {},
                "effect_artifacts": {e["effect_id"]: artifacts for e in effects}, "effect_obligations": {}}
    schedule = []
    for i in range(epochs):
        targets = [rng.choice(["a:"+a for a in artifacts] if (i*updates+j) % 2 == 0 else unrelated)
                   for j in range(updates)]
        schedule.append({"effects": [e["effect_id"] for e in effects[i*group_size:(i+1)*group_size]],
                         "mutations": [{"kind": "refresh", "subject_id": s, "deadline": 1_000_000.0}
                                       for s in targets]})
    return {"family": "synthetic", "name": f"k{support_size}_ratio{ratio:g}", "seed": seed,
            "config": {"support_size": support_size, "release_update_ratio": ratio,
                       "epochs": epochs, "releases_per_epoch": group_size,
                       "updates_per_epoch": updates, "scenario": "alternating_benign_related_unrelated",
                       "related_updates": (epochs*updates+1)//2,
                       "unrelated_updates": epochs*updates//2},
            "workload": {"registry": registry, "effects": effects,
                         "accounts": {"payer": epochs*group_size+100, "sink": 0},
                         "extra_subjects": unrelated}, "schedule": schedule,
            "initial_deadline": 1_000_000.0, "ttl": 1000.0}


def workflow_plan(workflow, seed, scenario):
    if scenario not in (*WORKFLOW_SCENARIOS, "deadline_extension", "deadline_shortening"):
        raise ValueError("unknown workflow scenario")
    workflow = Path(workflow).resolve()
    manifest = json.loads((workflow/"workflow_manifest.json").read_text(encoding="utf-8"))
    workload = json.loads((workflow/"compatible_workload.json").read_text(encoding="utf-8"))
    # Independent adapter-to-registry and effect-to-report checks are outside timing.
    check_registry_against_file_manifests(workload["registry"], manifest)
    check_release_bindings(workload, manifest, workflow)
    ids = sorted(e["effect_id"] for e in workload["effects"])
    random.Random(seed).shuffle(ids)
    quality = "a:"+next(a for a in workload["registry"]["artifact_parents"] if a.startswith("policy:quality@"))
    unrelated = "o:unrelated_dataset_approval"
    mutation = []
    if scenario == "unrelated_refresh":
        mutation = [{"kind": "refresh", "subject_id": unrelated, "deadline": 1_000_000.0}]
    elif scenario == "benign_shared_refresh":
        mutation = [{"kind": "refresh", "subject_id": quality, "deadline": 1_000_000.0}]
    elif scenario == "baseline_withdrawal":
        mutation = [{"kind": "invalidate", "subject_id": workload["controlled_revocation"]["subject_id"]}]
    elif scenario == "deadline_extension":
        mutation = [{"kind": "refresh", "subject_id": quality, "deadline": 50.0}]
    elif scenario == "deadline_shortening":
        mutation = [{"kind": "refresh", "subject_id": quality, "deadline": 3.0}]
    deadline_overrides = {quality: 5.0} if scenario == "deadline_extension" else {}
    return {"family": "workflow", "name": scenario, "seed": seed,
            "config": {"scenario": scenario, "report_count": len(ids),
                       "support_size_range": workload["support_size_range"]},
            "workload": {**workload, "extra_subjects": [unrelated]},
            "schedule": [{"effects": ids, "mutations": mutation,
                          "settle_at": 6.0 if scenario == "deadline_extension" else
                                       4.0 if scenario == "deadline_shortening" else 3.0}],
            "initial_deadline": 1_000_000.0, "deadline_overrides": deadline_overrides,
            "post_settlement_invalidation": quality if scenario == "deadline_shortening" else None,
            "ttl": 1000.0, "workflow_root": str(workflow), "file_manifest": manifest}


def compile_plan(plan):
    workload = plan["workload"]
    if plan["family"] == "workflow":
        # Includes file verification/role schema checks; excludes upstream ETL.
        compiled = compile_workload(plan["file_manifest"], Path(plan["workflow_root"]))
        if compiled["registry"] != workload["registry"] or compiled["effects"] != workload["effects"]:
            raise AssertionError("frozen input differs from actual manifest compilation")
    declaration, supports = compile_registry(Registry(**workload["registry"]))
    return declaration, supports


def register(gate, plan, declaration, supports):
    workload = plan["workload"]
    subjects = sorted(set().union(*map(set, supports.values())) | set(workload.get("extra_subjects", [])))
    deadlines = {s: float(plan.get("deadline_overrides", {}).get(s, plan["initial_deadline"])) for s in subjects}
    with gate._transaction():
        gate.db.executemany("INSERT INTO accounts VALUES (?,?)", sorted(workload["accounts"].items()))
        gate.db.executemany("INSERT INTO subjects VALUES (?,0,1,?)", sorted(deadlines.items()))
        for e in workload["effects"]:
            gate.db.execute("INSERT INTO effects VALUES (?,0,?,?,?,NULL,'pending')",
                            (e["effect_id"], e["payer"], e["recipient"], e["amount"]))
            gate.db.executemany("INSERT INTO effect_support VALUES (?,?)",
                                ((e["effect_id"], sid) for sid in supports[e["effect_id"]]))
        initial = {"registry": declaration, "supports": supports, "subject_expiries": deadlines,
                   "accounts": workload["accounts"], "effects": workload["effects"],
                   "expires_at": plan["initial_deadline"]}
        gate.db.execute("UPDATE network_meta SET workload=? WHERE singleton=1", (canonical(initial).decode(),))
        gate._audit("bootstrap", gate._time(None), initial=initial, policy=gate.policy)


def prepare_report(plan, effect, run):
    eid = effect["effect_id"]
    if plan["family"] == "workflow":
        root = Path(plan["workflow_root"])
        source = (root/effect["artifact_path"]).resolve()
        if not source.is_relative_to(root):
            raise ValueError("report path escapes input root")
        content = source.read_bytes()
        if hashlib.sha256(content).hexdigest() != effect["payload"]["content_sha256"]:
            raise AssertionError("report bytes no longer match input manifest")
        if json.loads(content) != effect["payload"]["result"]:
            raise AssertionError("report content differs from declared payload")
        atomic_bytes(run/"staged_files"/(hashlib.sha256(eid.encode()).hexdigest()+".json"), content)
        return effect["payload"], content
    # Deterministic fixed-size payload preparation, not artificial compute cost.
    payload = json.loads(canonical(effect["payload"]))
    return payload, None


def publish_report(plan, eid, content, run):
    if plan["family"] != "workflow":
        return
    name = hashlib.sha256(eid.encode()).hexdigest()+".json"
    atomic_bytes(run/"published"/name, content)
    (run/"staged_files"/name).unlink()


def expected_decision_events(plan):
    """Derive exact intervention/settlement coverage from the frozen input plan."""
    effect_ids = [effect["effect_id"] for effect in plan["workload"]["effects"]]
    scheduled = [eid for batch in plan["schedule"] for eid in batch["effects"]]
    if len(set(effect_ids)) != len(effect_ids) or Counter(scheduled) != Counter(effect_ids):
        raise AssertionError("planned effects must each have exactly one settlement")
    events = []
    for epoch, batch in enumerate(plan["schedule"]):
        mutation_at = 2.0+epoch*10
        for mutation in batch["mutations"]:
            if mutation["kind"] not in ("refresh", "invalidate"):
                raise AssertionError("unknown planned mutation")
            event = {"kind": mutation["kind"], "subject_id": mutation["subject_id"], "at": mutation_at}
            if mutation["kind"] == "refresh":
                event["deadline"] = mutation["deadline"]
            events.append(event)
        settle_at = batch.get("settle_at", 3.0+epoch*10)
        events.extend({"kind": "settle", "effect_id": eid, "at": settle_at} for eid in batch["effects"])
        if plan.get("post_settlement_invalidation"):
            events.append({"kind": "invalidate", "subject_id": plan["post_settlement_invalidation"], "at": settle_at})
    return events


def audit_run(plan, db_path, decisions, run):
    """Independently verify planned event coverage, current predicates and bindings."""
    observed = []
    for event in decisions:
        if event.get("kind") == "settle":
            if not isinstance(event.get("accepted"), bool):
                raise AssertionError("planned event settlement requires a Boolean outcome")
            observed.append({key: value for key, value in event.items() if key != "accepted"})
        else:
            observed.append(event)
    if observed != expected_decision_events(plan):
        raise AssertionError("planned event order or coverage differs from decision log")
    supports = supports_from_manifest_registry(plan["workload"]["registry"])
    state = {sid: [True, float(plan.get("deadline_overrides", {}).get(sid, plan["initial_deadline"]))]
             for sid in set().union(*map(set, supports.values())) | set(plan["workload"].get("extra_subjects", []))}
    expected, blocked = set(), set()
    for event in decisions:
        if event["kind"] == "refresh":
            if not state[event["subject_id"]][0]:
                raise AssertionError("refresh of invalid source in test plan")
            state[event["subject_id"]][1] = event["deadline"]
        elif event["kind"] == "invalidate":
            state[event["subject_id"]][0] = False
        else:
            eid, at = event["effect_id"], event["at"]
            should = all(state[s][0] and at < state[s][1] for s in supports[eid])
            if should != event["accepted"]:
                raise AssertionError(f"independent admissibility mismatch: {eid}")
            (expected if should else blocked).add(eid)
    with closing(sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True)) as db:
        db.row_factory = sqlite3.Row
        ledgers = [dict(row) for row in db.execute("SELECT * FROM ledger")]
        if {row["effect_id"] for row in ledgers} != expected or len(ledgers) != len(expected):
            raise AssertionError("ledger coverage or uniqueness mismatch")
        accounts = dict(plan["workload"]["accounts"])
        effect_map = {e["effect_id"]: e for e in plan["workload"]["effects"]}
        # Ledger stores effect_id/nonce, not a duplicated payload_hash column.
        # Check both persisted payload bindings addressed by the actual receipt.
        bindings = [dict(row) for row in db.execute("""
            SELECT l.effect_id, e.payload_hash AS effect_payload_hash,
                   e.state AS effect_state, t.effect_id AS token_effect_id,
                   t.payload_hash AS token_payload_hash, t.state AS token_state
            FROM ledger l JOIN effects e ON e.effect_id=l.effect_id
            JOIN tokens t ON t.nonce=l.nonce
        """)]
        if len(bindings) != len(ledgers):
            raise AssertionError("ledger has a missing effect or token binding")
        for binding in bindings:
            eid = binding["effect_id"]
            expected_hash = digest(effect_map[eid]["payload"])
            if binding["effect_payload_hash"] != expected_hash or binding["token_payload_hash"] != expected_hash:
                raise AssertionError("planned payload hash differs from settled effect/token binding")
            if binding["token_effect_id"] != eid or binding["effect_state"] != "settled" or binding["token_state"] != "consumed":
                raise AssertionError("settled effect/token identity or state mismatch")
        for row in ledgers:
            effect = effect_map[row["effect_id"]]
            for key in ("payer", "recipient", "amount"):
                if row[key] != effect[key]:
                    raise AssertionError("action binding mismatch")
            accounts[row["payer"]] -= row["amount"]
            accounts[row["recipient"]] += row["amount"]
        if accounts != dict(db.execute("SELECT account_id,balance FROM accounts")):
            raise AssertionError("account reconciliation mismatch")
        if db.execute("SELECT COUNT(*) FROM stages").fetchone()[0] or db.execute("SELECT COUNT(*) FROM cleanup_queue").fetchone()[0]:
            raise AssertionError("staging or cleanup residue")
        published = set()
        for effect in plan["workload"]["effects"]:
            eid = effect["effect_id"]
            path = run/"published"/(hashlib.sha256(eid.encode()).hexdigest()+".json")
            if path.exists():
                published.add(eid)
                if hashlib.sha256(path.read_bytes()).hexdigest() != effect["payload"]["content_sha256"]:
                    raise AssertionError("published file differs from original report")
        if plan["family"] == "workflow" and (published != expected or list((run/"staged_files").glob("*.json"))):
            raise AssertionError("published set or local stage mismatch")
        history = db.execute("SELECT COUNT(*) FROM mutation_history").fetchone()[0]
        floor = db.execute("SELECT pruned_through FROM adaptive_meta").fetchone()[0]
    return {"status": "passed", "expected_accepted": sorted(expected), "expected_blocked": sorted(blocked),
            "ledger_rows": len(ledgers), "published_reports": len(published),
            "support_size_range": [min(map(len, supports.values())), max(map(len, supports.values()))],
            "history_rows": history, "pruned_through": floor,
            "oracle": "exact planned event coverage/order; independent declared graph replay; ledger-addressed effect/token payload hashes; balances and output hashes"}


def run_plan(run, plan, policy, *, history_limit=4096, delta_budget=256, keep_database=False):
    run = Path(run)
    run.mkdir(parents=True, exist_ok=False)
    save(run/"plan.json", plan)
    db_path = run/"gateway.sqlite"
    clock = [1.0]
    rec = Recorder()
    decisions, tokens, prepared = [], {}, {}
    effects = {e["effect_id"]: e for e in plan["workload"]["effects"]}
    gate = None
    whole_start = snapshot_clock()
    try:
        compiled, _ = rec.call("compile", lambda: compile_plan(plan))
        declaration, supports = compiled
        gate, _ = rec.call("initialize", lambda: AdaptiveGateway(db_path, policy, clock=lambda: clock[0],
                            history_limit=history_limit, delta_budget=delta_budget))
        rec.call("register", lambda: register(gate, plan, declaration, supports), gate=gate)
        operational_start = snapshot_clock()
        for epoch, batch in enumerate(plan["schedule"]):
            clock[0] = 1.0+epoch*10
            for eid in batch["effects"]:
                prepared[eid], _ = rec.call("prepare_report", lambda eid=eid: prepare_report(plan, effects[eid], run), effect_id=eid)
                payload, _ = prepared[eid]
                rec.call("stage", lambda eid=eid, payload=payload: gate.stage(eid, payload), gate=gate, effect_id=eid)
                tokens[eid], _ = rec.call("issue", lambda eid=eid: gate.issue(eid, ttl=plan["ttl"]), gate=gate, effect_id=eid)
            clock[0] += 1.0
            for event in batch["mutations"]:
                sid = event["subject_id"]
                if event["kind"] == "refresh":
                    rec.call("refresh", lambda sid=sid, d=event["deadline"]: gate.refresh(sid, d), gate=gate, subject_id=sid)
                else:
                    rec.call("invalidate", lambda sid=sid: gate.invalidate(sid), gate=gate, subject_id=sid)
                decisions.append({**event, "at": clock[0]})
            clock[0] = batch.get("settle_at", clock[0]+1.0)
            for eid in batch["effects"]:
                receipt, denial = rec.call("settle", lambda eid=eid: gate.settle(tokens[eid], expected_effect_id=eid),
                                           gate=gate, effect_id=eid, allow_denial=True)
                decisions.append({"kind": "settle", "effect_id": eid, "at": clock[0], "accepted": denial is None})
                if denial is None and plan["family"] == "workflow":
                    rec.call("publish_report", lambda eid=eid: publish_report(plan, eid, prepared[eid][1], run), effect_id=eid)
                elif denial is not None and plan["family"] == "workflow":
                    name = hashlib.sha256(eid.encode()).hexdigest()+".json"
                    rec.call("remove_blocked_local_stage", lambda name=name: (run/"staged_files"/name).unlink(), effect_id=eid)
            if plan.get("post_settlement_invalidation"):
                sid = plan["post_settlement_invalidation"]
                rec.call("invalidate_for_reclamation", lambda: gate.invalidate(sid), gate=gate, subject_id=sid)
                decisions.append({"kind": "invalidate", "subject_id": sid, "at": clock[0]})
            while True:
                result, _ = rec.call("cleanup", lambda: gate.cleanup(batch_size=32), gate=gate)
                if not result["has_more"]:
                    break
        rec.call("close", gate.close)
        gate = None
        finished = snapshot_clock()
    finally:
        if gate is not None:
            gate.close()
    # The oracle and output serialization start strictly after all timers stop.
    audit = audit_run(plan, db_path, decisions, run)
    byphase = defaultdict(list)
    for row in rec.rows:
        byphase[row["phase"]].append(row)
    phase_totals = {phase: {"count": len(rows),
                            "wall_ms": sum(row["wall_ms"] for row in rows),
                            "cpu_ms": sum(row["cpu_ms"] for row in rows),
                            "writer_ms": sum(row.get("gateway", {}).get("transaction_ms", 0.0) for row in rows)}
                    for phase, rows in sorted(byphase.items())}
    oper_phases = set(phase_totals)-{"compile", "initialize", "register"}
    result = {"status": "completed", "family": plan["family"], "name": plan["name"],
              "seed": plan["seed"], "policy": policy, "config": plan["config"],
              "input_sha256": digest(plan), "code_sha256": source_hashes(),
              "full_lifecycle": elapsed(whole_start, finished),
              "one_time_setup": elapsed(whole_start, operational_start),
              "operational_lifecycle": elapsed(operational_start, finished),
              "phase_totals": phase_totals,
              "operational_writer_ms": sum(phase_totals[p]["writer_ms"] for p in oper_phases),
              "all_instrumented_writer_ms": sum(p["writer_ms"] for p in phase_totals.values()),
              "settle_validation_ms": sum(r.get("gateway", {}).get("validation_ms", 0.0) for r in byphase["settle"]),
              "refresh_history_ms": sum(r.get("gateway", {}).get("mutation_log_ms", 0.0) for r in byphase.get("refresh", [])),
              "validation_paths": dict(Counter(r.get("gateway", {}).get("validation_path", "none") for r in byphase["settle"])),
              "audit": audit, "operations": rec.rows,
              "database_bytes_after_close": db_path.stat().st_size,
              "timing_scope": "One serial process, direct gateway; complete windows include instrumentation overhead; oracle/output JSON excluded. Upstream ETL already completed. Setup and operational are disjoint. Writer sum excludes uninstrumented schema/close work. No throughput/parallelism inference."}
    save(run/"decisions.json", decisions)
    save(run/"result.json", result)
    with (run/"operations.csv").open("w", newline="", encoding="utf-8") as stream:
        fields = ["operation_index", "phase", "effect_id", "subject_id", "accepted", "reason", "wall_ms", "cpu_ms", "writer_ms", "validation_ms", "mutation_log_ms", "validation_path"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rec.rows:
            flat = {k: row.get(k) for k in fields}
            m = row.get("gateway", {})
            flat.update(writer_ms=m.get("transaction_ms"), validation_ms=m.get("validation_ms"),
                        mutation_log_ms=m.get("mutation_log_ms"), validation_path=m.get("validation_path"))
            writer.writerow(flat)
    if not keep_database:
        for suffix in ("", "-wal", "-shm"):
            owned = Path(str(db_path)+suffix)
            if owned.exists():
                owned.unlink()
    return result


def percentile(values, q):
    v = sorted(values)
    p = (len(v)-1)*q
    a, b = math.floor(p), math.ceil(p)
    return v[a] if a == b else v[a]*(b-p)+v[b]*(p-a)


def interval(values):
    n = len(values)
    rng = random.Random(20261109)
    if n <= 5:
        means = [statistics.fmean(draw) for draw in itertools.product(values, repeat=n)]
    else:
        means = [statistics.fmean(rng.choices(values, k=n)) for _ in range(10000)]
    return {"n_runs": n, "mean": statistics.fmean(values), "values": values,
            "paired_bootstrap_95ci": [percentile(means, .025), percentile(means, .975)]}


def metric(result, key):
    if "." not in key:
        return result[key]
    head, tail = key.split(".", 1)
    return result[head][tail]


METRICS = ("full_lifecycle.wall_ms", "full_lifecycle.cpu_ms", "one_time_setup.wall_ms",
           "operational_lifecycle.wall_ms", "operational_lifecycle.cpu_ms",
           "operational_writer_ms", "settle_validation_ms", "refresh_history_ms")


def analyze(results):
    cells = defaultdict(dict)
    for row in results:
        cell, pair = (row["family"], row["name"]), (row["seed"], row["policy"])
        if pair in cells[cell]:
            raise AssertionError(f"duplicate paired run: {cell!r} {pair!r}")
        cells[cell][pair] = row
    output = []
    for (family, name), rows in sorted(cells.items()):
        seeds = sorted({seed for seed, _ in rows})
        policies = sorted({p for _, p in rows})
        if any((seed, p) not in rows for seed in seeds for p in policies):
            raise AssertionError("incomplete paired cell")
        for seed in seeds:
            match = [rows[(seed, p)] for p in policies]
            if len({r["input_sha256"] for r in match}) != 1:
                raise AssertionError("policies did not receive identical external workload")
            if len({tuple(r["audit"]["expected_accepted"]) for r in match}) != 1:
                raise AssertionError("policies disagree on accepted effects")
        means = {p: {m: statistics.fmean(metric(rows[(s,p)], m) for s in seeds) for m in METRICS} for p in policies}
        paired = {}
        if "adaptive_delta" in policies:
            for baseline in [p for p in policies if p != "adaptive_delta"]:
                paired[baseline] = {m: interval([metric(rows[(s,"adaptive_delta")],m)-metric(rows[(s,baseline)],m) for s in seeds]) for m in METRICS}
        output.append({"family": family, "name": name, "config": next(iter(rows.values()))["config"],
                       "seeds": seeds, "policy_means": means, "paired_delta_minus_baseline": paired})
    return {"status": "passed", "cells": output, "completed_runs": len(results),
            "unit": "complete independent run paired by input seed; requests are not replicates",
            "interval": "whole-run paired percentile bootstrap, exploratory; all seed differences retained; no multiple-comparison adjustment",
            "timing": "full and operational windows separately; nested gateway components not added to either"}


def history_gap_check(out, changes=4100):
    """Untimed boundary witness: token survives >4096 mutations with valid TTL."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    rows = []
    for policy in POLICIES:
        path = out/(policy+".sqlite")
        with AdaptiveGateway(path, policy, clock=lambda: 1.0) as gate:
            gate.create_account("payer", 3)
            gate.create_account("sink", 0)
            gate.put_subject("support", 1000)
            gate.put_subject("unrelated", 1000)
            gate.create_effect("action", "payer", "sink", 1, ["support"])
            gate.stage("action", {"fixed": "payload"})
            token = gate.issue("action", ttl=900)
            for _ in range(changes):
                gate.refresh("unrelated", 1000)
            receipt = gate.settle(token, expected_effect_id="action")
            row = {"policy": policy, "changes": changes, "accepted": receipt["effect_id"] == "action",
                   "path": gate.last_metrics["validation_path"],
                   "floor": gate.db.execute("SELECT pruned_through FROM adaptive_meta").fetchone()[0]}
            if not row["accepted"]:
                raise AssertionError(f"history-gap current-valid action was not accepted by {policy}")
            if policy == "adaptive_delta" and (row["floor"] <= 0 or row["path"] != "fallback_history"):
                raise AssertionError("old token did not fall back to current full predicate")
            rows.append(row)
        for suffix in ("", "-wal", "-shm"):
            owned = Path(str(path)+suffix)
            if owned.exists():owned.unlink()
    result = {"status": "passed", "changes": changes, "results": rows,
              "scope": "functional history-loss witness, no performance inference"}
    save(out/"summary.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--suite", choices=("synthetic", "workflow", "all", "history-gap"), default="all")
    p.add_argument("--workflow", type=Path)
    p.add_argument("--data", type=Path)
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--seed-start", type=int, default=2026110901)
    p.add_argument("--support-sizes", type=int, nargs="+", default=[128,512,2048])
    p.add_argument("--ratios", type=float, nargs="+", default=[.25,1,16])
    p.add_argument("--epochs", type=int, default=4)
    p.add_argument("--group-size", type=int, default=16)
    p.add_argument("--scenarios", nargs="+", choices=(*WORKFLOW_SCENARIOS,"deadline_extension","deadline_shortening"), default=list(WORKFLOW_SCENARIOS))
    p.add_argument("--policies", nargs="+", choices=POLICIES, default=list(POLICIES))
    p.add_argument("--history-limit", type=int, default=4096)
    p.add_argument("--delta-budget", type=int, default=256)
    p.add_argument("--keep-databases", action="store_true")
    args = p.parse_args()
    if args.suite == "history-gap":
        print(json.dumps(history_gap_check(args.out)), flush=True)
        return
    if args.repeats < 1:
        p.error("positive repeats required")
    if args.suite in ("workflow", "all") and (args.workflow is None or args.data is None):
        p.error("workflow suite requires explicit --workflow and --data frozen input paths")
    args.out.mkdir(parents=True, exist_ok=False)
    hashes = source_hashes()
    preflight = None
    if args.suite in ("workflow", "all"):
        scientific = verify_scientific_outputs(args.data, args.workflow)
        file_manifest = json.loads((args.workflow/"workflow_manifest.json").read_text(encoding="utf-8"))
        # Common preflight touches all manifest files before any policy is timed.
        # Per-run compile still includes its own actual reads/hash/schema work.
        compiled = compile_workload(file_manifest, args.workflow)
        frozen = json.loads((args.workflow/"compatible_workload.json").read_text(encoding="utf-8"))
        if compiled != frozen:
            raise AssertionError("common preflight compile differs from frozen workload")
        preflight = {"status": "passed", "scientific_oracle": scientific,
                     "manifest_sha256": digest(file_manifest), "compiled_workload_sha256": digest(compiled),
                     "common_file_preflight": "all manifest files hashed/validated before randomized policy timing; upstream ETL is frozen"}
        save(args.out/"scientific_preflight.json", preflight)
    manifest = {"status": "running", "python": sys.version, "platform": platform.platform(),
                "processor": platform.processor(), "logical_cpus": os.cpu_count(), "physical_hosts": 1,
                "source_hashes": hashes, "args": {k: str(v) if isinstance(v, Path) else v for k,v in vars(args).items()},
                "design": "fixed lifecycle input and event order per seed; independently recreated DB per policy; serial randomized cells/policies",
                "excluded": "scientific ETL already completed; preflight/oracle/report serialization outside measured windows",
                "requested_runs": 0, "runs": []}
    jobs = []
    for seed in range(args.seed_start, args.seed_start+args.repeats):
        cells = []
        if args.suite in ("synthetic", "all"):
            cells += [synthetic_plan(seed,k,ratio,args.epochs,args.group_size) for k in args.support_sizes for ratio in args.ratios]
        if args.suite in ("workflow", "all"):
            cells += [workflow_plan(args.workflow,seed,scenario) for scenario in args.scenarios]
        random.Random(seed).shuffle(cells)
        for plan in cells:
            policies = list(args.policies)
            random.Random(seed+sum(map(ord,plan["name"]))).shuffle(policies)
            jobs.extend((plan, policy) for policy in policies)
    manifest["requested_runs"] = len(jobs)
    save(args.out/"manifest.json", manifest)
    results = []
    for plan, policy in jobs:
        name = f"{plan['family']}_{plan['name']}_s{plan['seed']}_{policy}"
        if source_hashes() != hashes:
            raise RuntimeError("runtime changed during cohort; retain completed runs, do not combine versions")
        try:
            result = run_plan(args.out/name, plan, policy, history_limit=args.history_limit,
                              delta_budget=args.delta_budget, keep_database=args.keep_databases)
            if source_hashes() != hashes:
                raise RuntimeError("runtime changed inside a timed run; do not use this cohort")
            results.append(result)
            manifest["runs"].append({"run_id": name, "status": result["status"], "input_sha256": result["input_sha256"]})
            save(args.out/"manifest.json", manifest)
            print(json.dumps({"completed": len(results), "total": len(jobs), "run": name,
                              "full_wall_ms": result["full_lifecycle"]["wall_ms"],
                              "operational_wall_ms": result["operational_lifecycle"]["wall_ms"]}), flush=True)
        except BaseException as error:
            manifest.update(status="failed", failure={"run": name, "error": repr(error)})
            save(args.out/"manifest.json", manifest)
            raise
    summary = analyze(results)
    save(args.out/"summary.json", summary)
    manifest.update(status="completed", completed_runs=len(results))
    save(args.out/"manifest.json", manifest)
    with (args.out/"run_totals.csv").open("w", newline="", encoding="utf-8") as stream:
        w = csv.DictWriter(stream, fieldnames=["family","name","seed","policy","input_sha256",*METRICS])
        w.writeheader()
        for r in results:
            w.writerow({**{k:r[k] for k in ["family","name","seed","policy","input_sha256"]}, **{m:metric(r,m) for m in METRICS}})
    print(json.dumps({"status": "completed", "runs": len(results), "cells": len(summary["cells"])}), flush=True)


if __name__ == "__main__":
    main()
