"""Exact delta revalidation at a trusted transactional workflow release gate.

Three policies have the same current-predicate acceptance contract. Changes are
admitted atomically with their invalidation queue entry. Bounded history is an
optimization: an unavailable/large interval or expired old minimum falls back
to indexed full revalidation. This is not a novel general OCC algorithm.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import time
import uuid

from durable_gateway import GateRejected
from network_gateway import NetworkGateway
from integrated_controller import Registry
from persistent_workflow import compile_registry

POLICIES = ("full_sql", "guarded_full", "adaptive_delta")


class AdaptiveGateway(NetworkGateway):
    def __init__(self, path, policy="adaptive_delta", *, initialize=True,
                 history_limit=4096, delta_budget=256, clock=time.time,
                 request_id=None, actor_id=None, fault_hook=None):
        if policy not in POLICIES:
            raise ValueError("unknown policy")
        if history_limit < 1 or delta_budget < 1:
            raise ValueError("positive history and delta bounds required")
        self.last_metrics = {}
        self.policy = policy
        if initialize:
            # Base schema is initialized once; request connections never run DDL.
            super().__init__(path, "full_recheck", clock=clock,
                             request_id=request_id, actor_id=actor_id,
                             fault_hook=fault_hook)
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS adaptive_meta (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    policy TEXT NOT NULL, history_limit INTEGER NOT NULL,
                    delta_budget INTEGER NOT NULL, pruned_through INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS adaptive_tokens (
                    nonce TEXT PRIMARY KEY REFERENCES tokens(nonce),
                    issued_sequence INTEGER NOT NULL, support_total INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS mutation_history (
                    seq INTEGER PRIMARY KEY, subject_id TEXT, kind TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cleanup_queue (
                    subject_id TEXT PRIMARY KEY REFERENCES subjects(subject_id),
                    cursor TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS adaptive_clock (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    mutation_sequence INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS support_by_subject
                    ON effect_support(subject_id,effect_id);
                CREATE INDEX IF NOT EXISTS effects_by_state
                    ON effects(state,effect_id);
            """)
            # Keep the hot counter separate from the immutable workload JSON.
            # SQLite rewrites the row payload on UPDATE: sharing a row with a
            # large registry made every refresh rewrite megabytes of metadata.
            # Existing closed databases can seed this small table once from
            # the prior counter; all subsequent writers must use this runtime.
            self.db.execute("""INSERT OR IGNORE INTO adaptive_clock
                SELECT singleton,global_epoch FROM network_meta WHERE singleton=1""")
            row = self.db.execute("SELECT * FROM adaptive_meta WHERE singleton=1").fetchone()
            if row is None:
                self.db.execute("INSERT INTO adaptive_meta VALUES (1,?,?,?,0)",
                                (policy, history_limit, delta_budget))
            elif row["policy"] != policy:
                raise GateRejected("persisted_policy_mismatch")
        else:
            self.path, self.clock, self.fault_hook = str(path), clock, fault_hook
            self.request_id, self.actor_id = request_id, actor_id
            self.db = sqlite3.connect(self.path, isolation_level=None, timeout=30)
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA busy_timeout=30000")
            self.db.execute("PRAGMA synchronous=FULL")
        self.policy = policy
        row = self.db.execute("SELECT * FROM adaptive_meta WHERE singleton=1").fetchone()
        if row is None or row["policy"] != policy:
            self.db.close()
            raise GateRejected("persisted_policy_mismatch")
        self.history_limit, self.delta_budget = row["history_limit"], row["delta_budget"]

    def _global(self):
        return self.db.execute("SELECT mutation_sequence FROM adaptive_clock WHERE singleton=1").fetchone()[0]

    def _bump_global(self):
        self.db.execute("UPDATE adaptive_clock SET mutation_sequence=mutation_sequence+1 WHERE singleton=1")
        return self._global()

    @contextmanager
    def _transaction(self):
        begin = time.perf_counter_ns()
        self.last_metrics = {"validation_ms": 0.0, "validation_path": "not_applicable",
                             "support_total": 0, "changed_checked": 0,
                             "log_entries_scanned": 0, "mutation_log_ms": 0.0}
        self.db.execute("BEGIN IMMEDIATE")
        locked = time.perf_counter_ns()
        self.last_metrics["lock_wait_ms"] = (locked - begin) / 1e6
        self._decision_timestamp = self._time(None)
        try:
            yield
            commit_start = time.perf_counter_ns()
            self.db.execute("COMMIT")
            finished = time.perf_counter_ns()
            self.last_metrics["commit_ms"] = (finished - commit_start) / 1e6
            self.last_metrics["transaction_ms"] = (finished - locked) / 1e6
        except BaseException as exc:
            if isinstance(exc, GateRejected):
                prefix = self.db.execute("SELECT COALESCE(MAX(seq),0) FROM audit").fetchone()[0]
                self._last_denial = {"evaluated_prefix_seq": prefix,
                                     "evaluated_at": self._decision_timestamp}
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            self.last_metrics["transaction_ms"] = (time.perf_counter_ns() - locked) / 1e6
            self.last_metrics["commit_ms"] = 0.0
            raise

    def _audit(self, kind, timestamp, *, effect_id=None, subject_id=None, nonce=None, **details):
        if kind in ("refresh", "invalidate", "extend"):
            start = time.perf_counter_ns()
            if self.policy == "adaptive_delta":
                seq = self._global()
                self.db.execute("INSERT INTO mutation_history VALUES (?,?,?)",
                                (seq, subject_id, kind))
                floor = max(0, seq - self.history_limit)
                self.db.execute("DELETE FROM mutation_history WHERE seq<=?", (floor,))
                self.db.execute("UPDATE adaptive_meta SET pruned_through=? WHERE singleton=1",
                                (floor,))
            if kind == "invalidate":
                self.db.execute("INSERT OR IGNORE INTO cleanup_queue(subject_id) VALUES (?)",
                                (subject_id,))
            elif kind == "extend":
                # An appended revoked subject can fall behind a completed
                # cursor. Requeue that root so new pending support is reclaimed.
                for sid in details.get("additions", []):
                    row = self.db.execute("SELECT valid FROM subjects WHERE subject_id=?", (sid,)).fetchone()
                    if row is not None and not row["valid"]:
                        self.db.execute("""INSERT INTO cleanup_queue(subject_id,cursor) VALUES (?,'')
                            ON CONFLICT(subject_id) DO UPDATE SET cursor=''""", (sid,))
            self.last_metrics["mutation_log_ms"] = (time.perf_counter_ns() - start) / 1e6
        super()._audit(kind, timestamp, effect_id=effect_id, subject_id=subject_id,
                       nonce=nonce, **details)

    def _initial_support(self, effect_id, timestamp):
        row = self.db.execute("""
            SELECT COUNT(*) AS total, MIN(s.valid) AS valid,
                   MIN(s.expires_at) AS deadline
            FROM effect_support es JOIN subjects s USING(subject_id)
            WHERE es.effect_id=?""", (effect_id,)).fetchone()
        if not row["total"]:
            raise GateRejected("empty_support")
        if not row["valid"]:
            raise GateRejected("support_invalidated")
        if timestamp >= row["deadline"]:
            raise GateRejected("support_expired")
        return row["total"], row["deadline"]

    def issue(self, effect_id, *, now=None, ttl=30.0):
        if not math.isfinite(ttl) or ttl <= 0:
            raise ValueError("positive finite token ttl required")
        with self._transaction():
            timestamp = self._time(now)
            effect = self._pending(effect_id)
            stage = self.db.execute("SELECT * FROM stages WHERE effect_id=?", (effect_id,)).fetchone()
            if stage is None:
                raise GateRejected("payload_not_staged")
            start = time.perf_counter_ns()
            total, evidence_deadline = self._initial_support(effect_id, timestamp)
            self.last_metrics.update(validation_ms=(time.perf_counter_ns()-start)/1e6,
                                     validation_path="issue_full", support_total=total)
            nonce, seq = uuid.uuid4().hex, self._global()
            ttl_deadline = timestamp + ttl
            deadline = min(ttl_deadline, evidence_deadline)
            # All policies store identical compact certificates; no baseline pays
            # a Python row materialization or JSON support-vector penalty.
            self.db.execute("INSERT INTO tokens VALUES (?,?,?,?,?,?,?,'issued')",
                            (nonce, effect_id, effect["contract_version"], stage["payload_hash"],
                             "[]", timestamp, deadline))
            self.db.execute("INSERT INTO network_tokens VALUES (?,?,?)", (nonce, seq, ttl_deadline))
            self.db.execute("INSERT INTO adaptive_tokens VALUES (?,?,?)", (nonce, seq, total))
            self._audit("issue", timestamp, effect_id=effect_id, nonce=nonce,
                        contract_version=effect["contract_version"], expires_at=deadline,
                        ttl_deadline=ttl_deadline, global_epoch=seq, issued_sequence=seq,
                        support_total=total, payload_hash=stage["payload_hash"],
                        validation_metrics=dict(self.last_metrics))
            return nonce

    def _full_validate(self, effect_id, timestamp):
        # Indexed SQL predicate with early rejection and no ORDER BY, object
        # conversion, repeated closure discovery, or artificial validator cost.
        bad = self.db.execute("""
            SELECT s.valid,s.expires_at FROM effect_support es
            JOIN subjects s USING(subject_id)
            WHERE es.effect_id=? AND (s.valid=0 OR s.expires_at<=?) LIMIT 1
        """, (effect_id, timestamp)).fetchone()
        if bad is not None:
            raise GateRejected("support_invalidated" if not bad["valid"] else "support_expired")

    def _validate(self, token, timestamp):
        eid, seq, old = token["effect_id"], self._global(), token["issued_sequence"]
        total = token["support_total"]
        self.last_metrics.update(support_total=total, issued_sequence=old,
                                 current_sequence=seq, changed_checked=0,
                                 log_entries_scanned=0)
        if timestamp >= token["ttl_deadline"]:
            raise GateRejected("token_expired")
        path = "full"
        if self.policy != "full_sql" and seq == old and timestamp < token["expires_at"]:
            self.last_metrics["validation_path"] = "unchanged"
            return
        if self.policy == "adaptive_delta":
            floor = self.db.execute("SELECT pruned_through FROM adaptive_meta WHERE singleton=1").fetchone()[0]
            if old < floor:
                path = "fallback_history"
            elif timestamp >= token["expires_at"]:
                path = "fallback_deadline"
            elif seq - old > min(self.delta_budget, total):
                path = "fallback_budget"
            else:
                # Force an indexed mutation interval first; then exact membership
                # probes through the (effect_id, subject_id) primary key.
                history = self.db.execute(
                    "SELECT seq,subject_id FROM mutation_history WHERE seq>? ORDER BY seq",
                    (old,)).fetchall()
                if len(history) != seq-old:
                    # Defensive against incomplete/corrupt retained history.
                    path = "fallback_gap"
                else:
                    self.last_metrics["validation_path"] = "delta"
                    self.last_metrics["log_entries_scanned"] = len(history)
                    rows = self.db.execute("""
                        SELECT DISTINCT s.subject_id,s.valid,s.expires_at
                        FROM mutation_history c
                        CROSS JOIN effect_support es
                        CROSS JOIN subjects s
                        WHERE c.seq>? AND es.effect_id=?
                          AND es.subject_id=c.subject_id AND s.subject_id=c.subject_id
                    """, (old, eid)).fetchall()
                    self.last_metrics["changed_checked"] = len(rows)
                    for row in rows:
                        if not row["valid"]:
                            raise GateRejected("support_invalidated")
                        if timestamp >= row["expires_at"]:
                            raise GateRejected("support_expired")
                    return
        elif self.policy == "guarded_full":
            path = "fallback_global_change" if seq != old else "fallback_deadline"
        self.last_metrics["validation_path"] = path
        self._full_validate(eid, timestamp)

    def settle(self, nonce, *, now=None, expected_effect_id=None):
        with self._transaction():
            timestamp = self._time(now)
            token = self.db.execute("""
                SELECT t.*,n.ttl_deadline,a.issued_sequence,a.support_total
                FROM tokens t JOIN network_tokens n USING(nonce)
                JOIN adaptive_tokens a USING(nonce) WHERE nonce=?""", (nonce,)).fetchone()
            if token is None:
                raise GateRejected("unknown_token")
            eid = token["effect_id"]
            if expected_effect_id is not None and eid != expected_effect_id:
                raise GateRejected("token_effect_mismatch")
            prior = self.db.execute("SELECT * FROM ledger WHERE nonce=?", (nonce,)).fetchone()
            if prior is not None:
                self.last_metrics["validation_path"] = "receipt_replay"
                return dict(prior)
            if token["state"] != "issued":
                raise GateRejected("token_" + token["state"])
            effect = self._pending(eid)
            if effect["contract_version"] != token["contract_version"]:
                raise GateRejected("contract_changed")
            if timestamp < token["issued_at"]:
                raise GateRejected("clock_regression")
            validation_start = time.perf_counter_ns()
            try:
                self._validate(token, timestamp)
            finally:
                self.last_metrics["validation_ms"] = (time.perf_counter_ns()-validation_start)/1e6
            sink_start = time.perf_counter_ns()
            stage = self.db.execute("SELECT * FROM stages WHERE effect_id=?", (eid,)).fetchone()
            if stage is None:
                raise GateRejected("payload_not_staged")
            digest = hashlib.sha256(stage["payload"].encode("utf-8")).hexdigest()
            if digest != token["payload_hash"] or digest != effect["payload_hash"]:
                raise GateRejected("payload_changed")
            amount = effect["amount"]
            if self.balance(effect["payer"]) < amount:
                raise GateRejected("insufficient_funds")
            if self.balance(effect["recipient"]) + amount > 2**63-1:
                raise GateRejected("balance_overflow")
            self.db.execute("UPDATE accounts SET balance=balance-? WHERE account_id=?", (amount,effect["payer"]))
            self._fault("after_debit")
            self.db.execute("UPDATE accounts SET balance=balance+? WHERE account_id=?", (amount,effect["recipient"]))
            receipt = dict(effect_id=eid, nonce=nonce, receipt_id=uuid.uuid4().hex,
                           payer=effect["payer"], recipient=effect["recipient"], amount=amount,
                           settled_at=timestamp)
            self.db.execute("INSERT INTO ledger VALUES (?,?,?,?,?,?,?)", tuple(receipt.values()))
            self.db.execute("UPDATE tokens SET state='consumed' WHERE nonce=?", (nonce,))
            self.db.execute("UPDATE effects SET state='settled' WHERE effect_id=?", (eid,))
            self.db.execute("DELETE FROM stages WHERE effect_id=?", (eid,))
            self.last_metrics["sink_sql_ms"] = (time.perf_counter_ns()-sink_start)/1e6
            self._audit("settle", timestamp, effect_id=eid, nonce=nonce, receipt=receipt,
                        policy=self.policy, contract_version=effect["contract_version"],
                        global_epoch=self._global(), validation_metrics=dict(self.last_metrics))
            self._fault("before_commit")
        self._fault("after_commit")
        return receipt

    def cleanup(self, batch_size=32):
        """Reclaim stages by bounded effect candidates, without touching tokens.

        A cancelled effect is the durable invalidation tombstone for all of its
        outstanding nonces.  settle() checks that tombstone before validation;
        committed-receipt replay still precedes it and does not create an action.
        Token rows retain their stored states for audit.  This removes work
        proportional to either tokens per effect or the entire token table.

        A batch visits at most B candidates and changes at most 2*B+2 logical
        rows (one stage, one effect per cancellation; queue and audit rows).
        It does not bound payload bytes, index pages, lock waits or durable I/O.
        """
        if batch_size is not None and (type(batch_size) is not int or batch_size < 1):
            raise ValueError("batch size must be positive or null")
        with self._transaction():
            timestamp = self._time(None)
            changes_before = self.db.total_changes
            queue = self.db.execute("SELECT * FROM cleanup_queue ORDER BY subject_id LIMIT 1").fetchone()
            cancelled, removed, candidates = [], 0, []
            if queue is not None:
                sql = """SELECT effect_id FROM effect_support
                         WHERE subject_id=? AND effect_id>? ORDER BY effect_id"""
                args = [queue["subject_id"], queue["cursor"]]
                if batch_size is not None:
                    sql += " LIMIT ?"
                    args.append(batch_size+1)
                all_candidates = [r[0] for r in self.db.execute(sql,args)]
                candidates = all_candidates if batch_size is None else all_candidates[:batch_size]
                for eid in candidates:
                    if self._effect(eid)["state"] != "pending":
                        continue
                    removed += self.db.execute("DELETE FROM stages WHERE effect_id=?", (eid,)).rowcount
                    self.db.execute("UPDATE effects SET state='cancelled' WHERE effect_id=?", (eid,))
                    # The effect tombstone rejects every outstanding token via
                    # _pending(); do not scan or fan out writes to token rows.
                    cancelled.append(eid)
                if len(all_candidates) > len(candidates):
                    self.db.execute("UPDATE cleanup_queue SET cursor=? WHERE subject_id=?",
                                    (candidates[-1],queue["subject_id"]))
                else:
                    self.db.execute("DELETE FROM cleanup_queue WHERE subject_id=?", (queue["subject_id"],))
            has_more = bool(self.db.execute("SELECT 1 FROM cleanup_queue LIMIT 1").fetchone())
            result = dict(cancelled_effects=cancelled, stage_rows_deleted=removed,
                          scanned_effects=candidates, batch_size=batch_size, has_more=has_more,
                          root=queue["subject_id"] if queue else None,
                          token_invalidation="effect_tombstone")
            self._audit("cleanup",timestamp,**result)
            self.last_metrics["cleanup_logical_row_changes"] = self.db.total_changes - changes_before
            self._fault("cleanup_before_commit")
            return result

    def inspect(self):
        result = super().inspect()
        result["metadata"]["global_epoch"] = self._global()
        result["adaptive_metadata"] = dict(self.db.execute("SELECT * FROM adaptive_meta").fetchone())
        result["adaptive_metadata"]["mutation_sequence"] = self._global()
        result["mutation_history"] = [dict(r) for r in self.db.execute("SELECT * FROM mutation_history ORDER BY seq")]
        result["cleanup_queue"] = [dict(r) for r in self.db.execute("SELECT * FROM cleanup_queue ORDER BY subject_id")]
        # The tokens list remains a faithful snapshot of persisted rows.  A
        # stored 'issued' state is not authorization when its effect cancelled.
        result["cleanup_token_invalidation"] = "effect_tombstone"
        return result


def bootstrap(db_path, workload, policy="adaptive_delta", history_limit=4096, delta_budget=256):
    declaration, supports = compile_registry(Registry(**workload["registry"]))
    expiry = float(workload.get("expires_at",time.time()+3600))
    subjects = set(workload.get("extra_subjects",[]))
    subjects.update("a:"+aid for aid in declaration["artifact_parents"])
    for support in supports.values():
        subjects.update(support)
    subjects.update("o:"+oid for vals in declaration["artifact_obligations"].values() for oid in vals)
    deadlines = workload.get("subject_expiries",{})
    started = time.perf_counter_ns()
    with AdaptiveGateway(db_path,policy,history_limit=history_limit,delta_budget=delta_budget) as gate:
        if gate.db.execute("SELECT COUNT(*) FROM effects").fetchone()[0]:
            raise GateRejected("bootstrap_requires_empty_database")
        # One setup transaction for all policies; no one-transaction-per-object
        # overhead in large registries. Setup is measured separately from traffic.
        with gate._transaction():
            for name,balance in workload["accounts"].items():
                gate._integer(balance)
                gate.db.execute("INSERT INTO accounts VALUES (?,?)",(name,balance))
            gate.db.executemany("INSERT INTO subjects VALUES (?,0,1,?)",
                                ((sid,float(deadlines.get(sid,expiry))) for sid in sorted(subjects)))
            for effect in workload["effects"]:
                eid=effect["effect_id"]
                gate._integer(effect["amount"],positive=True)
                gate.db.execute("INSERT INTO effects VALUES (?,0,?,?,?,NULL,'pending')",
                                (eid,effect["payer"],effect["recipient"],effect["amount"]))
                gate.db.executemany("INSERT INTO effect_support VALUES (?,?)",
                                    ((eid,sid) for sid in supports[eid]))
                if workload.get("stage_at_bootstrap",True):
                    payload=json.dumps(effect["payload"],sort_keys=True,ensure_ascii=False,
                                       separators=(",",":"),allow_nan=False)
                    digest=hashlib.sha256(payload.encode()).hexdigest()
                    gate.db.execute("INSERT INTO stages VALUES (?,?,?)",(eid,payload,digest))
                    gate.db.execute("UPDATE effects SET payload_hash=? WHERE effect_id=?",(digest,eid))
            initial={"registry":declaration,"supports":supports,"expires_at":expiry,
                     "subject_expiries":{s:float(deadlines.get(s,expiry)) for s in subjects},
                     "accounts":workload["accounts"],"effects":workload["effects"]}
            gate.db.execute("UPDATE network_meta SET workload=? WHERE singleton=1",
                            (json.dumps(initial,sort_keys=True),))
            gate._audit("bootstrap",gate._time(None),initial=initial,policy=policy)
        result=gate.inspect()
    result["bootstrap_ms"]=(time.perf_counter_ns()-started)/1e6
    return result


def serve(db_path,policy,ready_file,port=0,host="127.0.0.1",api_token=None):
    if host not in ("127.0.0.1","localhost","::1") and not api_token:
        raise ValueError("remote binding requires an explicit API token")
    class Handler(BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def log_message(self,*_args):
            pass
        def setup(self):
            super().setup()
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.gate=AdaptiveGateway(db_path,policy,initialize=False)
        def finish(self):
            try:
                self.gate.close()
            finally:
                super().finish()
        def do_POST(self):
            start=time.perf_counter_ns()
            status=200
            if self.path!="/rpc":
                self.send_error(404)
                return
            operation,arguments="unknown",{}
            try:
                length=int(self.headers.get("Content-Length","0"))
                if length<=0 or length>8*1024*1024:
                    raise ValueError("invalid request size")
                body=self.rfile.read(length)
                if api_token and not secrets.compare_digest(self.headers.get("Authorization",""),"Bearer "+api_token):
                    self.close_connection=True
                    status=403
                    raise ValueError("authentication_required")
                request=json.loads(body)
                operation=request["operation"]
                arguments=dict(request.get("arguments",{}))
                self.gate.request_id=request.get("request_id")
                self.gate.actor_id=request.get("actor_id")
                if "now" in arguments:
                    raise ValueError("server clock required")
                if operation=="ping":
                    result={"pid":os.getpid(),"policy":policy}
                elif operation in ("stage","issue","settle","refresh","invalidate","cleanup","inspect"):
                    result=getattr(self.gate,operation)(**arguments)
                elif operation=="extend":
                    result=self.gate.extend_contract(**arguments)
                else:
                    raise ValueError("unknown operation")
                response={"ok":True,"result":result,"metrics":dict(self.gate.last_metrics)}
            except (GateRejected,ValueError,TypeError,KeyError) as exc:
                reason=exc.reason if isinstance(exc,GateRejected) else str(exc)
                metrics=dict(self.gate.last_metrics)
                if status==200:
                    self.gate.log_reject(operation,arguments,reason)
                response={"ok":False,"reason":reason,"metrics":metrics}
            except Exception as exc:
                response={"ok":False,"reason":"server_error:"+type(exc).__name__}
            response.setdefault("metrics",{})["handler_ms"]=(time.perf_counter_ns()-start)/1e6
            body=json.dumps(response,allow_nan=False).encode()
            try:
                self.send_response(status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):
                pass
    with AdaptiveGateway(db_path,policy):
        pass
    server=ThreadingHTTPServer((host,port),Handler)
    server.daemon_threads=True
    Path(ready_file).write_text(json.dumps({"host":host,"port":server.server_port,
                                          "pid":os.getpid(),"policy":policy}),encoding="utf-8")
    server.serve_forever(poll_interval=.05)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--db",required=True)
    parser.add_argument("--policy",choices=POLICIES,required=True)
    parser.add_argument("--ready-file",required=True)
    parser.add_argument("--port",type=int,default=0)
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--api-token-env",default="WASF_EXPERIMENT_TOKEN")
    args=parser.parse_args()
    serve(args.db,args.policy,args.ready_file,args.port,args.host,
          os.environ.get(args.api_token_env))

