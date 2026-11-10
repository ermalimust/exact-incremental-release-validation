"""Integrated release, revocation and staged-object reclamation.

This reference implements admitted-event safety, not detection of unobserved
world changes. The registry is immutable within an effect generation. Tokens
bind a complete artifact/obligation support, not just local obligation labels.
A root tombstone invalidates all dependent tokens before descendant cleanup.

All policies receive identical declarations and admitted events:
support_epoch: support versions must match at settlement.
global_epoch: any admitted update invalidates a pending token (safe baseline).
full_recheck: re-evaluate the same cached complete support at settlement
              (safe, same-information simple baseline).
own_only, no_revalidate, no_expiry: explicitly unsafe diagnostic ablations.

The in-memory sink is a local linearization reference. It is NOT an on-chain
gateway or crash-durable ledger; durable_gateway.py tests a separate SQLite sink.
"""
from __future__ import annotations

from collections import defaultdict, deque
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
import hashlib
import json
import math
import threading
from typing import Mapping, Optional


@dataclass(frozen=True)
class Registry:
    artifact_parents: Mapping[str, tuple[str, ...]]
    artifact_obligations: Mapping[str, tuple[str, ...]]
    effect_artifacts: Mapping[str, tuple[str, ...]]
    effect_obligations: Mapping[str, tuple[str, ...]] = field(default_factory=dict)


@dataclass(frozen=True)
class ReleaseToken:
    token_id: str
    effect_id: str
    contract_version: int
    binding_digest: str
    support_versions: tuple[tuple[str, int], ...]
    global_epoch: int
    issued_at: float
    valid_until: float


@dataclass
class _Subject:
    epoch: int = 0
    state: str = "unresolved"
    valid_until: float = math.inf
    present: bool = True


@dataclass
class _Effect:
    version: int = 0
    ready: bool = False
    settled: bool = False
    extra_obligations: tuple[str, ...] = ()


class IntegratedController:
    POLICIES = {"support_epoch", "global_epoch", "full_recheck",
                "own_only", "no_revalidate", "no_expiry"}

    def __init__(self, registry: Registry, policy: str = "support_epoch"):
        if policy not in self.POLICIES:
            raise ValueError(f"unknown policy {policy}")
        self.policy = policy
        # Copy input maps: callers cannot silently mutate the registered graph.
        self.parents = {k: tuple(v) for k, v in registry.artifact_parents.items()}
        self.artifact_obligations = {
            k: tuple(v) for k, v in registry.artifact_obligations.items()
        }
        self.effect_artifacts = {
            k: tuple(v) for k, v in registry.effect_artifacts.items()
        }
        self.effect_obligations = {
            k: tuple(v) for k, v in registry.effect_obligations.items()
        }
        for aid, parents in self.parents.items():
            if any(p not in self.parents for p in parents):
                raise ValueError(f"unknown parent of {aid}")
        if set(self.artifact_obligations) - set(self.parents):
            raise ValueError("obligations bound to unknown artifact")
        if set(self.effect_obligations) - set(self.effect_artifacts):
            raise ValueError("obligations bound to unknown effect")
        for eid, roots in self.effect_artifacts.items():
            if not roots or any(a not in self.parents for a in roots):
                raise ValueError(f"unknown/empty artifact roots for {eid}")
        # DFS rejects cycles; a topological contract is a supported input scope.
        visited, visiting = set(), set()
        def visit(a):
            if a in visiting:
                raise ValueError("artifact dependency cycle")
            if a in visited:
                return
            visiting.add(a)
            for p in self.parents[a]:
                visit(p)
            visiting.remove(a)
            visited.add(a)
        for aid in self.parents:
            visit(aid)
        self._effects = {e: _Effect() for e in self.effect_artifacts}
        self._subjects = {"a:" + a: _Subject(state="valid") for a in self.parents}
        all_obligations = set()
        for values in list(self.artifact_obligations.values()) + list(self.effect_obligations.values()):
            all_obligations.update(values)
        self._subjects.update({"o:" + o: _Subject() for o in all_obligations})
        self._locks = {key: threading.RLock() for key in self._subjects}
        self._effect_locks = {e: threading.RLock() for e in self._effects}
        self._meta_lock = threading.RLock()
        self._epoch_lock = threading.RLock()
        self._queue_lock = threading.RLock()
        self._global_epoch = 0
        self._sequence = 0
        self._issued = {}
        self._consumed = set()
        self._cleanup_queue = deque()
        self._children = defaultdict(set)
        self._obligation_artifacts = defaultdict(set)
        for artifact, obligations in self.artifact_obligations.items():
            for obligation in obligations:
                self._obligation_artifacts[obligation].add(artifact)
        for child, parents in self.parents.items():
            for parent in parents:
                self._children[parent].add(child)
        self._base_support = {e: self._discover_support(e) for e in self._effects}
        self.metrics = defaultdict(int)
        self.audit = []
        self.settlements = []

    def _discover_support(self, effect_id, own_only=False):
        artifacts, work = set(), list(self.effect_artifacts[effect_id])
        while work:
            aid = work.pop()
            if aid in artifacts:
                continue
            artifacts.add(aid)
            if not own_only:
                work.extend(self.parents[aid])
        obligations = set(self.effect_obligations.get(effect_id, ()))
        for aid in artifacts:
            obligations.update(self.artifact_obligations.get(aid, ()))
        return tuple(sorted(["a:" + a for a in artifacts] +
                            ["o:" + o for o in obligations]))

    def _support(self, effect_id):
        if self.policy == "own_only":
            base = self._discover_support(effect_id, own_only=True)
        else:
            base = self._base_support[effect_id]
        return tuple(sorted(set(base) |
                            {"o:" + x for x in self._effects[effect_id].extra_obligations}))

    @contextmanager
    def _held_support(self, effect_id):
        # Every path takes effect lock before sorted support locks. Invalidation
        # takes a single subject lock, never an effect lock, so it cannot form a cycle.
        with self._effect_locks[effect_id]:
            support = self._support(effect_id)
            locks = [self._locks[x] for x in support]
            for lock in locks:
                lock.acquire()
            try:
                yield support
            finally:
                for lock in reversed(locks):
                    lock.release()

    def _bump_global(self):
        with self._epoch_lock:
            self._global_epoch += 1

    @staticmethod
    def _time(now):
        now = float(now)
        if not math.isfinite(now):
            raise ValueError("event time must be finite")
        return now

    def _binding(self, effect_id, support):
        value = (effect_id, self._effects[effect_id].version,
                 self.effect_artifacts[effect_id], support)
        return hashlib.sha256(json.dumps(value).encode()).hexdigest()

    def _check(self, effect_id, support, now):
        effect = self._effects[effect_id]
        if effect.settled:
            return "already_settled"
        if not effect.ready:
            return "not_ready"
        for key in support:
            self.metrics["predicate_checks"] += 1
            subject = self._subjects[key]
            if key.startswith("a:"):
                if subject.state == "invalid" or not subject.present:
                    return "invalid_artifact"
            elif subject.state == "unresolved":
                return "unresolved_obligation"
            elif subject.state == "invalid":
                return "invalid_obligation"
            if self.policy != "no_expiry" and now >= subject.valid_until:
                return "expired_evidence"
        return None

    def resolve(self, obligation_id, state="valid", valid_until=math.inf):
        if state not in {"valid", "invalid", "unresolved"}:
            raise ValueError(state)
        key = "o:" + obligation_id
        if key not in self._subjects:
            raise KeyError(obligation_id)
        valid_until = float(valid_until)
        if math.isnan(valid_until) or valid_until == -math.inf:
            raise ValueError("invalid evidence expiry")
        with self._locks[key]:
            subject = self._subjects[key]
            # A revoked evidence identity cannot resurrect a derived old artifact.
            if subject.state == "invalid" and state != "invalid":
                raise ValueError("revoked evidence is immutable; use a new generation")
            subject.epoch += 1
            subject.state = state
            subject.valid_until = valid_until
            self._bump_global()
            self.audit.append({"event": "resolve", "subject": obligation_id,
                               "state": state, "epoch": subject.epoch})
        if state == "invalid":
            # Retire materialized outputs justified by the revoked evidence.
            # The evidence tombstone already blocks release during this loop.
            for artifact in sorted(self._obligation_artifacts[obligation_id]):
                self.invalidate(artifact)

    def set_ready(self, effect_id, ready=True):
        with self._effect_locks[effect_id]:
            effect = self._effects[effect_id]
            if effect.settled:
                return
            if effect.ready != bool(ready):
                effect.ready = bool(ready)
                effect.version += 1
                self._bump_global()

    def invalidate(self, subject_id):
        key = "a:" + subject_id
        if key not in self._subjects:
            raise KeyError(subject_id)
        with self._locks[key]:
            subject = self._subjects[key]
            subject.epoch += 1
            subject.state = "invalid"
            self._bump_global()
            self.metrics["root_invalidations"] += 1
            self.audit.append({"event": "invalidate", "subject": subject_id,
                               "epoch": subject.epoch})
        with self._queue_lock:
            self._cleanup_queue.append(subject_id)

    def rollback_pending(self):
        """Physically retire staged descendants; safety does not await this walk."""
        with self._queue_lock:
            pending = list(self._cleanup_queue)
            self._cleanup_queue.clear()
        seen, work = set(), deque(pending)
        removed = set()
        while work:
            aid = work.popleft()
            if aid in seen:
                continue
            seen.add(aid)
            with self._locks["a:" + aid]:
                subject = self._subjects["a:" + aid]
                if subject.present:
                    subject.present = False
                    subject.state = "invalid"
                    subject.epoch += 1
                    removed.add(aid)
                self.metrics["cleanup_subject_visits"] += 1
            work.extend(sorted(self._children[aid]))
        self.audit.append({"event": "cleanup", "removed": sorted(removed)})
        return removed

    def staged_artifacts(self):
        return {k[2:] for k, v in self._subjects.items()
                if k.startswith("a:") and v.present}

    def extend(self, effect_id, obligations):
        """Append registered predicates; never remove old support or change a graph."""
        with self._effect_locks[effect_id]:
            effect = self._effects[effect_id]
            if effect.settled:
                raise ValueError("settled effect is immutable")
            additions = tuple(sorted(set(obligations)))
            with self._meta_lock:
                for oid in additions:
                    key = "o:" + oid
                    if key not in self._subjects:
                        self._subjects[key] = _Subject()
                        self._locks[key] = threading.RLock()
            effect.extra_obligations = tuple(sorted(set(effect.extra_obligations) |
                                                     set(additions)))
            effect.version += 1
            self._bump_global()

    def issue(self, effect_id, now):
        now = self._time(now)
        self.metrics["issue_attempts"] += 1
        with self._held_support(effect_id) as support:
            reason = self._check(effect_id, support, now)
            if reason:
                self.audit.append({"event": "issue_rejected", "effect": effect_id,
                                   "reason": reason})
                return None
            versions = tuple((key, self._subjects[key].epoch) for key in support)
            expiry = min((self._subjects[key].valid_until for key in support),
                         default=math.inf)
            with self._epoch_lock:
                epoch = self._global_epoch
            with self._meta_lock:
                sequence = self._sequence
                self._sequence += 1
                token_id = hashlib.sha256(
                    f"{effect_id}|{sequence}|{versions}|{now}".encode()).hexdigest()
                token = ReleaseToken(token_id, effect_id,
                    self._effects[effect_id].version, self._binding(effect_id, support),
                    versions, epoch, now, expiry)
                self._issued[token_id] = token
            self.metrics["tokens_issued"] += 1
            self.audit.append({"event": "issue", "effect": effect_id, "token": token_id})
            return token

    def _reject(self, effect_id, reason):
        self.metrics["settle_rejections"] += 1
        self.metrics["reject_" + reason] += 1
        self.audit.append({"event": "settle_rejected", "effect": effect_id,
                           "reason": reason})
        return False, reason

    def settle(self, effect_id, token: Optional[ReleaseToken], now):
        now = self._time(now)
        self.metrics["settle_attempts"] += 1
        with self._held_support(effect_id) as support:
            if token is None or self._issued.get(token.token_id) != token:
                return self._reject(effect_id, "unknown_token")
            if token.effect_id != effect_id:
                return self._reject(effect_id, "wrong_effect")
            if token.token_id in self._consumed:
                return self._reject(effect_id, "replay")
            if self._effects[effect_id].settled:
                return self._reject(effect_id, "already_settled")
            if now < token.issued_at:
                return self._reject(effect_id, "time_before_issue")
            if self.policy != "no_revalidate":
                if token.contract_version != self._effects[effect_id].version:
                    return self._reject(effect_id, "stale_contract")
                if token.binding_digest != self._binding(effect_id, support):
                    return self._reject(effect_id, "stale_contract")
            # global_epoch's final epoch check and local commit are protected
            # together; mutations cannot advance the epoch between these events.
            with (self._epoch_lock if self.policy == "global_epoch" else nullcontext()):
                if self.policy == "global_epoch" and token.global_epoch != self._global_epoch:
                    return self._reject(effect_id, "stale_global")
                if self.policy not in {"no_revalidate", "full_recheck"}:
                    for key, old_version in token.support_versions:
                        self.metrics["version_checks"] += 1
                        if self._subjects[key].epoch != old_version:
                            return self._reject(effect_id, "stale_support")
                if self.policy == "full_recheck":
                    reason = self._check(effect_id, support, now)
                    if reason:
                        return self._reject(effect_id, reason)
                elif self.policy not in {"no_revalidate", "no_expiry"}:
                    # Issuance checked all predicates. Equal versions and the
                    # fixed contract imply their values are unchanged; time is
                    # the one changing input and must still be checked here.
                    if now >= token.valid_until:
                        return self._reject(effect_id, "expired_evidence")
                # Commit point of this in-memory sink: no asynchronous action
                # is initiated and later advertised as atomically reversible.
                self._consumed.add(token.token_id)
                self._effects[effect_id].settled = True
                self.settlements.append({"effect_id": effect_id, "time": now,
                                         "token_id": token.token_id})
            self.metrics["settled"] += 1
            self.audit.append({"event": "settle", "effect": effect_id,
                               "time": now, "token": token.token_id})
            return True, "accepted"

    def status(self, effect_id):
        with self._effect_locks[effect_id]:
            return "settled" if self._effects[effect_id].settled else "staged"


def registry_from_legacy_trace(trace):
    """Make the previously implicit effect/artifact mapping explicit.

    Every workflow effect consumes its last artifact. Each workflow's own
    obligation list is attached to that final artifact. Thus parents' final
    artifacts bring their predicates into downstream release support. Failure
    events additionally tombstone their explicitly named root artifacts.
    """
    parents = {a.artifact_id: [] for a in trace.artifacts}
    finals = {}
    for artifact in trace.artifacts:
        old = finals.get(artifact.workflow_id)
        if old is None or artifact.step_id > old.step_id:
            finals[artifact.workflow_id] = artifact
    for parent, child in trace.dependency_edges:
        parents[child].append(parent)
    artifact_obligations = {}
    effects = {}
    for effect in trace.effects:
        final = finals[effect.workflow_id].artifact_id
        effects[effect.effect_id] = (final,)
        artifact_obligations[final] = tuple(effect.obligation_ids)
    return Registry({a: tuple(sorted(p)) for a, p in parents.items()},
                    artifact_obligations, effects)

