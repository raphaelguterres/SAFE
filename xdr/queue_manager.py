"""Resilient bounded queues for SAFE operational reliability.

The queue manager is intentionally in-process and dependency-free. It gives the
platform deterministic backpressure, priority ordering and dead-letter handling
without forcing Redis/Kafka into local/demo deployments.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from threading import RLock
from typing import Any, Deque, Dict, Iterable, Mapping
from uuid import uuid4


PRIORITY_ORDER = ("P0", "P1", "P2", "P3")
PRIORITY_RANK = {name: index for index, name in enumerate(PRIORITY_ORDER)}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_priority(priority: str | None) -> str:
    value = str(priority or "P2").upper()
    return value if value in PRIORITY_RANK else "P2"


@dataclass
class QueuedMessage:
    tenant_id: str
    event_type: str
    payload: Mapping[str, Any]
    priority: str = "P2"
    message_id: str = field(default_factory=lambda: uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid4().hex)
    created_at: str = field(default_factory=_utc_now)
    attempts: int = 0
    max_attempts: int = 3
    last_error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "trace_id": self.trace_id,
            "tenant_id": self.tenant_id,
            "event_type": self.event_type,
            "priority": self.priority,
            "created_at": self.created_at,
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "last_error": self.last_error,
            "payload": dict(self.payload),
        }


@dataclass
class QueueSubmitResult:
    accepted: bool
    message_id: str | None = None
    reason: str = ""
    queue_depth: int = 0
    dead_lettered: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "message_id": self.message_id,
            "reason": self.reason,
            "queue_depth": self.queue_depth,
            "dead_lettered": self.dead_lettered,
        }


@dataclass(frozen=True)
class QueueSnapshot:
    max_size: int
    total_depth: int
    by_priority: Dict[str, int]
    by_tenant: Dict[str, int]
    inflight: int
    dead_letter_depth: int
    submitted: int
    rejected: int
    dropped: int
    retried: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_size": self.max_size,
            "total_depth": self.total_depth,
            "by_priority": dict(self.by_priority),
            "by_tenant": dict(self.by_tenant),
            "inflight": self.inflight,
            "dead_letter_depth": self.dead_letter_depth,
            "submitted": self.submitted,
            "rejected": self.rejected,
            "dropped": self.dropped,
            "retried": self.retried,
        }


class ResilientQueueManager:
    """Bounded priority queue with tenant-aware accounting and DLQ support."""

    def __init__(
        self,
        *,
        max_size: int = 10_000,
        dead_letter_size: int = 1_000,
        per_tenant_limit: int = 2_500,
        max_payload_bytes: int = 256_000,
    ) -> None:
        if max_size < 1:
            raise ValueError("max_size must be positive")
        self.max_size = int(max_size)
        self.dead_letter_size = max(1, int(dead_letter_size))
        self.per_tenant_limit = max(1, int(per_tenant_limit))
        self.max_payload_bytes = max(1_024, int(max_payload_bytes))
        self._queues: Dict[str, Deque[QueuedMessage]] = {name: deque() for name in PRIORITY_ORDER}
        self._dead_letter: Deque[QueuedMessage] = deque(maxlen=self.dead_letter_size)
        self._inflight: Dict[str, QueuedMessage] = {}
        self._tenant_depth: Counter[str] = Counter()
        self._lock = RLock()
        self._submitted = 0
        self._rejected = 0
        self._dropped = 0
        self._retried = 0

    def submit(
        self,
        *,
        tenant_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        priority: str = "P2",
        trace_id: str | None = None,
        max_attempts: int = 3,
    ) -> QueueSubmitResult:
        tenant = str(tenant_id or "").strip()
        event = str(event_type or "").strip()
        if not tenant or not event:
            return self._reject("missing_tenant_or_event")
        if not isinstance(payload, Mapping):
            return self._reject("invalid_payload")
        if self._payload_size(payload) > self.max_payload_bytes:
            return self._reject("payload_too_large")

        prio = normalize_priority(priority)
        message = QueuedMessage(
            tenant_id=tenant,
            event_type=event,
            payload=dict(payload),
            priority=prio,
            trace_id=trace_id or uuid4().hex,
            max_attempts=max(1, int(max_attempts)),
        )

        with self._lock:
            if self._tenant_depth[tenant] >= self.per_tenant_limit:
                return self._reject("tenant_queue_limit")
            if self.total_depth >= self.max_size and not self._shed_lower_priority(prio):
                return self._reject("queue_full")
            self._queues[prio].append(message)
            self._tenant_depth[tenant] += 1
            self._submitted += 1
            return QueueSubmitResult(
                accepted=True,
                message_id=message.message_id,
                reason="queued",
                queue_depth=self.total_depth,
            )

    def next_batch(self, limit: int = 100, *, tenant_id: str | None = None) -> list[QueuedMessage]:
        if limit <= 0:
            return []
        batch: list[QueuedMessage] = []
        tenant_filter = str(tenant_id).strip() if tenant_id else None
        with self._lock:
            for priority in PRIORITY_ORDER:
                if len(batch) >= limit:
                    break
                queue = self._queues[priority]
                scanned = 0
                while queue and len(batch) < limit and scanned < len(queue):
                    message = queue.popleft()
                    scanned += 1
                    if tenant_filter and message.tenant_id != tenant_filter:
                        queue.append(message)
                        continue
                    self._tenant_depth[message.tenant_id] -= 1
                    if self._tenant_depth[message.tenant_id] <= 0:
                        self._tenant_depth.pop(message.tenant_id, None)
                    message.attempts += 1
                    self._inflight[message.message_id] = message
                    batch.append(message)
        return batch

    def ack(self, message_id: str) -> bool:
        with self._lock:
            return self._inflight.pop(message_id, None) is not None

    def fail(self, message_id: str, reason: str = "worker_failed") -> bool:
        with self._lock:
            message = self._inflight.pop(message_id, None)
            if not message:
                return False
            message.last_error = str(reason or "worker_failed")[:240]
            if message.attempts >= message.max_attempts:
                self._to_dead_letter(message, "max_attempts")
                return True
            if self.total_depth >= self.max_size and not self._shed_lower_priority(message.priority):
                self._to_dead_letter(message, "retry_queue_full")
                return True
            self._queues[message.priority].append(message)
            self._tenant_depth[message.tenant_id] += 1
            self._retried += 1
            return True

    def mark_poison(self, message_id: str, reason: str = "poison_message") -> bool:
        with self._lock:
            message = self._inflight.pop(message_id, None)
            if not message:
                return False
            self._to_dead_letter(message, reason)
            return True

    def recover_dead_letters(self, limit: int = 100, *, tenant_id: str | None = None) -> int:
        if limit <= 0:
            return 0
        recovered = 0
        tenant_filter = str(tenant_id).strip() if tenant_id else None
        with self._lock:
            retained: Deque[QueuedMessage] = deque(maxlen=self.dead_letter_size)
            while self._dead_letter:
                message = self._dead_letter.popleft()
                if recovered < limit and (not tenant_filter or message.tenant_id == tenant_filter):
                    message.last_error = ""
                    if self.total_depth < self.max_size:
                        self._queues[message.priority].append(message)
                        self._tenant_depth[message.tenant_id] += 1
                        recovered += 1
                        continue
                retained.append(message)
            self._dead_letter = retained
        return recovered

    @property
    def total_depth(self) -> int:
        return sum(len(queue) for queue in self._queues.values())

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            snapshot = QueueSnapshot(
                max_size=self.max_size,
                total_depth=self.total_depth,
                by_priority={priority: len(self._queues[priority]) for priority in PRIORITY_ORDER},
                by_tenant=dict(self._tenant_depth),
                inflight=len(self._inflight),
                dead_letter_depth=len(self._dead_letter),
                submitted=self._submitted,
                rejected=self._rejected,
                dropped=self._dropped,
                retried=self._retried,
            )
            return snapshot.to_dict()

    def dead_letters(self, limit: int = 50) -> list[Dict[str, Any]]:
        with self._lock:
            return [message.to_dict() for message in list(self._dead_letter)[-max(0, limit):]]

    def _reject(self, reason: str) -> QueueSubmitResult:
        with self._lock:
            self._rejected += 1
            depth = self.total_depth
        return QueueSubmitResult(accepted=False, reason=reason, queue_depth=depth)

    def _payload_size(self, payload: Mapping[str, Any]) -> int:
        try:
            return len(json.dumps(payload, default=str, sort_keys=True).encode("utf-8"))
        except Exception:
            return self.max_payload_bytes + 1

    def _shed_lower_priority(self, incoming_priority: str) -> bool:
        incoming_rank = PRIORITY_RANK[normalize_priority(incoming_priority)]
        for priority in reversed(PRIORITY_ORDER):
            if PRIORITY_RANK[priority] <= incoming_rank:
                continue
            queue = self._queues[priority]
            if not queue:
                continue
            dropped = queue.popleft()
            self._tenant_depth[dropped.tenant_id] -= 1
            if self._tenant_depth[dropped.tenant_id] <= 0:
                self._tenant_depth.pop(dropped.tenant_id, None)
            self._to_dead_letter(dropped, "shed_for_higher_priority")
            self._dropped += 1
            return True
        return False

    def _to_dead_letter(self, message: QueuedMessage, reason: str) -> None:
        message.last_error = reason
        if len(self._dead_letter) >= self.dead_letter_size:
            self._dropped += 1
        self._dead_letter.append(message)


def queue_pressure(snapshot: Mapping[str, Any]) -> float:
    max_size = max(1, int(snapshot.get("max_size") or 1))
    return min(1.0, max(0.0, float(snapshot.get("total_depth") or 0) / max_size))


def drain_messages(messages: Iterable[QueuedMessage]) -> list[Dict[str, Any]]:
    return [message.to_dict() for message in messages]
