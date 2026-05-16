"""Optional Redis-backed queue backend for SAFE operational reliability."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import re
from typing import Any, Mapping
from uuid import uuid4

from .queue_manager import PRIORITY_ORDER, QueuedMessage, QueueSubmitResult, normalize_priority


class RedisQueueBackend:
    """Priority queue adapter with tenant-isolated Redis keys.

    Redis is optional. The local/demo path remains the in-process
    ResilientQueueManager; this adapter is used only when SAFE_QUEUE_BACKEND=redis.
    """

    def __init__(
        self,
        *,
        client,
        namespace: str = "safe:xdr",
        max_size: int = 10_000,
        dead_letter_size: int = 1_000,
        max_payload_bytes: int = 256_000,
    ) -> None:
        self.client = client
        self.namespace = _clean_namespace(namespace)
        self.max_size = max(1, int(max_size))
        self.dead_letter_size = max(1, int(dead_letter_size))
        self.max_payload_bytes = max(1024, int(max_payload_bytes))

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
        if self._total_depth() >= self.max_size:
            return self._reject("queue_full")

        message = QueuedMessage(
            tenant_id=tenant,
            event_type=event,
            payload=dict(payload),
            priority=normalize_priority(priority),
            trace_id=trace_id or uuid4().hex,
            max_attempts=max(1, int(max_attempts)),
        )
        encoded = json.dumps(message.to_dict(), sort_keys=True, default=str)
        self.client.sadd(self._tenants_key(), self._tenant_token(tenant))
        self.client.hset(self._tenant_names_key(), self._tenant_token(tenant), tenant)
        self.client.rpush(self._queue_key(tenant, message.priority), encoded)
        self.client.incr(self._metric_key("enqueue_count"))
        return QueueSubmitResult(
            accepted=True,
            message_id=message.message_id,
            reason="queued",
            queue_depth=self._total_depth(),
        )

    def next_batch(self, limit: int = 100, *, tenant_id: str | None = None) -> list[QueuedMessage]:
        if limit <= 0:
            return []
        tenants = [str(tenant_id).strip()] if tenant_id else self._known_tenants()
        batch: list[QueuedMessage] = []
        for priority in PRIORITY_ORDER:
            for tenant in tenants:
                while len(batch) < limit:
                    raw = self.client.lpop(self._queue_key(tenant, priority))
                    if raw is None:
                        break
                    message = self._decode_message(raw)
                    message.attempts += 1
                    self.client.hset(self._inflight_key(), message.message_id, json.dumps(message.to_dict(), sort_keys=True, default=str))
                    self.client.incr(self._metric_key("dequeue_count"))
                    batch.append(message)
                if len(batch) >= limit:
                    break
            if len(batch) >= limit:
                break
        return batch

    def ack(self, message_id: str) -> bool:
        return bool(self.client.hdel(self._inflight_key(), str(message_id)))

    def fail(self, message_id: str, reason: str = "worker_failed") -> bool:
        raw = self.client.hget(self._inflight_key(), str(message_id))
        if raw is None:
            return False
        self.client.hdel(self._inflight_key(), str(message_id))
        message = self._decode_message(raw)
        message.last_error = str(reason or "worker_failed")[:240]
        if message.attempts >= message.max_attempts:
            self._dead_letter(message, "max_attempts")
            return True
        self.client.rpush(self._queue_key(message.tenant_id, message.priority), json.dumps(message.to_dict(), sort_keys=True, default=str))
        self.client.incr(self._metric_key("retry_count"))
        return True

    def recover_dead_letters(self, limit: int = 100, *, tenant_id: str | None = None) -> int:
        recovered = 0
        retained: list[str] = []
        while recovered < max(0, limit):
            raw = self.client.lpop(self._dead_letter_key())
            if raw is None:
                break
            message = self._decode_message(raw)
            if tenant_id and message.tenant_id != tenant_id:
                retained.append(self._encode(message))
                continue
            message.last_error = ""
            self.client.rpush(self._queue_key(message.tenant_id, message.priority), self._encode(message))
            recovered += 1
        for raw in retained:
            self.client.rpush(self._dead_letter_key(), raw)
        return recovered

    def snapshot(self) -> dict[str, Any]:
        by_priority = {priority: 0 for priority in PRIORITY_ORDER}
        by_tenant: Counter[str] = Counter()
        for tenant in self._known_tenants():
            for priority in PRIORITY_ORDER:
                depth = int(self.client.llen(self._queue_key(tenant, priority)) or 0)
                by_priority[priority] += depth
                by_tenant[tenant] += depth
        total = sum(by_priority.values())
        return {
            "backend": "redis",
            "max_size": self.max_size,
            "total_depth": total,
            "queue_depth": total,
            "by_priority": by_priority,
            "by_tenant": dict(by_tenant),
            "inflight": int(self.client.hlen(self._inflight_key()) or 0),
            "dead_letter_depth": int(self.client.llen(self._dead_letter_key()) or 0),
            "enqueue_count": self._metric("enqueue_count"),
            "dequeue_count": self._metric("dequeue_count"),
            "retry_count": self._metric("retry_count"),
            "dead_letter_count": self._metric("dead_letter_count"),
            "submitted": self._metric("enqueue_count"),
            "rejected": self._metric("rejected_count"),
            "dropped": 0,
            "retried": self._metric("retry_count"),
        }

    def dead_letters(self, limit: int = 50) -> list[dict[str, Any]]:
        values = self.client.lrange(self._dead_letter_key(), 0, max(0, int(limit)) - 1)
        return [self._decode_message(raw).to_dict() for raw in values]

    def _reject(self, reason: str) -> QueueSubmitResult:
        self.client.incr(self._metric_key("rejected_count"))
        return QueueSubmitResult(accepted=False, reason=reason, queue_depth=self._total_depth())

    def _dead_letter(self, message: QueuedMessage, reason: str) -> None:
        message.last_error = reason
        self.client.lpush(self._dead_letter_key(), self._encode(message))
        self.client.ltrim(self._dead_letter_key(), 0, self.dead_letter_size - 1)
        self.client.incr(self._metric_key("dead_letter_count"))

    def _known_tenants(self) -> list[str]:
        tokens = self.client.smembers(self._tenants_key()) or []
        names = []
        for token in tokens:
            if isinstance(token, bytes):
                token = token.decode("utf-8")
            name = self.client.hget(self._tenant_names_key(), str(token))
            if isinstance(name, bytes):
                name = name.decode("utf-8")
            if name:
                names.append(str(name))
        return sorted(set(names))

    def _total_depth(self) -> int:
        return sum(int(self.client.llen(self._queue_key(tenant, priority)) or 0) for tenant in self._known_tenants() for priority in PRIORITY_ORDER)

    def _queue_key(self, tenant_id: str, priority: str) -> str:
        return f"{self.namespace}:tenant:{self._tenant_token(tenant_id)}:queue:{normalize_priority(priority)}"

    def _tenant_token(self, tenant_id: str) -> str:
        clean = re.sub(r"[^a-zA-Z0-9_.-]+", "_", tenant_id.strip())[:48] or "default"
        digest = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()[:12]
        return f"{clean}:{digest}"

    def _tenants_key(self) -> str:
        return f"{self.namespace}:tenants"

    def _tenant_names_key(self) -> str:
        return f"{self.namespace}:tenant_names"

    def _inflight_key(self) -> str:
        return f"{self.namespace}:inflight"

    def _dead_letter_key(self) -> str:
        return f"{self.namespace}:dead_letter"

    def _metric_key(self, name: str) -> str:
        return f"{self.namespace}:metrics:{name}"

    def _metric(self, name: str) -> int:
        value = self.client.get(self._metric_key(name))
        if isinstance(value, bytes):
            value = value.decode("utf-8")
        return int(value or 0)

    def _payload_size(self, payload: Mapping[str, Any]) -> int:
        try:
            return len(json.dumps(payload, default=str, sort_keys=True).encode("utf-8"))
        except Exception:
            return self.max_payload_bytes + 1

    def _decode_message(self, raw) -> QueuedMessage:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        data = json.loads(raw)
        return QueuedMessage(
            tenant_id=str(data["tenant_id"]),
            event_type=str(data["event_type"]),
            payload=data.get("payload") or {},
            priority=normalize_priority(data.get("priority")),
            message_id=str(data["message_id"]),
            trace_id=str(data.get("trace_id") or ""),
            created_at=str(data.get("created_at") or ""),
            attempts=int(data.get("attempts") or 0),
            max_attempts=int(data.get("max_attempts") or 3),
            last_error=str(data.get("last_error") or ""),
        )

    def _encode(self, message: QueuedMessage) -> str:
        return json.dumps(message.to_dict(), sort_keys=True, default=str)


def build_redis_client(redis_url: str):
    import redis  # type: ignore

    client = redis.Redis.from_url(redis_url, socket_connect_timeout=1.0, socket_timeout=1.0, decode_responses=True)
    client.ping()
    return client


def _clean_namespace(namespace: str) -> str:
    return re.sub(r"[^a-zA-Z0-9:_-]+", "_", namespace.strip() or "safe:xdr")
