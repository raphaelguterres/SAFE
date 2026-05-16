from __future__ import annotations

from collections import defaultdict, deque

import pytest

from server.queue_config import build_operational_queue_manager
from xdr.redis_queue_backend import RedisQueueBackend
from xdr.queue_manager import ResilientQueueManager


class FakeRedis:
    def __init__(self, fail_ping=False):
        self.fail_ping = fail_ping
        self.lists = defaultdict(deque)
        self.sets = defaultdict(set)
        self.hashes = defaultdict(dict)
        self.values = defaultdict(int)

    def ping(self):
        if self.fail_ping:
            raise OSError("redis down")
        return True

    def sadd(self, key, value):
        self.sets[key].add(value)

    def smembers(self, key):
        return set(self.sets[key])

    def hset(self, key, field, value):
        self.hashes[key][field] = value

    def hget(self, key, field):
        return self.hashes[key].get(field)

    def hdel(self, key, field):
        return 1 if self.hashes[key].pop(field, None) is not None else 0

    def hlen(self, key):
        return len(self.hashes[key])

    def rpush(self, key, value):
        self.lists[key].append(value)

    def lpush(self, key, value):
        self.lists[key].appendleft(value)

    def lpop(self, key):
        if not self.lists[key]:
            return None
        return self.lists[key].popleft()

    def llen(self, key):
        return len(self.lists[key])

    def ltrim(self, key, start, stop):
        items = list(self.lists[key])[start : stop + 1]
        self.lists[key] = deque(items)

    def lrange(self, key, start, stop):
        return list(self.lists[key])[start : stop + 1]

    def incr(self, key):
        self.values[key] += 1
        return self.values[key]

    def get(self, key):
        return self.values.get(key, 0)


def test_redis_queue_preserves_tenant_isolation_and_metrics():
    redis = FakeRedis()
    queue = RedisQueueBackend(client=redis, namespace="safe:test")

    first = queue.submit(tenant_id="tenant-a", event_type="telemetry", payload={"n": 1}, priority="P1")
    queue.submit(tenant_id="tenant-b", event_type="telemetry", payload={"n": 2}, priority="P0")

    assert first.accepted is True
    assert queue.snapshot()["enqueue_count"] == 2

    batch = queue.next_batch(limit=10, tenant_id="tenant-a")

    assert len(batch) == 1
    assert batch[0].tenant_id == "tenant-a"
    assert queue.ack(batch[0].message_id) is True
    assert queue.snapshot()["dequeue_count"] == 1
    assert queue.snapshot()["by_tenant"]["tenant-b"] == 1


def test_redis_queue_dead_letters_after_retry_budget():
    redis = FakeRedis()
    queue = RedisQueueBackend(client=redis, namespace="safe:test")
    queue.submit(tenant_id="tenant-a", event_type="telemetry", payload={"ok": True}, max_attempts=1)
    message = queue.next_batch(limit=1)[0]

    assert queue.fail(message.message_id, "boom") is True

    snapshot = queue.snapshot()
    assert snapshot["dead_letter_depth"] == 1
    assert snapshot["dead_letter_count"] == 1


def test_queue_config_defaults_to_memory(monkeypatch):
    monkeypatch.delenv("SAFE_QUEUE_BACKEND", raising=False)

    queue = build_operational_queue_manager(max_size=10)

    assert isinstance(queue, ResilientQueueManager)


def test_queue_config_falls_back_to_memory_when_redis_optional(monkeypatch):
    monkeypatch.setenv("SAFE_QUEUE_BACKEND", "redis")
    monkeypatch.setenv("SAFE_REDIS_REQUIRED", "false")

    queue = build_operational_queue_manager(max_size=10, redis_client=FakeRedis(fail_ping=True))

    assert isinstance(queue, ResilientQueueManager)
    assert getattr(queue, "backend") == "memory-fallback"


def test_queue_config_fails_when_redis_required(monkeypatch):
    monkeypatch.setenv("SAFE_QUEUE_BACKEND", "redis")
    monkeypatch.setenv("SAFE_REDIS_REQUIRED", "true")

    with pytest.raises(RuntimeError):
        build_operational_queue_manager(max_size=10, redis_client=FakeRedis(fail_ping=True))
