"""Tenant-scoped in-process event bus for live SAFE operations."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Deque, Dict, Mapping
from uuid import uuid4

from .queue_manager import normalize_priority


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class BusEvent:
    event_id: str
    tenant_id: str
    channel: str
    event_type: str
    payload: Mapping[str, Any]
    priority: str
    trace_id: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "channel": self.channel,
            "event_type": self.event_type,
            "payload": dict(self.payload),
            "priority": self.priority,
            "trace_id": self.trace_id,
            "created_at": self.created_at,
        }


@dataclass
class EventSubscription:
    subscription_id: str
    tenant_id: str
    channel: str
    consumer_id: str
    max_queue_size: int
    created_at: str = field(default_factory=_now)
    last_poll_at: str | None = None
    dropped_events: int = 0
    backlog: Deque[BusEvent] = field(default_factory=deque)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "subscription_id": self.subscription_id,
            "tenant_id": self.tenant_id,
            "channel": self.channel,
            "consumer_id": self.consumer_id,
            "created_at": self.created_at,
            "last_poll_at": self.last_poll_at,
            "backlog": len(self.backlog),
            "dropped_events": self.dropped_events,
            "max_queue_size": self.max_queue_size,
        }


class LiveSOCEventBus:
    """Small pub/sub fabric with bounded per-consumer buffers."""

    def __init__(self, *, default_consumer_queue_size: int = 250, dead_letter_size: int = 1_000) -> None:
        self.default_consumer_queue_size = max(1, int(default_consumer_queue_size))
        self.dead_letter_size = max(1, int(dead_letter_size))
        self._subscriptions: Dict[str, EventSubscription] = {}
        self._tenant_index: dict[str, set[str]] = defaultdict(set)
        self._dead_letter: Deque[Dict[str, Any]] = deque(maxlen=self.dead_letter_size)
        self._lock = RLock()
        self._published = 0
        self._delivered = 0
        self._dropped = 0

    def subscribe(
        self,
        *,
        tenant_id: str,
        channel: str,
        consumer_id: str,
        max_queue_size: int | None = None,
    ) -> EventSubscription:
        tenant = str(tenant_id or "").strip()
        chan = normalize_channel(channel)
        consumer = str(consumer_id or "").strip()
        if not tenant or not chan or not consumer:
            raise ValueError("tenant_id, channel and consumer_id are required")
        subscription = EventSubscription(
            subscription_id=uuid4().hex,
            tenant_id=tenant,
            channel=chan,
            consumer_id=consumer,
            max_queue_size=max(1, int(max_queue_size or self.default_consumer_queue_size)),
        )
        with self._lock:
            self._subscriptions[subscription.subscription_id] = subscription
            self._tenant_index[tenant].add(subscription.subscription_id)
        return subscription

    def unsubscribe(self, subscription_id: str) -> bool:
        with self._lock:
            subscription = self._subscriptions.pop(subscription_id, None)
            if not subscription:
                return False
            self._tenant_index[subscription.tenant_id].discard(subscription_id)
            return True

    def publish(
        self,
        *,
        tenant_id: str,
        channel: str,
        event_type: str,
        payload: Mapping[str, Any],
        priority: str = "P2",
        trace_id: str | None = None,
    ) -> BusEvent:
        tenant = str(tenant_id or "").strip()
        chan = normalize_channel(channel)
        event_name = str(event_type or "").strip()
        if not tenant or not chan or not event_name:
            raise ValueError("tenant_id, channel and event_type are required")
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a mapping")

        event = BusEvent(
            event_id=uuid4().hex,
            tenant_id=tenant,
            channel=chan,
            event_type=event_name,
            payload=dict(payload),
            priority=normalize_priority(priority),
            trace_id=trace_id or uuid4().hex,
            created_at=_now(),
        )
        with self._lock:
            self._published += 1
            for sub_id in list(self._tenant_index.get(tenant, set())):
                subscription = self._subscriptions.get(sub_id)
                if not subscription or not channel_matches(subscription.channel, chan):
                    continue
                self._deliver(subscription, event)
        return event

    def poll(self, subscription_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        if limit <= 0:
            return []
        with self._lock:
            subscription = self._subscriptions.get(subscription_id)
            if not subscription:
                return []
            subscription.last_poll_at = _now()
            events: list[Dict[str, Any]] = []
            while subscription.backlog and len(events) < limit:
                events.append(subscription.backlog.popleft().to_dict())
            return events

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "published": self._published,
                "delivered": self._delivered,
                "dropped": self._dropped,
                "dead_letter_depth": len(self._dead_letter),
                "subscriptions": [sub.snapshot() for sub in self._subscriptions.values()],
                "tenants": {tenant: len(ids) for tenant, ids in self._tenant_index.items()},
            }

    def dead_letters(self, limit: int = 50) -> list[Dict[str, Any]]:
        with self._lock:
            return list(self._dead_letter)[-max(0, limit):]

    def _deliver(self, subscription: EventSubscription, event: BusEvent) -> None:
        if len(subscription.backlog) >= subscription.max_queue_size:
            dropped = subscription.backlog.popleft()
            subscription.dropped_events += 1
            self._dropped += 1
            self._dead_letter.append(
                {
                    "reason": "consumer_backpressure",
                    "subscription_id": subscription.subscription_id,
                    "event": dropped.to_dict(),
                    "recorded_at": _now(),
                }
            )
        subscription.backlog.append(event)
        self._delivered += 1


def normalize_channel(channel: str | None) -> str:
    value = str(channel or "").strip().lower().replace(" ", "_")
    return value.strip(":")


def channel_matches(subscription_channel: str, event_channel: str) -> bool:
    sub = normalize_channel(subscription_channel)
    event = normalize_channel(event_channel)
    if sub in {"*", "all"}:
        return True
    if sub.endswith(":*"):
        return event.startswith(sub[:-1])
    return sub == event


_GLOBAL_EVENT_BUS: LiveSOCEventBus | None = None


def get_event_bus() -> LiveSOCEventBus:
    global _GLOBAL_EVENT_BUS
    if _GLOBAL_EVENT_BUS is None:
        _GLOBAL_EVENT_BUS = LiveSOCEventBus()
    return _GLOBAL_EVENT_BUS
