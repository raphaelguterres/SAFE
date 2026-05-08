"""Realtime stream hub for SAFE SOC clients.

This module is transport-agnostic: Flask routes can expose it through SSE today
and a WebSocket adapter later without changing the tenant-scoped subscription
model.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Deque, Dict, Mapping, Sequence
from uuid import uuid4

from .event_bus import LiveSOCEventBus, get_event_bus, normalize_channel


READ_ONLY_CHANNELS = {
    "detections",
    "incidents",
    "approvals",
    "host_state",
    "telemetry_alerts",
    "orchestration",
    "response_queue",
    "metrics",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class StreamClient:
    client_id: str
    tenant_id: str
    user_id: str
    channels: tuple[str, ...]
    subscriptions: tuple[str, ...]
    connected_at: str
    last_heartbeat_at: str
    last_poll_at: str | None = None
    disconnected: bool = False
    events_sent: int = 0
    rate_limit_hits: int = 0
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "client_id": self.client_id,
            "tenant_id": self.tenant_id,
            "user_id": self.user_id,
            "channels": list(self.channels),
            "connected_at": self.connected_at,
            "last_heartbeat_at": self.last_heartbeat_at,
            "last_poll_at": self.last_poll_at,
            "disconnected": self.disconnected,
            "events_sent": self.events_sent,
            "rate_limit_hits": self.rate_limit_hits,
        }


class RealtimeStreamHub:
    """Manage authenticated tenant-scoped realtime clients."""

    def __init__(
        self,
        *,
        event_bus: LiveSOCEventBus | None = None,
        max_clients_per_tenant: int = 100,
        max_events_per_minute: int = 1_000,
        heartbeat_timeout_seconds: int = 90,
    ) -> None:
        self.event_bus = event_bus or get_event_bus()
        self.max_clients_per_tenant = max(1, int(max_clients_per_tenant))
        self.max_events_per_minute = max(1, int(max_events_per_minute))
        self.heartbeat_timeout = timedelta(seconds=max(10, int(heartbeat_timeout_seconds)))
        self._clients: Dict[str, StreamClient] = {}
        self._tenant_clients: dict[str, set[str]] = defaultdict(set)
        self._rate_windows: dict[str, Deque[datetime]] = defaultdict(deque)
        self._lock = RLock()

    def connect(
        self,
        *,
        tenant_id: str,
        user_id: str,
        channels: Sequence[str],
        auth_context: Mapping[str, Any],
        metadata: Mapping[str, Any] | None = None,
    ) -> StreamClient:
        tenant = str(tenant_id or "").strip()
        user = str(user_id or "").strip()
        if not self._auth_allows(tenant, auth_context):
            raise PermissionError("stream_auth_failed")
        if not user:
            raise PermissionError("missing_user")
        normalized = tuple(self._normalize_channels(channels))
        if not normalized:
            raise ValueError("at least one channel is required")

        with self._lock:
            self.cleanup_stale_locked()
            if len(self._tenant_clients[tenant]) >= self.max_clients_per_tenant:
                raise RuntimeError("tenant_stream_client_limit")
            subscriptions = tuple(
                self.event_bus.subscribe(
                    tenant_id=tenant,
                    channel=channel,
                    consumer_id=f"stream:{user}",
                    max_queue_size=500,
                ).subscription_id
                for channel in normalized
            )
            current = _now().isoformat()
            client = StreamClient(
                client_id=uuid4().hex,
                tenant_id=tenant,
                user_id=user,
                channels=normalized,
                subscriptions=subscriptions,
                connected_at=current,
                last_heartbeat_at=current,
                metadata=dict(metadata or {}),
            )
            self._clients[client.client_id] = client
            self._tenant_clients[tenant].add(client.client_id)
            return client

    def publish(
        self,
        *,
        tenant_id: str,
        channel: str,
        event_type: str,
        payload: Mapping[str, Any],
        priority: str = "P2",
        trace_id: str | None = None,
    ) -> Dict[str, Any]:
        chan = normalize_channel(channel)
        if chan not in READ_ONLY_CHANNELS and not chan.startswith("host:") and not chan.startswith("incident:"):
            raise ValueError("unsupported_stream_channel")
        event = self.event_bus.publish(
            tenant_id=tenant_id,
            channel=chan,
            event_type=event_type,
            payload=payload,
            priority=priority,
            trace_id=trace_id,
        )
        return event.to_dict()

    def poll(self, client_id: str, limit: int = 100) -> list[Dict[str, Any]]:
        with self._lock:
            client = self._clients.get(client_id)
            if not client or client.disconnected:
                raise PermissionError("stream_client_inactive")
            if not self._rate_allows(client):
                client.rate_limit_hits += 1
                return [{"event_type": "rate_limited", "retry_after_seconds": 5, "tenant_id": client.tenant_id}]
            client.last_poll_at = _now().isoformat()
            events: list[Dict[str, Any]] = []
            for subscription_id in client.subscriptions:
                if len(events) >= limit:
                    break
                events.extend(self.event_bus.poll(subscription_id, limit - len(events)))
            client.events_sent += len(events)
            return events

    def heartbeat(self, client_id: str) -> Dict[str, Any]:
        with self._lock:
            client = self._clients.get(client_id)
            if not client or client.disconnected:
                raise PermissionError("stream_client_inactive")
            client.last_heartbeat_at = _now().isoformat()
            return {"ok": True, "client_id": client_id, "server_time": client.last_heartbeat_at}

    def disconnect(self, client_id: str) -> bool:
        with self._lock:
            client = self._clients.pop(client_id, None)
            if not client:
                return False
            client.disconnected = True
            self._tenant_clients[client.tenant_id].discard(client_id)
            for subscription_id in client.subscriptions:
                self.event_bus.unsubscribe(subscription_id)
            self._rate_windows.pop(client_id, None)
            return True

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            self.cleanup_stale_locked()
            return {
                "active_clients": len(self._clients),
                "max_clients_per_tenant": self.max_clients_per_tenant,
                "heartbeat_timeout_seconds": int(self.heartbeat_timeout.total_seconds()),
                "clients_by_tenant": {tenant: len(ids) for tenant, ids in self._tenant_clients.items()},
                "clients": [client.to_dict() for client in self._clients.values()],
                "event_bus": self.event_bus.snapshot(),
            }

    def cleanup_stale_locked(self) -> int:
        now = _now()
        stale: list[str] = []
        for client_id, client in self._clients.items():
            last = datetime.fromisoformat(client.last_heartbeat_at)
            if now - last > self.heartbeat_timeout:
                stale.append(client_id)
        for client_id in stale:
            self.disconnect(client_id)
        return len(stale)

    def _normalize_channels(self, channels: Sequence[str]) -> list[str]:
        normalized: list[str] = []
        for channel in channels:
            value = normalize_channel(channel)
            if not value:
                continue
            if value in READ_ONLY_CHANNELS or value.startswith("host:") or value.startswith("incident:"):
                normalized.append(value)
        return normalized

    def _auth_allows(self, tenant_id: str, auth_context: Mapping[str, Any]) -> bool:
        if not tenant_id or not auth_context:
            return False
        if not bool(auth_context.get("authenticated")):
            return False
        auth_tenant = str(auth_context.get("tenant_id") or "").strip()
        role = str(auth_context.get("role") or "").lower()
        return auth_tenant == tenant_id or role in {"owner", "admin"}

    def _rate_allows(self, client: StreamClient) -> bool:
        now = _now()
        window = self._rate_windows[client.client_id]
        cutoff = now - timedelta(minutes=1)
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= self.max_events_per_minute:
            return False
        window.append(now)
        return True


def host_channel(host_id: str) -> str:
    return f"host:{normalize_channel(host_id)}"


def incident_channel(incident_id: str) -> str:
    return f"incident:{normalize_channel(incident_id)}"


_GLOBAL_STREAM_HUB: RealtimeStreamHub | None = None


def get_realtime_stream_hub() -> RealtimeStreamHub:
    global _GLOBAL_STREAM_HUB
    if _GLOBAL_STREAM_HUB is None:
        _GLOBAL_STREAM_HUB = RealtimeStreamHub()
    return _GLOBAL_STREAM_HUB
