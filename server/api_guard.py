"""API abuse guard for tenant and agent-scoped ingest surfaces."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Any


DEFAULT_EVENT_TYPES = {
    "authentication",
    "file_change",
    "heartbeat",
    "host_heartbeat",
    "host_inventory",
    "memory_indicator",
    "network_connection",
    "behavioral_anomaly",
    "persistence_indicator",
    "port_scan",
    "process_execution",
    "registry_change",
    "script_execution",
    "security_event",
    "telemetry",
}


@dataclass(frozen=True, slots=True)
class ApiGuardDecision:
    allowed: bool
    reason: str
    status_code: int = 200
    retry_after: int = 0
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["details"] = dict(self.details or {})
        return payload


class ApiAbuseGuard:
    """Bounded per-tenant/per-agent rate and payload guard."""

    def __init__(
        self,
        *,
        max_payload_bytes: int = 1024 * 1024,
        max_batch_events: int = 500,
        rate_limit_per_minute: int = 1200,
        event_type_whitelist: set[str] | None = None,
    ):
        self.max_payload_bytes = max(1024, int(max_payload_bytes))
        self.max_batch_events = max(1, int(max_batch_events))
        self.rate_limit_per_minute = max(1, int(rate_limit_per_minute))
        self.event_type_whitelist = set(event_type_whitelist or DEFAULT_EVENT_TYPES)
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def inspect(
        self,
        *,
        endpoint: str,
        tenant_id: str = "default",
        agent_id: str = "",
        content_length: int | None = None,
        payload: Any = None,
        now: float | None = None,
    ) -> ApiGuardDecision:
        if content_length is not None and int(content_length or 0) > self.max_payload_bytes:
            return ApiGuardDecision(False, "payload_too_large", 413, details={"max_bytes": self.max_payload_bytes})

        events = _events(payload)
        if len(events) > self.max_batch_events:
            return ApiGuardDecision(False, "batch_too_large", 413, details={"max_events": self.max_batch_events})

        invalid_types = sorted(
            {
                str(event.get("event_type") or "").strip().lower()
                for event in events
                if str(event.get("event_type") or "").strip().lower()
                and str(event.get("event_type") or "").strip().lower() not in self.event_type_whitelist
            }
        )
        if invalid_types:
            return ApiGuardDecision(False, "event_type_not_allowed", 400, details={"event_types": invalid_types[:10]})

        now_value = time.time() if now is None else float(now)
        key = f"{tenant_id or 'default'}:{agent_id or 'unknown'}:{endpoint}"
        bucket = self._hits[key]
        cutoff = now_value - 60
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.rate_limit_per_minute:
            return ApiGuardDecision(False, "rate_limited", 429, retry_after=1)
        bucket.append(now_value)
        return ApiGuardDecision(True, "ok")

    def snapshot(self) -> dict[str, Any]:
        return {
            "max_payload_bytes": self.max_payload_bytes,
            "max_batch_events": self.max_batch_events,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "active_buckets": len(self._hits),
        }


def _events(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        raw = payload.get("events")
        if raw is None:
            raw = [payload] if payload.get("event_type") else []
    elif isinstance(payload, list):
        raw = payload
    else:
        raw = []
    return [dict(item) for item in raw if isinstance(item, dict)]
