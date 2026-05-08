"""Operational observability registry for SAFE XDR."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from statistics import mean
from threading import RLock
from typing import Any, Deque, Dict, Mapping


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class LatencyWindow:
    values: Deque[float] = field(default_factory=lambda: deque(maxlen=500))

    def observe(self, value_ms: float) -> None:
        self.values.append(max(0.0, float(value_ms)))

    def snapshot(self) -> Dict[str, float]:
        values = list(self.values)
        if not values:
            return {"avg_ms": 0.0, "p95_ms": 0.0, "max_ms": 0.0}
        sorted_values = sorted(values)
        p95_index = min(len(sorted_values) - 1, int(len(sorted_values) * 0.95))
        return {
            "avg_ms": round(mean(values), 3),
            "p95_ms": round(sorted_values[p95_index], 3),
            "max_ms": round(max(values), 3),
        }


class ObservabilityRegistry:
    """Track latency, throughput and reliability counters in memory."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._counters: Counter[str] = Counter()
        self._tenant_counters: dict[str, Counter[str]] = defaultdict(Counter)
        self._latencies: dict[str, LatencyWindow] = defaultdict(LatencyWindow)
        self._last_events: Deque[Dict[str, Any]] = deque(maxlen=200)
        self.started_at = _now()

    def increment(self, name: str, value: int = 1, *, tenant_id: str | None = None) -> None:
        key = normalize_metric(name)
        amount = int(value)
        with self._lock:
            self._counters[key] += amount
            if tenant_id:
                self._tenant_counters[str(tenant_id)][key] += amount

    def observe_latency(self, name: str, value_ms: float, *, tenant_id: str | None = None) -> None:
        key = normalize_metric(name)
        with self._lock:
            self._latencies[key].observe(value_ms)
            if tenant_id:
                self._latencies[f"{str(tenant_id)}:{key}"].observe(value_ms)

    def record_event(self, event_type: str, detail: Mapping[str, Any] | None = None, *, tenant_id: str | None = None) -> None:
        with self._lock:
            self._last_events.append(
                {
                    "event_type": str(event_type or "operational_event"),
                    "tenant_id": tenant_id or "system",
                    "detail": dict(detail or {}),
                    "recorded_at": _now(),
                }
            )
            self.increment(f"event.{event_type}", tenant_id=tenant_id)

    def snapshot(
        self,
        *,
        queue_snapshot: Mapping[str, Any] | None = None,
        stream_snapshot: Mapping[str, Any] | None = None,
        worker_snapshot: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        with self._lock:
            counters = dict(self._counters)
            latency = {name: window.snapshot() for name, window in self._latencies.items() if ":" not in name}
            dropped = counters.get("dropped_events", 0) + int((queue_snapshot or {}).get("dropped") or 0)
            replay_retry = counters.get("replay_attempts", 0) + counters.get("retry_attempts", 0)
            return {
                "started_at": self.started_at,
                "generated_at": _now(),
                "counters": counters,
                "tenant_counters": {tenant: dict(values) for tenant, values in self._tenant_counters.items()},
                "latency": latency,
                "worker_latency": latency.get("worker_latency", {}),
                "ingestion_latency": latency.get("ingestion_latency", {}),
                "websocket_latency": latency.get("websocket_latency", {}),
                "queue_pressure": queue_pressure_value(queue_snapshot or {}),
                "dropped_events": dropped,
                "telemetry_throughput": counters.get("telemetry_events", 0),
                "orchestration_failures": counters.get("orchestration_failures", 0),
                "replay_retry_counts": replay_retry,
                "queue": dict(queue_snapshot or {}),
                "streaming": dict(stream_snapshot or {}),
                "workers": dict(worker_snapshot or {}),
                "recent_events": list(self._last_events),
            }


def normalize_metric(name: str) -> str:
    return str(name or "metric").strip().lower().replace(" ", "_").replace("-", "_")


def queue_pressure_value(snapshot: Mapping[str, Any]) -> float:
    max_size = max(1, int(snapshot.get("max_size") or 1))
    total = max(0, int(snapshot.get("total_depth") or 0))
    return round(min(1.0, total / max_size), 4)


_GLOBAL_OBSERVABILITY: ObservabilityRegistry | None = None


def get_observability_registry() -> ObservabilityRegistry:
    global _GLOBAL_OBSERVABILITY
    if _GLOBAL_OBSERVABILITY is None:
        _GLOBAL_OBSERVABILITY = ObservabilityRegistry()
    return _GLOBAL_OBSERVABILITY
