"""Thread-safe performance counters for the scalable XDR platform core."""

from __future__ import annotations

import gc
import threading
import time
import tracemalloc
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class _LatencyBucket:
    count: int = 0
    total_ms: float = 0.0
    max_ms: float = 0.0

    def add(self, value_ms: float) -> None:
        value = max(0.0, float(value_ms))
        self.count += 1
        self.total_ms += value
        self.max_ms = max(self.max_ms, value)

    def snapshot(self) -> dict[str, float | int]:
        avg = self.total_ms / self.count if self.count else 0.0
        return {
            "count": self.count,
            "avg_ms": round(avg, 3),
            "max_ms": round(self.max_ms, 3),
        }


class PerformanceMetrics:
    """Small in-process metrics registry.

    This intentionally avoids heavy observability dependencies. It can be
    exported to Prometheus/OpenTelemetry later without changing the pipeline.
    """

    def __init__(self):
        if not tracemalloc.is_tracing():
            tracemalloc.start(10)
        self._lock = threading.RLock()
        self._started = time.monotonic()
        self._counters: defaultdict[str, int] = defaultdict(int)
        self._tenant_counters: defaultdict[str, defaultdict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._latencies: dict[str, _LatencyBucket] = {
            "queue": _LatencyBucket(),
            "ingestion": _LatencyBucket(),
            "detection": _LatencyBucket(),
        }
        self._queue_depths: dict[str, int] = {}
        self._last_event_ts = 0.0

    def record_received(self, *, tenant_id: str = "default", count: int = 1) -> None:
        self._inc("events_received", count, tenant_id=tenant_id)
        self._last_event_ts = time.time()

    def record_accepted(self, *, tenant_id: str = "default", count: int = 1) -> None:
        self._inc("events_accepted", count, tenant_id=tenant_id)

    def record_processed(self, *, tenant_id: str = "default", count: int = 1) -> None:
        self._inc("events_processed", count, tenant_id=tenant_id)

    def record_dropped(self, *, tenant_id: str = "default", count: int = 1, reason: str = "unknown") -> None:
        self._inc("events_dropped", count, tenant_id=tenant_id)
        self._inc(f"events_dropped_{_safe_key(reason)}", count, tenant_id=tenant_id)

    def record_deduplicated(self, *, tenant_id: str = "default", count: int = 1) -> None:
        self._inc("events_deduplicated", count, tenant_id=tenant_id)

    def record_queue_latency(self, value_ms: float) -> None:
        self._latency("queue", value_ms)

    def record_ingestion_latency(self, value_ms: float) -> None:
        self._latency("ingestion", value_ms)

    def record_detection_latency(self, value_ms: float) -> None:
        self._latency("detection", value_ms)

    def set_queue_depths(self, depths: dict[str, int]) -> None:
        with self._lock:
            self._queue_depths = {str(key): max(0, int(value)) for key, value in depths.items()}

    def snapshot(self, *, include_tenants: bool = False) -> dict[str, Any]:
        with self._lock:
            elapsed = max(0.001, time.monotonic() - self._started)
            received = self._counters.get("events_received", 0)
            processed = self._counters.get("events_processed", 0)
            deduped = self._counters.get("events_deduplicated", 0)
            accepted = self._counters.get("events_accepted", 0)
            current_mem, peak_mem = tracemalloc.get_traced_memory()
            payload: dict[str, Any] = {
                "uptime_seconds": round(elapsed, 3),
                "events_per_second": round(received / elapsed, 3),
                "processed_per_second": round(processed / elapsed, 3),
                "dedup_ratio": round(deduped / max(1, accepted + deduped), 4),
                "counters": dict(self._counters),
                "queue_depths": dict(self._queue_depths),
                "latency": {name: bucket.snapshot() for name, bucket in self._latencies.items()},
                "memory": {
                    "tracemalloc_current_bytes": current_mem,
                    "tracemalloc_peak_bytes": peak_mem,
                    "gc_counts": list(gc.get_count()),
                },
                "last_event_epoch": self._last_event_ts,
            }
            if include_tenants:
                payload["tenants"] = {
                    tenant: dict(counters)
                    for tenant, counters in self._tenant_counters.items()
                }
            return payload

    def _inc(self, key: str, count: int, *, tenant_id: str) -> None:
        amount = max(0, int(count))
        tenant = str(tenant_id or "default")
        with self._lock:
            self._counters[key] += amount
            self._tenant_counters[tenant][key] += amount

    def _latency(self, key: str, value_ms: float) -> None:
        with self._lock:
            self._latencies[key].add(value_ms)


_GLOBAL_METRICS = PerformanceMetrics()


def get_performance_metrics() -> PerformanceMetrics:
    return _GLOBAL_METRICS


def _safe_key(value: str) -> str:
    text = "".join(ch if ch.isalnum() else "_" for ch in str(value or "unknown").lower())
    return text.strip("_") or "unknown"
