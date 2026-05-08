"""Health evaluation for SAFE operational reliability."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Sequence


class HealthStatus(str, Enum):
    healthy = "healthy"
    degraded = "degraded"
    unstable = "unstable"
    critical = "critical"


@dataclass(frozen=True)
class ComponentHealth:
    name: str
    status: HealthStatus
    detail: str
    observed_at: str
    metrics: Mapping[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
            "observed_at": self.observed_at,
            "metrics": dict(self.metrics),
        }


class HealthEngine:
    def evaluate(
        self,
        *,
        db_ok: bool = True,
        queue_snapshot: Mapping[str, Any] | None = None,
        stream_snapshot: Mapping[str, Any] | None = None,
        worker_snapshot: Mapping[str, Any] | None = None,
        ingestion_snapshot: Mapping[str, Any] | None = None,
        orchestration_snapshot: Mapping[str, Any] | None = None,
        heartbeat_records: Sequence[Mapping[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        components = [
            self._db(db_ok),
            self._queue(queue_snapshot or {}),
            self._stream(stream_snapshot or {}),
            self._workers(worker_snapshot or {}),
            self._ingestion(ingestion_snapshot or {}),
            self._orchestration(orchestration_snapshot or {}),
            self._heartbeats(heartbeat_records or []),
        ]
        overall = aggregate_health([component.status for component in components])
        return {
            "status": overall.value,
            "generated_at": _now(),
            "components": [component.to_dict() for component in components],
        }

    def _db(self, db_ok: bool) -> ComponentHealth:
        return ComponentHealth(
            name="database",
            status=HealthStatus.healthy if db_ok else HealthStatus.critical,
            detail="connectivity_ok" if db_ok else "connectivity_failed",
            observed_at=_now(),
            metrics={"db_ok": bool(db_ok)},
        )

    def _queue(self, snapshot: Mapping[str, Any]) -> ComponentHealth:
        max_size = max(1, int(snapshot.get("max_size") or 1))
        depth = int(snapshot.get("total_depth") or 0)
        dead = int(snapshot.get("dead_letter_depth") or 0)
        pressure = depth / max_size
        status = HealthStatus.healthy
        detail = "queue_nominal"
        if pressure >= 0.95:
            status, detail = HealthStatus.critical, "queue_saturated"
        elif pressure >= 0.75 or dead > 0:
            status, detail = HealthStatus.degraded, "queue_pressure"
        return ComponentHealth("queues", status, detail, _now(), {"pressure": round(pressure, 4), "dead_letters": dead})

    def _stream(self, snapshot: Mapping[str, Any]) -> ComponentHealth:
        active = int(snapshot.get("active_clients") or 0)
        bus = snapshot.get("event_bus") if isinstance(snapshot.get("event_bus"), Mapping) else {}
        dropped = int(bus.get("dropped") or snapshot.get("dropped") or 0)
        status = HealthStatus.healthy if dropped == 0 else HealthStatus.degraded
        return ComponentHealth("realtime_stream", status, "streaming_ok" if dropped == 0 else "stream_backpressure", _now(), {"active_clients": active, "dropped": dropped})

    def _workers(self, snapshot: Mapping[str, Any]) -> ComponentHealth:
        failed = snapshot.get("failed_workers") or []
        workers = snapshot.get("workers") if isinstance(snapshot.get("workers"), Mapping) else {}
        if failed:
            status, detail = HealthStatus.unstable, "worker_failure"
        elif workers and int(snapshot.get("active_workers") or 0) == 0:
            status, detail = HealthStatus.degraded, "workers_idle"
        else:
            status, detail = HealthStatus.healthy, "workers_ok"
        return ComponentHealth("workers", status, detail, _now(), {"active": snapshot.get("active_workers", 0), "failed": list(failed)})

    def _ingestion(self, snapshot: Mapping[str, Any]) -> ComponentHealth:
        dropped = int(snapshot.get("dropped") or snapshot.get("dropped_events") or 0)
        status = HealthStatus.degraded if dropped else HealthStatus.healthy
        return ComponentHealth("ingestion", status, "ingestion_drops" if dropped else "ingestion_ok", _now(), {"dropped": dropped})

    def _orchestration(self, snapshot: Mapping[str, Any]) -> ComponentHealth:
        failures = int(snapshot.get("failures") or snapshot.get("failed") or 0)
        status = HealthStatus.degraded if failures else HealthStatus.healthy
        return ComponentHealth("orchestration", status, "orchestration_failures" if failures else "orchestration_ok", _now(), {"failures": failures})

    def _heartbeats(self, records: Sequence[Mapping[str, Any]]) -> ComponentHealth:
        stale = 0
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        for record in records:
            raw = str(record.get("last_seen") or record.get("last_heartbeat") or "")
            try:
                observed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except Exception:
                stale += 1
                continue
            if observed < cutoff:
                stale += 1
        status = HealthStatus.degraded if stale else HealthStatus.healthy
        return ComponentHealth("host_heartbeats", status, "stale_hosts" if stale else "heartbeats_fresh", _now(), {"stale_hosts": stale, "checked": len(records)})


def aggregate_health(statuses: Sequence[HealthStatus]) -> HealthStatus:
    if any(status == HealthStatus.critical for status in statuses):
        return HealthStatus.critical
    if any(status == HealthStatus.unstable for status in statuses):
        return HealthStatus.unstable
    if any(status == HealthStatus.degraded for status in statuses):
        return HealthStatus.degraded
    return HealthStatus.healthy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
