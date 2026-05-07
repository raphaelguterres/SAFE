"""Host heartbeat and telemetry freshness evaluation."""

from __future__ import annotations

import threading
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class HostHeartbeatState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DELAYED = "delayed"
    OFFLINE = "offline"
    ISOLATED = "isolated"


@dataclass(slots=True)
class HeartbeatRecord:
    tenant_id: str
    host_id: str
    last_heartbeat_epoch: float = 0.0
    last_telemetry_epoch: float = 0.0
    queue_lag_ms: float = 0.0
    ingestion_failures: int = 0
    isolated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HostHeartbeatSnapshot:
    tenant_id: str
    host_id: str
    state: HostHeartbeatState
    last_heartbeat_age_seconds: float
    last_telemetry_age_seconds: float
    queue_lag_ms: float
    ingestion_failures: int
    isolated: bool
    reason: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        return payload


class HostHeartbeatEngine:
    """Tracks endpoint liveness without storing sensitive telemetry payloads."""

    def __init__(
        self,
        *,
        healthy_after_seconds: int = 90,
        delayed_after_seconds: int = 300,
        offline_after_seconds: int = 900,
        degraded_queue_lag_ms: int = 30000,
    ):
        self.healthy_after_seconds = max(10, int(healthy_after_seconds))
        self.delayed_after_seconds = max(self.healthy_after_seconds + 1, int(delayed_after_seconds))
        self.offline_after_seconds = max(self.delayed_after_seconds + 1, int(offline_after_seconds))
        self.degraded_queue_lag_ms = max(1000, int(degraded_queue_lag_ms))
        self._lock = threading.RLock()
        self._records: dict[tuple[str, str], HeartbeatRecord] = {}

    def record_heartbeat(
        self,
        *,
        tenant_id: str,
        host_id: str,
        queue_lag_ms: float = 0.0,
        ingestion_failures: int = 0,
        isolated: bool = False,
        metadata: dict[str, Any] | None = None,
        now: float | None = None,
    ) -> HeartbeatRecord:
        now = time.time() if now is None else float(now)
        record = self._record(tenant_id, host_id)
        with self._lock:
            record.last_heartbeat_epoch = now
            record.queue_lag_ms = max(0.0, float(queue_lag_ms))
            record.ingestion_failures = max(0, int(ingestion_failures))
            record.isolated = bool(isolated)
            if metadata:
                record.metadata.update({str(k): v for k, v in metadata.items()})
            return record

    def record_telemetry(
        self,
        *,
        tenant_id: str,
        host_id: str,
        queue_lag_ms: float = 0.0,
        ingestion_failed: bool = False,
        now: float | None = None,
    ) -> HeartbeatRecord:
        now = time.time() if now is None else float(now)
        record = self._record(tenant_id, host_id)
        with self._lock:
            record.last_telemetry_epoch = now
            record.queue_lag_ms = max(0.0, float(queue_lag_ms))
            if ingestion_failed:
                record.ingestion_failures += 1
            return record

    def evaluate_host(self, *, tenant_id: str, host_id: str, now: float | None = None) -> HostHeartbeatSnapshot:
        now = time.time() if now is None else float(now)
        key = (_tenant(tenant_id), _host(host_id))
        with self._lock:
            record = self._records.get(key)
            if not record:
                return HostHeartbeatSnapshot(
                    tenant_id=key[0],
                    host_id=key[1],
                    state=HostHeartbeatState.OFFLINE,
                    last_heartbeat_age_seconds=-1.0,
                    last_telemetry_age_seconds=-1.0,
                    queue_lag_ms=0.0,
                    ingestion_failures=0,
                    isolated=False,
                    reason="no_heartbeat_record",
                )
            return self._evaluate(record, now)

    def snapshot(self, *, tenant_id: str | None = None, now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else float(now)
        tenant_filter = _tenant(tenant_id) if tenant_id else None
        with self._lock:
            records = list(self._records.values())
        output = []
        for record in records:
            if tenant_filter and record.tenant_id != tenant_filter:
                continue
            output.append(self._evaluate(record, now).to_dict())
        return output

    def _record(self, tenant_id: str, host_id: str) -> HeartbeatRecord:
        key = (_tenant(tenant_id), _host(host_id))
        with self._lock:
            record = self._records.get(key)
            if not record:
                record = HeartbeatRecord(tenant_id=key[0], host_id=key[1])
                self._records[key] = record
            return record

    def _evaluate(self, record: HeartbeatRecord, now: float) -> HostHeartbeatSnapshot:
        heartbeat_age = now - record.last_heartbeat_epoch if record.last_heartbeat_epoch else self.offline_after_seconds + 1.0
        telemetry_age = now - record.last_telemetry_epoch if record.last_telemetry_epoch else self.offline_after_seconds + 1.0
        if record.isolated:
            state = HostHeartbeatState.ISOLATED
            reason = "host_isolated"
        elif heartbeat_age > self.offline_after_seconds:
            state = HostHeartbeatState.OFFLINE
            reason = "heartbeat_stale"
        elif heartbeat_age > self.delayed_after_seconds or telemetry_age > self.delayed_after_seconds:
            state = HostHeartbeatState.DELAYED
            reason = "telemetry_delayed"
        elif record.queue_lag_ms >= self.degraded_queue_lag_ms or record.ingestion_failures > 0:
            state = HostHeartbeatState.DEGRADED
            reason = "queue_lag_or_ingestion_failures"
        else:
            state = HostHeartbeatState.HEALTHY
            reason = "heartbeat_current"
        return HostHeartbeatSnapshot(
            tenant_id=record.tenant_id,
            host_id=record.host_id,
            state=state,
            last_heartbeat_age_seconds=round(heartbeat_age, 3),
            last_telemetry_age_seconds=round(telemetry_age, 3),
            queue_lag_ms=round(record.queue_lag_ms, 3),
            ingestion_failures=record.ingestion_failures,
            isolated=record.isolated,
            reason=reason,
        )


def _tenant(value: str | None) -> str:
    return str(value or "default").strip() or "default"


def _host(value: str | None) -> str:
    return str(value or "").strip()
