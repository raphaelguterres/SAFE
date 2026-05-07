"""Rolling-window event deduplication for high-volume XDR telemetry."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class DeduplicationResult:
    is_duplicate: bool
    fingerprint: str
    deduplicated_count: int
    first_seen: str
    last_seen: str
    suppression_reason: str
    event: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class DeduplicatedBatch:
    accepted: list[dict[str, Any]]
    duplicates: list[DeduplicationResult]
    results: list[DeduplicationResult]

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted_count": self.accepted_count,
            "duplicate_count": self.duplicate_count,
            "duplicates": [item.to_dict() for item in self.duplicates],
            "results": [item.to_dict() for item in self.results],
        }


@dataclass(slots=True)
class _FingerprintRecord:
    first_seen_epoch: float
    last_seen_epoch: float
    count: int
    reason: str


class EventDeduplicationEngine:
    """Deduplicate repeated telemetry with a bounded TTL cache.

    The tenant id is part of every fingerprint. This is deliberate: duplicate
    suppression must never leak or suppress telemetry across tenant boundaries.
    """

    def __init__(self, *, ttl_seconds: int = 60, max_fingerprints: int = 10000):
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.max_fingerprints = max(100, int(max_fingerprints))
        self._lock = threading.RLock()
        self._cache: OrderedDict[str, _FingerprintRecord] = OrderedDict()

    def check(self, event: Any, *, now: float | None = None) -> DeduplicationResult:
        now = time.time() if now is None else float(now)
        payload = _event_dict(event)
        fingerprint, reason = self.fingerprint(payload)

        with self._lock:
            self._evict_expired(now)
            record = self._cache.get(fingerprint)
            if record and now - record.last_seen_epoch <= self.ttl_seconds:
                record.last_seen_epoch = now
                record.count += 1
                self._cache.move_to_end(fingerprint)
                return DeduplicationResult(
                    is_duplicate=True,
                    fingerprint=fingerprint,
                    deduplicated_count=max(0, record.count - 1),
                    first_seen=_iso(record.first_seen_epoch),
                    last_seen=_iso(record.last_seen_epoch),
                    suppression_reason=record.reason,
                    event=payload,
                )

            self._cache[fingerprint] = _FingerprintRecord(
                first_seen_epoch=now,
                last_seen_epoch=now,
                count=1,
                reason=reason,
            )
            self._cache.move_to_end(fingerprint)
            self._evict_over_capacity()
            return DeduplicationResult(
                is_duplicate=False,
                fingerprint=fingerprint,
                deduplicated_count=0,
                first_seen=_iso(now),
                last_seen=_iso(now),
                suppression_reason="",
                event=payload,
            )

    def deduplicate_batch(self, events: list[Any], *, now: float | None = None) -> DeduplicatedBatch:
        accepted: list[dict[str, Any]] = []
        duplicates: list[DeduplicationResult] = []
        results: list[DeduplicationResult] = []
        base_now = time.time() if now is None else float(now)
        for offset, event in enumerate(events):
            result = self.check(event, now=base_now + (offset / 1000.0))
            results.append(result)
            if result.is_duplicate:
                duplicates.append(result)
            else:
                accepted.append(result.event)
        return DeduplicatedBatch(accepted=accepted, duplicates=duplicates, results=results)

    def fingerprint(self, event: dict[str, Any]) -> tuple[str, str]:
        kind = str(event.get("event_type") or event.get("alert_type") or "event").lower()
        tenant_id = str(event.get("tenant_id") or event.get("tenant") or "default").strip().lower()
        host_id = str(event.get("host_id") or "").strip().lower()
        details = event.get("details") if isinstance(event.get("details"), dict) else {}

        if kind in {"process_execution", "script_execution"}:
            fields = [
                tenant_id,
                host_id,
                kind,
                _norm(event.get("process_name") or details.get("process_name")),
                _norm(event.get("parent_process") or details.get("parent_process")),
                _norm(event.get("command_line") or details.get("command_line")),
                _norm(event.get("username")),
            ]
            reason = "repeated_process_event"
        elif kind == "authentication":
            fields = [
                tenant_id,
                host_id,
                kind,
                _norm(event.get("auth_result")),
                _norm(event.get("auth_source_ip")),
                _norm(event.get("username")),
            ]
            reason = "repeated_auth_failure" if "fail" in fields[3] else "repeated_auth_event"
        elif kind == "network_connection":
            fields = [
                tenant_id,
                host_id,
                kind,
                _norm(event.get("process_name") or details.get("process_name")),
                _norm(event.get("network_dst_ip") or event.get("dst_ip")),
                _norm(event.get("network_dst_port") or event.get("dst_port")),
                _norm(event.get("network_direction")),
            ]
            reason = "repeated_network_event"
        else:
            fields = [
                tenant_id,
                host_id,
                kind,
                _norm(event.get("rule_id")),
                _norm(event.get("alert_type")),
                _norm(event.get("severity")),
                _norm(event.get("summary") or details.get("summary")),
            ]
            reason = "repeated_alert"

        text = json.dumps(fields, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(text.encode("utf-8")).hexdigest(), reason

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ttl_seconds": self.ttl_seconds,
                "max_fingerprints": self.max_fingerprints,
                "active_fingerprints": len(self._cache),
            }

    def _evict_expired(self, now: float) -> None:
        expired = [
            key for key, record in self._cache.items()
            if now - record.last_seen_epoch > self.ttl_seconds
        ]
        for key in expired:
            self._cache.pop(key, None)

    def _evict_over_capacity(self) -> None:
        while len(self._cache) > self.max_fingerprints:
            self._cache.popitem(last=False)


def _event_dict(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return dict(event)
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        return dict(to_dict())
    return {
        key: value for key, value in getattr(event, "__dict__", {}).items()
        if not key.startswith("_")
    }


def _norm(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().lower().split())


def _iso(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat().replace("+00:00", "Z")
