"""Canonical security telemetry model for SAFE.

The canonical model is deliberately conservative: it preserves the original raw
event reference while normalizing the fields that detections, enrichment and
search need to share.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Mapping
from uuid import uuid4


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class ProcessContext:
    name: str = ""
    pid: int | None = None
    ppid: int | None = None
    command_line: str = ""
    parent_name: str = ""
    executable_path: str = ""
    sha256: str = ""
    signer: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _compact(asdict(self))


@dataclass(frozen=True)
class NetworkContext:
    src_ip: str = ""
    src_port: int | None = None
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = ""
    direction: str = ""
    domain: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _compact(asdict(self))


@dataclass(frozen=True)
class AuthContext:
    username: str = ""
    result: str = ""
    source_ip: str = ""
    logon_type: str = ""
    identity_provider: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _compact(asdict(self))


@dataclass(frozen=True)
class EventLineageRef:
    source: str = ""
    source_event_id: str = ""
    ingest_id: str = ""
    raw_hash: str = ""
    parent_event_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _compact(asdict(self))


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    tenant_id: str
    host_id: str
    user_id: str
    event_type: str
    category: str
    timestamp: str
    telemetry_source: str
    severity: str = "low"
    process: ProcessContext = field(default_factory=ProcessContext)
    network: NetworkContext = field(default_factory=NetworkContext)
    auth: AuthContext = field(default_factory=AuthContext)
    raw_event_ref: str = ""
    normalized_fields: Mapping[str, Any] = field(default_factory=dict)
    enrichment: Mapping[str, Any] = field(default_factory=dict)
    lineage: EventLineageRef = field(default_factory=EventLineageRef)
    confidence: float = 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "host_id": self.host_id,
            "user_id": self.user_id,
            "event_type": self.event_type,
            "category": self.category,
            "timestamp": self.timestamp,
            "process": self.process.to_dict(),
            "network": self.network.to_dict(),
            "auth": self.auth.to_dict(),
            "telemetry_source": self.telemetry_source,
            "severity": self.severity,
            "raw_event_ref": self.raw_event_ref,
            "normalized_fields": dict(self.normalized_fields),
            "enrichment": dict(self.enrichment),
            "lineage": self.lineage.to_dict(),
            "confidence": round(float(self.confidence), 4),
        }

    def with_enrichment(self, enrichment: Mapping[str, Any]) -> "CanonicalEvent":
        merged = dict(self.enrichment)
        merged.update(dict(enrichment or {}))
        return CanonicalEvent(
            event_id=self.event_id,
            tenant_id=self.tenant_id,
            host_id=self.host_id,
            user_id=self.user_id,
            event_type=self.event_type,
            category=self.category,
            timestamp=self.timestamp,
            telemetry_source=self.telemetry_source,
            severity=self.severity,
            process=self.process,
            network=self.network,
            auth=self.auth,
            raw_event_ref=self.raw_event_ref,
            normalized_fields=dict(self.normalized_fields),
            enrichment=merged,
            lineage=self.lineage,
            confidence=self.confidence,
        )


def canonical_event_id(raw_event: Mapping[str, Any]) -> str:
    seed = canonical_hash(raw_event)[:24]
    return f"ce_{seed}"


def canonical_hash(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(_redact(payload), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def make_raw_ref(raw_event: Mapping[str, Any]) -> str:
    return f"raw:{canonical_hash(raw_event)[:32]}"


def new_event_id() -> str:
    return f"ce_{uuid4().hex}"


def _compact(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in payload.items() if value not in (None, "", [], {})}


def _redact(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        lower = str(key).lower()
        if any(token in lower for token in ("secret", "token", "password", "api_key", "host_key", "signature")):
            redacted[str(key)] = "[redacted]"
        elif isinstance(value, Mapping):
            redacted[str(key)] = _redact(value)
        elif isinstance(value, list):
            redacted[str(key)] = [_redact(item) if isinstance(item, Mapping) else item for item in value]
        else:
            redacted[str(key)] = value
    return redacted
