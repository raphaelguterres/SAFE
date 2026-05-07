"""Structured audit pipeline for Enterprise Defense Core events."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class AuditRecord:
    event_type: str
    action: str
    tenant_id: str = ""
    host_id: str = ""
    actor: str = "system"
    correlation_id: str = ""
    policy_decision: dict[str, Any] = field(default_factory=dict)
    response_action: dict[str, Any] = field(default_factory=dict)
    incident_id: str = ""
    outcome: str = "observed"
    timestamp: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["audit_id"] = f"nga_{uuid.uuid4().hex}"
        if not payload["correlation_id"]:
            payload["correlation_id"] = f"ngc_{uuid.uuid4().hex}"
        return _redact(payload)


class EnterpriseAuditPipeline:
    """Append-only JSONL writer used by response and SOC orchestration paths."""

    def __init__(self, log_path: str | Path = "netguard_enterprise_audit.jsonl"):
        self.log_path = Path(log_path)

    def emit(self, record: AuditRecord | dict[str, Any]) -> dict[str, Any]:
        payload = record.to_dict() if isinstance(record, AuditRecord) else _redact(dict(record))
        if "timestamp" not in payload:
            payload["timestamp"] = int(time.time())
        if "audit_id" not in payload:
            payload["audit_id"] = f"nga_{uuid.uuid4().hex}"
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")
        return payload


def emit_audit_record(record: AuditRecord | dict[str, Any], *, log_path: str | Path = "netguard_enterprise_audit.jsonl") -> dict[str, Any]:
    return EnterpriseAuditPipeline(log_path).emit(record)


def _redact(payload: dict[str, Any]) -> dict[str, Any]:
    clean: dict[str, Any] = {}
    for key, value in payload.items():
        lowered = str(key).lower()
        if any(marker in lowered for marker in ("token", "secret", "password", "api_key", "signature")):
            clean[str(key)] = "***redacted***"
            continue
        if isinstance(value, dict):
            clean[str(key)] = _redact(value)
        else:
            clean[str(key)] = value
    return clean
