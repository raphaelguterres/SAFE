"""Disaster recovery primitives for tenant-safe SAFE snapshots."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Mapping, Sequence
from uuid import uuid4


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class RecoverySnapshot:
    snapshot_id: str
    tenant_id: str
    created_at: str
    incidents: Sequence[Mapping[str, Any]] = field(default_factory=list)
    audit_logs: Sequence[Mapping[str, Any]] = field(default_factory=list)
    queue_state: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    integrity_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "snapshot_id": self.snapshot_id,
            "tenant_id": self.tenant_id,
            "created_at": self.created_at,
            "incidents": [dict(item) for item in self.incidents],
            "audit_logs": [dict(item) for item in self.audit_logs],
            "queue_state": dict(self.queue_state),
            "metadata": dict(self.metadata),
            "integrity_hash": self.integrity_hash,
        }
        return payload


class DisasterRecoveryManager:
    def export_snapshot(
        self,
        *,
        tenant_id: str,
        incidents: Sequence[Mapping[str, Any]],
        audit_logs: Sequence[Mapping[str, Any]],
        queue_state: Mapping[str, Any] | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Dict[str, Any]:
        tenant = str(tenant_id or "").strip()
        if not tenant:
            raise ValueError("tenant_id is required")
        safe_incidents = [redact_sensitive(dict(item)) for item in incidents if str(item.get("tenant_id") or tenant) == tenant]
        safe_audit = [redact_sensitive(dict(item)) for item in audit_logs if str(item.get("tenant_id") or tenant) == tenant]
        base = {
            "snapshot_id": uuid4().hex,
            "tenant_id": tenant,
            "created_at": _now(),
            "incidents": safe_incidents,
            "audit_logs": safe_audit,
            "queue_state": redact_sensitive(dict(queue_state or {})),
            "metadata": redact_sensitive(dict(metadata or {})),
        }
        base["integrity_hash"] = canonical_hash(base)
        return RecoverySnapshot(**base).to_dict()

    def verify_snapshot(self, snapshot: Mapping[str, Any]) -> Dict[str, Any]:
        supplied = str(snapshot.get("integrity_hash") or "")
        if not supplied:
            return {"valid": False, "reason": "missing_integrity_hash"}
        expected_payload = dict(snapshot)
        expected_payload.pop("integrity_hash", None)
        expected = canonical_hash(expected_payload)
        return {
            "valid": supplied == expected,
            "reason": "ok" if supplied == expected else "integrity_mismatch",
            "snapshot_id": snapshot.get("snapshot_id"),
            "tenant_id": snapshot.get("tenant_id"),
        }

    def tenant_safe_restore_plan(self, *, snapshot: Mapping[str, Any], target_tenant_id: str) -> Dict[str, Any]:
        verification = self.verify_snapshot(snapshot)
        tenant = str(target_tenant_id or "").strip()
        if not verification["valid"]:
            return {"allowed": False, "reason": verification["reason"], "steps": []}
        if str(snapshot.get("tenant_id") or "") != tenant:
            return {"allowed": False, "reason": "tenant_mismatch", "steps": []}
        return {
            "allowed": True,
            "reason": "verified",
            "snapshot_id": snapshot.get("snapshot_id"),
            "tenant_id": tenant,
            "steps": [
                "pause_low_priority_ingestion",
                "verify_current_audit_chain",
                "restore_incident_records",
                "restore_audit_backup",
                "recover_queue_state",
                "run_integrity_verification",
                "resume_ingestion",
            ],
        }


def canonical_hash(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def redact_sensitive(payload: Mapping[str, Any]) -> Dict[str, Any]:
    redacted: Dict[str, Any] = {}
    for key, value in payload.items():
        lower = str(key).lower()
        if any(secret in lower for secret in ("secret", "token", "api_key", "host_key", "password", "signature")):
            redacted[str(key)] = "[redacted]"
        elif isinstance(value, Mapping):
            redacted[str(key)] = redact_sensitive(value)
        elif isinstance(value, list):
            redacted[str(key)] = [redact_sensitive(item) if isinstance(item, Mapping) else item for item in value]
        else:
            redacted[str(key)] = value
    return redacted
