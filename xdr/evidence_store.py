"""Immutable tenant-scoped evidence store for SAFE investigations."""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    tenant_id: str
    evidence_type: str
    title: str
    data: Mapping[str, Any]
    created_at: str
    created_by: str
    linked_case_id: str = ""
    integrity_hash: str = ""
    previous_hash: str = ""
    tags: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["data"] = dict(self.data)
        payload["tags"] = list(self.tags)
        return payload


class EvidenceStore:
    """Append-only evidence store with hash-chain integrity."""

    def __init__(self):
        self._lock = threading.RLock()
        self._records: list[EvidenceRecord] = []

    def add_evidence(
        self,
        *,
        tenant_id: str,
        evidence_type: str,
        title: str,
        data: dict[str, Any],
        created_by: str,
        linked_case_id: str = "",
        tags: list[str] | None = None,
    ) -> EvidenceRecord:
        if not isinstance(data, dict):
            raise ValueError("evidence_data_must_be_object")
        with self._lock:
            tenant = _tenant(tenant_id)
            previous = next((item.integrity_hash for item in reversed(self._records) if item.tenant_id == tenant), "")
            base = {
                "evidence_id": f"ev_{uuid.uuid4().hex}",
                "tenant_id": tenant,
                "evidence_type": str(evidence_type or "telemetry")[:64],
                "title": str(title or "Evidence")[:180],
                "data": _redact(data),
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "created_by": str(created_by or "system")[:128],
                "linked_case_id": str(linked_case_id or "")[:128],
                "previous_hash": previous,
                "tags": tuple(str(tag)[:64] for tag in (tags or []) if str(tag).strip()),
            }
            integrity = _hash(base)
            record = EvidenceRecord(
                evidence_id=base["evidence_id"],
                tenant_id=base["tenant_id"],
                evidence_type=base["evidence_type"],
                title=base["title"],
                data=MappingProxyType(dict(base["data"])),
                created_at=base["created_at"],
                created_by=base["created_by"],
                linked_case_id=base["linked_case_id"],
                integrity_hash=integrity,
                previous_hash=previous,
                tags=base["tags"],
            )
            self._records.append(record)
            return record

    def list_evidence(self, *, tenant_id: str, case_id: str | None = None) -> list[EvidenceRecord]:
        tenant = _tenant(tenant_id)
        with self._lock:
            records = [
                item
                for item in self._records
                if item.tenant_id == tenant and (not case_id or item.linked_case_id == case_id)
            ]
        return list(records)

    def verify_integrity(self, *, tenant_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            records = list(self._records)
        tenants = [_tenant(tenant_id)] if tenant_id else sorted({item.tenant_id for item in records})
        checked = 0
        last_hash = ""
        for tenant in tenants:
            previous = ""
            tenant_records = [item for item in records if item.tenant_id == tenant]
            result = _verify_records(tenant_records, previous, checked)
            if not result["valid"]:
                return result
            checked += result["checked_records"]
            last_hash = result["last_hash"] or last_hash
        return {"valid": True, "checked_records": checked, "first_broken_record": "", "last_hash": last_hash}


def _verify_records(records: list[EvidenceRecord], previous: str, starting_count: int) -> dict[str, Any]:
    checked = 0
    for record in records:
        payload = {
            "evidence_id": record.evidence_id,
            "tenant_id": record.tenant_id,
            "evidence_type": record.evidence_type,
            "title": record.title,
            "data": dict(record.data),
            "created_at": record.created_at,
            "created_by": record.created_by,
            "linked_case_id": record.linked_case_id,
            "previous_hash": record.previous_hash,
            "tags": tuple(record.tags),
        }
        if record.previous_hash != previous or _hash(payload) != record.integrity_hash:
            return {
                "valid": False,
                "checked_records": starting_count + checked,
                "first_broken_record": record.evidence_id,
                "last_hash": previous,
            }
        checked += 1
        previous = record.integrity_hash
    return {"valid": True, "checked_records": checked, "first_broken_record": "", "last_hash": previous}


def _hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _redact(data: dict[str, Any]) -> dict[str, Any]:
    redacted = {}
    for key, value in data.items():
        if any(token in str(key).lower() for token in ("token", "secret", "password", "api_key", "host_key")):
            redacted[str(key)] = "[redacted]"
        else:
            redacted[str(key)] = value
    return redacted


def _tenant(value: str | None) -> str:
    return str(value or "default").strip() or "default"


__all__ = ["EvidenceRecord", "EvidenceStore"]
