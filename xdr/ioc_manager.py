"""Tenant-scoped IOC management for SAFE hunt operations."""

from __future__ import annotations

import re
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


IOC_TYPES = {"ip", "hash", "domain", "url", "filename"}


@dataclass(slots=True)
class IOCRecord:
    ioc_id: str
    tenant_id: str
    value: str
    ioc_type: str
    confidence: int
    source: str
    first_seen: str
    last_seen: str
    expiration: str = ""
    linked_cases: list[str] = field(default_factory=list)
    linked_hosts: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IOCManager:
    def __init__(self):
        self._lock = threading.RLock()
        self._records: dict[str, IOCRecord] = {}

    def add_ioc(
        self,
        *,
        tenant_id: str,
        value: str,
        ioc_type: str = "",
        confidence: int = 50,
        source: str = "analyst",
        expiration: str = "",
        linked_cases: list[str] | None = None,
        linked_hosts: list[str] | None = None,
        tags: list[str] | None = None,
    ) -> IOCRecord:
        clean_value = str(value or "").strip()
        if not clean_value:
            raise ValueError("ioc_value_required")
        normalized_type = _type(ioc_type or infer_ioc_type(clean_value))
        now = _now()
        key = f"{_tenant(tenant_id)}:{normalized_type}:{clean_value.lower()}"
        with self._lock:
            existing = self._records.get(key)
            if existing:
                existing.last_seen = now
                existing.confidence = max(existing.confidence, _confidence(confidence))
                existing.linked_cases = _merge(existing.linked_cases, linked_cases or [])
                existing.linked_hosts = _merge(existing.linked_hosts, linked_hosts or [])
                existing.tags = _merge(existing.tags, tags or [])
                return existing
            record = IOCRecord(
                ioc_id=f"ioc_{uuid.uuid4().hex}",
                tenant_id=_tenant(tenant_id),
                value=clean_value,
                ioc_type=normalized_type,
                confidence=_confidence(confidence),
                source=str(source or "analyst")[:128],
                first_seen=now,
                last_seen=now,
                expiration=str(expiration or "")[:64],
                linked_cases=_merge([], linked_cases or []),
                linked_hosts=_merge([], linked_hosts or []),
                tags=_merge([], tags or []),
            )
            self._records[key] = record
            return record

    def list_iocs(self, *, tenant_id: str, ioc_type: str | None = None, include_expired: bool = False) -> list[IOCRecord]:
        tenant = _tenant(tenant_id)
        with self._lock:
            records = [
                item
                for item in self._records.values()
                if item.tenant_id == tenant
                and (not ioc_type or item.ioc_type == _type(ioc_type))
                and (include_expired or not is_expired(item))
            ]
        return sorted(records, key=lambda item: item.last_seen, reverse=True)

    def link_case(self, *, tenant_id: str, ioc_id: str, case_id: str) -> IOCRecord:
        record = self._require_ioc(tenant_id, ioc_id)
        with self._lock:
            record.linked_cases = _merge(record.linked_cases, [case_id])
            record.last_seen = _now()
            return record

    def _require_ioc(self, tenant_id: str, ioc_id: str) -> IOCRecord:
        tenant = _tenant(tenant_id)
        with self._lock:
            for item in self._records.values():
                if item.tenant_id == tenant and item.ioc_id == ioc_id:
                    return item
        raise KeyError("ioc_not_found")


def infer_ioc_type(value: str) -> str:
    text = str(value or "").strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", text):
        return "ip"
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$", text):
        return "hash"
    if text.startswith(("http://", "https://")):
        return "url"
    if text.lower().endswith((".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jar", ".scr")):
        return "filename"
    if "." in text and "\\" not in text and "/" not in text:
        return "domain"
    return "filename"


def is_expired(record: IOCRecord) -> bool:
    if not record.expiration:
        return False
    try:
        return datetime.fromisoformat(record.expiration.replace("Z", "+00:00")) < datetime.now(timezone.utc)
    except ValueError:
        return False


def _type(value: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in IOC_TYPES else "filename"


def _tenant(value: str | None) -> str:
    return str(value or "default").strip() or "default"


def _confidence(value: int) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 50


def _merge(existing: list[str], incoming: list[Any]) -> list[str]:
    output = list(existing)
    seen = set(output)
    for item in incoming:
        text = str(item or "").strip()
        if text and text not in seen:
            output.append(text)
            seen.add(text)
    return output


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


__all__ = ["IOCManager", "IOCRecord", "infer_ioc_type", "is_expired"]
