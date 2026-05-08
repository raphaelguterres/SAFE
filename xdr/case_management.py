"""Tenant-scoped SOC case management for SAFE operations."""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


CASE_STATUSES = {"new", "triage", "investigating", "contained", "monitoring", "resolved", "closed"}
CASE_SEVERITIES = {"low", "medium", "high", "critical"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class CaseNote:
    note_id: str
    author: str
    body: str
    created_at: str
    note_type: str = "analyst_note"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CaseTimelineEntry:
    entry_id: str
    timestamp: str
    event_type: str
    title: str
    description: str = ""
    actor: str = "system"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class CaseEvidenceRef:
    evidence_id: str
    evidence_type: str
    title: str
    integrity_hash: str = ""
    pinned_by: str = ""
    pinned_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Case:
    case_id: str
    tenant_id: str
    title: str
    severity: str
    status: str
    assigned_to: str
    created_by: str
    created_at: str
    updated_at: str
    related_incidents: list[str] = field(default_factory=list)
    related_hosts: list[str] = field(default_factory=list)
    related_iocs: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    attack_story: str = ""
    evidence: list[CaseEvidenceRef] = field(default_factory=list)
    notes: list[CaseNote] = field(default_factory=list)
    timeline: list[CaseTimelineEntry] = field(default_factory=list)
    containment_status: str = "not_started"
    resolution_summary: str = ""
    watchers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence"] = [item.to_dict() for item in self.evidence]
        payload["notes"] = [item.to_dict() for item in self.notes]
        payload["timeline"] = [item.to_dict() for item in self.timeline]
        return payload


class CaseRepository:
    """In-memory case repository with explicit tenant scoping.

    The repository is intentionally small and dependency-free for local/demo
    mode. Production can back the same contract with a database repository.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._cases: dict[str, Case] = {}

    def create_case(
        self,
        *,
        tenant_id: str,
        title: str,
        severity: str = "medium",
        created_by: str = "system",
        assigned_to: str = "",
        related_incidents: list[str] | None = None,
        related_hosts: list[str] | None = None,
        related_iocs: list[str] | None = None,
        mitre_tactics: list[str] | None = None,
        attack_story: str = "",
    ) -> Case:
        tenant = _tenant(tenant_id)
        now = utc_now()
        case = Case(
            case_id=f"CASE-{uuid.uuid4().hex[:10].upper()}",
            tenant_id=tenant,
            title=_clean(title, "Untitled case", 180),
            severity=_severity(severity),
            status="new",
            assigned_to=_clean(assigned_to, "", 128),
            created_by=_clean(created_by, "system", 128),
            created_at=now,
            updated_at=now,
            related_incidents=_unique(related_incidents or []),
            related_hosts=_unique(related_hosts or []),
            related_iocs=_unique(related_iocs or []),
            mitre_tactics=_unique(mitre_tactics or []),
            attack_story=_clean(attack_story, "", 1500),
        )
        case.timeline.append(
            CaseTimelineEntry(
                entry_id=f"tl_{uuid.uuid4().hex}",
                timestamp=now,
                event_type="case_created",
                title="Case created",
                description=case.title,
                actor=case.created_by,
            )
        )
        with self._lock:
            self._cases[case.case_id] = case
        return case

    def get_case(self, case_id: str, *, tenant_id: str) -> Case | None:
        tenant = _tenant(tenant_id)
        with self._lock:
            case = self._cases.get(str(case_id or ""))
            if not case or case.tenant_id != tenant:
                return None
            return case

    def list_cases(
        self,
        *,
        tenant_id: str,
        status: str | None = None,
        assigned_to: str | None = None,
        limit: int = 100,
    ) -> list[Case]:
        tenant = _tenant(tenant_id)
        with self._lock:
            cases = [
                case
                for case in self._cases.values()
                if case.tenant_id == tenant
                and (not status or case.status == status)
                and (not assigned_to or case.assigned_to == assigned_to)
            ]
        cases.sort(key=lambda item: item.updated_at, reverse=True)
        return cases[: max(1, min(int(limit), 500))]

    def update_status(self, case_id: str, *, tenant_id: str, status: str, actor: str, note: str = "") -> Case:
        case = self._require_case(case_id, tenant_id)
        normalized = str(status or "").strip().lower()
        if normalized not in CASE_STATUSES:
            raise ValueError("invalid_case_status")
        with self._lock:
            case.status = normalized
            case.updated_at = utc_now()
            case.timeline.append(
                CaseTimelineEntry(
                    entry_id=f"tl_{uuid.uuid4().hex}",
                    timestamp=case.updated_at,
                    event_type="status_changed",
                    title=f"Status changed to {normalized}",
                    description=_clean(note, "", 1000),
                    actor=_clean(actor, "system", 128),
                )
            )
            return case

    def assign(self, case_id: str, *, tenant_id: str, assigned_to: str, actor: str) -> Case:
        case = self._require_case(case_id, tenant_id)
        with self._lock:
            case.assigned_to = _clean(assigned_to, "", 128)
            case.updated_at = utc_now()
            case.timeline.append(
                CaseTimelineEntry(
                    entry_id=f"tl_{uuid.uuid4().hex}",
                    timestamp=case.updated_at,
                    event_type="assignment_changed",
                    title=f"Assigned to {case.assigned_to or 'unassigned'}",
                    actor=_clean(actor, "system", 128),
                )
            )
            return case

    def add_note(self, case_id: str, *, tenant_id: str, author: str, body: str, note_type: str = "analyst_note") -> CaseNote:
        case = self._require_case(case_id, tenant_id)
        note = CaseNote(
            note_id=f"note_{uuid.uuid4().hex}",
            author=_clean(author, "analyst", 128),
            body=_clean(body, "", 4000),
            created_at=utc_now(),
            note_type=_clean(note_type, "analyst_note", 64),
        )
        if not note.body:
            raise ValueError("empty_note")
        with self._lock:
            case.notes.append(note)
            case.updated_at = note.created_at
            case.timeline.append(
                CaseTimelineEntry(
                    entry_id=f"tl_{uuid.uuid4().hex}",
                    timestamp=note.created_at,
                    event_type="note_added",
                    title="Analyst note added",
                    actor=note.author,
                )
            )
        return note

    def pin_evidence(
        self,
        case_id: str,
        *,
        tenant_id: str,
        evidence_id: str,
        evidence_type: str,
        title: str,
        integrity_hash: str = "",
        actor: str = "analyst",
    ) -> CaseEvidenceRef:
        case = self._require_case(case_id, tenant_id)
        ref = CaseEvidenceRef(
            evidence_id=_clean(evidence_id, "", 128),
            evidence_type=_clean(evidence_type, "telemetry", 64),
            title=_clean(title, "Evidence", 180),
            integrity_hash=_clean(integrity_hash, "", 128),
            pinned_by=_clean(actor, "analyst", 128),
            pinned_at=utc_now(),
        )
        if not ref.evidence_id:
            raise ValueError("evidence_id_required")
        with self._lock:
            if all(item.evidence_id != ref.evidence_id for item in case.evidence):
                case.evidence.append(ref)
                case.updated_at = ref.pinned_at
                case.timeline.append(
                    CaseTimelineEntry(
                        entry_id=f"tl_{uuid.uuid4().hex}",
                        timestamp=ref.pinned_at,
                        event_type="evidence_pinned",
                        title=f"Evidence pinned: {ref.title}",
                        actor=ref.pinned_by,
                    )
                )
        return ref

    def add_watcher(self, case_id: str, *, tenant_id: str, watcher: str, actor: str = "system") -> Case:
        case = self._require_case(case_id, tenant_id)
        clean_watcher = _clean(watcher, "", 128)
        if not clean_watcher:
            raise ValueError("watcher_required")
        with self._lock:
            if clean_watcher not in case.watchers:
                case.watchers.append(clean_watcher)
                case.updated_at = utc_now()
                case.timeline.append(
                    CaseTimelineEntry(
                        entry_id=f"tl_{uuid.uuid4().hex}",
                        timestamp=case.updated_at,
                        event_type="watcher_added",
                        title=f"Watcher added: {clean_watcher}",
                        actor=_clean(actor, "system", 128),
                    )
                )
            return case

    def _require_case(self, case_id: str, tenant_id: str) -> Case:
        case = self.get_case(case_id, tenant_id=tenant_id)
        if not case:
            raise KeyError("case_not_found")
        return case


def _tenant(value: str | None) -> str:
    return str(value or "default").strip() or "default"


def _severity(value: str | None) -> str:
    normalized = str(value or "medium").strip().lower()
    return normalized if normalized in CASE_SEVERITIES else "medium"


def _clean(value: Any, default: str, max_len: int) -> str:
    text = str(value if value is not None else default).strip()
    return (text or default)[:max_len]


def _unique(values: list[Any]) -> list[str]:
    output: list[str] = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


__all__ = [
    "CASE_STATUSES",
    "Case",
    "CaseEvidenceRef",
    "CaseNote",
    "CaseRepository",
    "CaseTimelineEntry",
]
