"""Event lineage tracking for explainability, replay and auditability."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping
from uuid import uuid4

from schema.canonical_event import CanonicalEvent


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class LineageStep:
    step_id: str
    event_id: str
    tenant_id: str
    step_type: str
    name: str
    detail: Mapping[str, Any]
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "step_type": self.step_type,
            "name": self.name,
            "detail": dict(self.detail),
            "created_at": self.created_at,
        }


class EventLineageEngine:
    """Tenant-scoped lineage store for canonical events."""

    def __init__(self) -> None:
        self._steps: dict[str, list[LineageStep]] = defaultdict(list)

    def start(self, event: CanonicalEvent, *, source: str = "normalization") -> LineageStep:
        return self.add_step(
            event,
            step_type="source",
            name=source,
            detail={
                "raw_event_ref": event.raw_event_ref,
                "telemetry_source": event.telemetry_source,
                "source_event_id": event.lineage.source_event_id,
            },
        )

    def add_enrichment(self, event: CanonicalEvent, name: str, detail: Mapping[str, Any] | None = None) -> LineageStep:
        return self.add_step(event, step_type="enrichment", name=name, detail=detail or {})

    def add_detection(self, event: CanonicalEvent, detection: Any) -> LineageStep:
        data = to_mapping(detection)
        return self.add_step(
            event,
            step_type="detection",
            name=str(data.get("rule_id") or data.get("rule_name") or "detection"),
            detail=compact_mapping(data),
        )

    def add_correlation(self, event: CanonicalEvent, correlation: Any) -> LineageStep:
        data = to_mapping(correlation)
        return self.add_step(
            event,
            step_type="correlation",
            name=str(data.get("rule_id") or data.get("rule_name") or "correlation"),
            detail=compact_mapping(data),
        )

    def add_playbook(self, event: CanonicalEvent, playbook_id: str, detail: Mapping[str, Any] | None = None) -> LineageStep:
        return self.add_step(event, step_type="playbook", name=playbook_id, detail=detail or {})

    def add_incident(self, event: CanonicalEvent, incident_id: str, detail: Mapping[str, Any] | None = None) -> LineageStep:
        return self.add_step(event, step_type="incident", name=incident_id, detail=detail or {})

    def add_step(
        self,
        event: CanonicalEvent,
        *,
        step_type: str,
        name: str,
        detail: Mapping[str, Any],
    ) -> LineageStep:
        step = LineageStep(
            step_id=uuid4().hex,
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            step_type=str(step_type or "step"),
            name=str(name or step_type or "step"),
            detail=redact(detail),
        )
        self._steps[event.event_id].append(step)
        return step

    def trace(self, *, tenant_id: str, event_id: str) -> dict[str, Any]:
        steps = [step for step in self._steps.get(event_id, []) if step.tenant_id == tenant_id]
        return {
            "tenant_id": tenant_id,
            "event_id": event_id,
            "steps": [step.to_dict() for step in steps],
            "step_count": len(steps),
        }

    def replay_manifest(self, *, tenant_id: str, event_id: str) -> dict[str, Any]:
        trace = self.trace(tenant_id=tenant_id, event_id=event_id)
        return {
            "tenant_id": tenant_id,
            "event_id": event_id,
            "replay_safe": True,
            "lineage_steps": trace["steps"],
            "debugging_hints": [step["name"] for step in trace["steps"]],
        }


def to_mapping(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return dict(item)
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return dict(result) if isinstance(result, Mapping) else {}
    if hasattr(item, "__dict__"):
        return dict(getattr(item, "__dict__", {}))
    return {}


def compact_mapping(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in payload.items() if value not in (None, "", [], {})}


def redact(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        lower = str(key).lower()
        if any(secret in lower for secret in ("secret", "token", "password", "api_key", "host_key", "signature")):
            redacted[str(key)] = "[redacted]"
        elif isinstance(value, Mapping):
            redacted[str(key)] = redact(value)
        elif isinstance(value, list):
            redacted[str(key)] = [redact(item) if isinstance(item, Mapping) else item for item in value]
        else:
            redacted[str(key)] = value
    return redacted
