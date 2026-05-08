"""SOC KPI calculations for SAFE operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def calculate_soc_metrics(
    *,
    cases: list[dict[str, Any]] | None = None,
    incidents: list[dict[str, Any]] | None = None,
    response_actions: list[dict[str, Any]] | None = None,
    analysts: list[str] | None = None,
) -> dict[str, Any]:
    cases = list(cases or [])
    incidents = list(incidents or [])
    response_actions = list(response_actions or [])
    open_cases = [case for case in cases if case.get("status") not in {"resolved", "closed"}]
    false_positive = sum(1 for item in [*cases, *incidents] if str(item.get("status") or "") == "false_positive")
    total_incidents = max(1, len(incidents) + len(cases))
    containment_success = _ratio(
        sum(1 for action in response_actions if str(action.get("status") or "") in {"succeeded", "executed"}),
        sum(1 for action in response_actions if str(action.get("status") or "") in {"succeeded", "executed", "failed", "refused"}),
    )
    return {
        "mttd_minutes": _average_minutes(incidents, "created_at", "detected_at"),
        "mttr_minutes": _average_resolution_minutes([*cases, *incidents]),
        "incident_volume": len(incidents) + len(cases),
        "false_positive_ratio": round(false_positive / total_incidents, 3),
        "containment_success": containment_success,
        "analyst_workload": _workload(open_cases, analysts or []),
        "unresolved_criticals": sum(
            1
            for item in [*cases, *incidents]
            if str(item.get("severity") or "").lower() == "critical"
            and str(item.get("status") or "") not in {"resolved", "closed", "false_positive"}
        ),
        "open_cases": len(open_cases),
    }


def _average_minutes(items: list[dict[str, Any]], start_key: str, end_key: str) -> int:
    values = []
    for item in items:
        start = _parse(item.get(start_key))
        end = _parse(item.get(end_key)) or _parse(item.get("updated_at"))
        if start and end and end >= start:
            values.append((end - start).total_seconds() / 60)
    return int(sum(values) / len(values)) if values else 0


def _average_resolution_minutes(items: list[dict[str, Any]]) -> int:
    values = []
    for item in items:
        if str(item.get("status") or "") not in {"resolved", "closed"}:
            continue
        start = _parse(item.get("created_at") or item.get("opened_at"))
        end = _parse(item.get("closed_at") or item.get("updated_at"))
        if start and end and end >= start:
            values.append((end - start).total_seconds() / 60)
    return int(sum(values) / len(values)) if values else 0


def _workload(open_cases: list[dict[str, Any]], analysts: list[str]) -> dict[str, int]:
    output = {analyst: 0 for analyst in analysts if analyst}
    for case in open_cases:
        owner = str(case.get("assigned_to") or "unassigned")
        output[owner] = output.get(owner, 0) + 1
    return output


def _ratio(success: int, total: int) -> float:
    return round(success / total, 3) if total else 0.0


def _parse(value: Any):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


__all__ = ["calculate_soc_metrics"]
