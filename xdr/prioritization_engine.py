"""Incident prioritization for SAFE AI-assisted SOC."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .severity import clamp_risk, normalize_severity, severity_weight


@dataclass(slots=True)
class IncidentPriority:
    priority: str
    score: int
    reasons: list[str] = field(default_factory=list)
    recommended_sla: str = "next_business_day"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IncidentPrioritizationEngine:
    """Prioritizes incidents by business and attack-progression impact."""

    def prioritize(
        self,
        *,
        severity: str = "low",
        business_impact: str = "",
        affected_hosts: Iterable[str] | None = None,
        critical_assets: Iterable[str] | None = None,
        attack_progression: int = 0,
        persistence: bool = False,
        lateral_movement: bool = False,
        credential_access: bool = False,
        threat_intel_severity: str = "none",
    ) -> IncidentPriority:
        reasons: list[str] = []
        score = severity_weight(normalize_severity(severity, default="low"))
        if severity:
            reasons.append(f"alert_severity_{normalize_severity(severity)}")

        affected = {str(item).strip() for item in (affected_hosts or []) if str(item).strip()}
        critical = {str(item).strip() for item in (critical_assets or []) if str(item).strip()}
        if affected:
            score += min(20, len(affected) * 5)
            reasons.append("affected_hosts")
        if affected & critical:
            score += 25
            reasons.append("critical_asset_involved")

        progression = clamp_risk(attack_progression)
        if progression >= 70:
            score += 20
            reasons.append("advanced_attack_progression")
        elif progression >= 40:
            score += 10
            reasons.append("active_attack_progression")

        if persistence:
            score += 12
            reasons.append("persistence_present")
        if lateral_movement:
            score += 18
            reasons.append("lateral_movement_present")
        if credential_access:
            score += 18
            reasons.append("credential_access_present")
        ti = normalize_severity(threat_intel_severity if threat_intel_severity != "none" else "", default="low")
        if threat_intel_severity and threat_intel_severity != "none":
            score += severity_weight(ti) // 2
            reasons.append("threat_intel_severity")
        if any(token in str(business_impact or "").lower() for token in ("interruption", "data exposure", "critical")):
            score += 15
            reasons.append("business_impact")

        final_score = clamp_risk(score)
        priority = _priority(final_score)
        return IncidentPriority(
            priority=priority,
            score=final_score,
            reasons=list(dict.fromkeys(reasons)),
            recommended_sla=_sla(priority),
        )


def prioritize_incident(**kwargs: Any) -> IncidentPriority:
    return IncidentPrioritizationEngine().prioritize(**kwargs)


def _priority(score: int) -> str:
    if score >= 86:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"


def _sla(priority: str) -> str:
    return {
        "Critical": "immediate_review",
        "High": "same_day_review",
        "Medium": "next_business_day",
        "Low": "routine_review",
    }[priority]


__all__ = ["IncidentPrioritizationEngine", "IncidentPriority", "prioritize_incident"]
