"""Executive risk translation for SAFE AI-assisted SOC."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass(slots=True)
class ExecutiveRiskExplanation:
    risk_level: str
    operational_risk: str
    potential_impact: str
    recommended_action: str
    key_points: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExecutiveSummaryEngine:
    """Turns technical SOC signals into non-technical business language."""

    def explain(
        self,
        *,
        posture_score: int = 100,
        active_threats: int = 0,
        critical_hosts: int = 0,
        open_incidents: int = 0,
        attack_progression: int = 0,
        recommendations: Iterable[str] | None = None,
    ) -> ExecutiveRiskExplanation:
        risk_level = _risk_level(posture_score, active_threats, critical_hosts, open_incidents, attack_progression)
        if risk_level == "Critical":
            operational = "Immediate security risk may affect business operations or sensitive data."
            impact = "Possible service disruption, credential exposure, or incident escalation."
            action = "Authorize urgent incident review and containment planning."
        elif risk_level == "High":
            operational = "Elevated security activity requires same-day leadership awareness."
            impact = "Potential spread or persistence if the activity is confirmed malicious."
            action = "Prioritize analyst triage and confirm affected assets."
        elif risk_level == "Medium":
            operational = "Security activity is present, but business impact is not confirmed."
            impact = "Limited operational risk if telemetry remains stable."
            action = "Continue investigation and track recommended controls."
        else:
            operational = "Environment appears stable based on current SAFE telemetry."
            impact = "No active business impact visible."
            action = "Maintain monitoring and validate endpoint coverage."
        key_points = [
            f"Security posture score: {int(posture_score)}/100",
            f"Active threats: {int(active_threats)}",
            f"Critical hosts: {int(critical_hosts)}",
            f"Open incidents: {int(open_incidents)}",
        ]
        key_points.extend(str(item).replace("_", " ") for item in (recommendations or [])[:3])
        return ExecutiveRiskExplanation(risk_level, operational, impact, action, key_points)


def explain_executive_risk(**kwargs: Any) -> ExecutiveRiskExplanation:
    return ExecutiveSummaryEngine().explain(**kwargs)


def _risk_level(posture: int, threats: int, critical_hosts: int, incidents: int, progression: int) -> str:
    if posture < 45 or threats >= 3 or critical_hosts >= 2 or progression >= 80:
        return "Critical"
    if posture < 65 or threats or critical_hosts or incidents >= 2 or progression >= 55:
        return "High"
    if posture < 80 or incidents:
        return "Medium"
    return "Low"


__all__ = ["ExecutiveRiskExplanation", "ExecutiveSummaryEngine", "explain_executive_risk"]
