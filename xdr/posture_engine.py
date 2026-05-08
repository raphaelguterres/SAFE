"""Executive security posture scoring for SAFE."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass(slots=True)
class PostureScore:
    score: int
    label: str
    risk_level: str
    factors: dict[str, int] = field(default_factory=dict)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PostureEngine:
    """Scores environment posture from SOC-safe aggregate signals."""

    def calculate(
        self,
        *,
        hosts: Iterable[dict[str, Any]] | None = None,
        incidents: Iterable[dict[str, Any]] | None = None,
        response_queue: dict[str, Any] | None = None,
        telemetry: dict[str, Any] | None = None,
    ) -> PostureScore:
        host_rows = list(hosts or [])
        incident_rows = list(incidents or [])
        queue = dict(response_queue or {})
        telemetry_data = dict(telemetry or {})

        factors = {
            "host_hygiene": _host_hygiene(host_rows),
            "incident_pressure": _incident_pressure(incident_rows),
            "telemetry_coverage": _telemetry_coverage(host_rows, telemetry_data),
            "response_readiness": _response_readiness(queue),
            "agent_freshness": _agent_freshness(host_rows),
        }
        score = int(sum(factors.values()) / max(1, len(factors)))
        label, risk_level = _label(score)
        return PostureScore(
            score=score,
            label=label,
            risk_level=risk_level,
            factors=factors,
            recommendations=_recommendations(factors, incident_rows, queue),
        )


def calculate_posture_score(**kwargs: Any) -> PostureScore:
    return PostureEngine().calculate(**kwargs)


def _host_hygiene(hosts: list[dict[str, Any]]) -> int:
    if not hosts:
        return 45
    risk_average = sum(int(host.get("risk_score") or 0) for host in hosts) / len(hosts)
    critical_hosts = sum(1 for host in hosts if int(host.get("risk_score") or 0) >= 80)
    score = 100 - int(risk_average) - (critical_hosts * 8)
    return _clamp(score)


def _incident_pressure(incidents: list[dict[str, Any]]) -> int:
    if not incidents:
        return 100
    open_items = [
        item for item in incidents
        if str(item.get("status") or "open").lower() in {"open", "new", "triage", "investigating", "in_progress"}
    ]
    critical = sum(1 for item in open_items if str(item.get("severity") or "").lower() == "critical")
    high = sum(1 for item in open_items if str(item.get("severity") or "").lower() == "high")
    return _clamp(100 - (len(open_items) * 6) - (critical * 18) - (high * 10))


def _telemetry_coverage(hosts: list[dict[str, Any]], telemetry: dict[str, Any]) -> int:
    if not hosts:
        return 40
    events_24h = int(telemetry.get("events_24h") or 0)
    online = sum(1 for host in hosts if str(host.get("status") or "").lower() == "online")
    coverage = int((online / max(1, len(hosts))) * 70)
    volume_bonus = min(30, events_24h // 10)
    return _clamp(coverage + volume_bonus)


def _response_readiness(queue: dict[str, Any]) -> int:
    pending = int(queue.get("pending_approvals") or 0)
    failed = int(queue.get("failed") or 0)
    refused = int(queue.get("refused") or 0)
    expired = int(queue.get("expired") or 0)
    executed = int(queue.get("executed") or 0)
    return _clamp(92 + min(8, executed) - (pending * 5) - (failed * 8) - (refused * 4) - (expired * 3))


def _agent_freshness(hosts: list[dict[str, Any]]) -> int:
    if not hosts:
        return 40
    offline = sum(1 for host in hosts if str(host.get("status") or "").lower() == "offline")
    enrolled = sum(1 for host in hosts if host.get("agent_enrolled"))
    score = int((enrolled / max(1, len(hosts))) * 100) - (offline * 8)
    return _clamp(score)


def _recommendations(factors: dict[str, int], incidents: list[dict[str, Any]], queue: dict[str, Any]) -> list[str]:
    recs: list[str] = []
    if factors.get("telemetry_coverage", 100) < 70:
        recs.append("connect_or_recover_endpoint_agents")
    if factors.get("incident_pressure", 100) < 75:
        recs.append("prioritize_open_critical_incidents")
    if factors.get("response_readiness", 100) < 85 or int(queue.get("pending_approvals") or 0) > 0:
        recs.append("review_pending_security_actions")
    if factors.get("host_hygiene", 100) < 70:
        recs.append("triage_high_risk_hosts")
    if not recs and not incidents:
        recs.append("maintain_monitoring_and_validate_coverage")
    return recs[:5]


def _label(score: int) -> tuple[str, str]:
    if score >= 85:
        return "Excellent", "low"
    if score >= 70:
        return "Good", "medium"
    if score >= 45:
        return "Attention Needed", "high"
    return "Critical Risk", "critical"


def _clamp(value: int | float) -> int:
    return max(0, min(100, int(value)))
