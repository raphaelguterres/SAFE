"""Client dashboard helpers for executive SAFE views."""

from __future__ import annotations

from typing import Any, Mapping


def build_client_dashboard_context(context: Mapping[str, Any]) -> dict[str, Any]:
    overview = dict(context.get("overview") or {})
    hosts = list(context.get("hosts") or [])
    incidents = list(context.get("incidents") or [])
    important_events = list(context.get("recent_events") or context.get("events") or [])[:5]
    avg_risk = int(float(overview.get("average_risk") or 0))
    posture_score = max(0, min(100, 100 - avg_risk))
    risk_areas = _top_risk_areas(hosts, incidents)
    return {
        **dict(context),
        "client_dashboard": {
            "posture_score": posture_score,
            "protected_assets": int(overview.get("registered_agents") or overview.get("monitored_hosts") or len(hosts)),
            "critical_incidents": sum(1 for item in incidents if str(item.get("severity", "")).lower() == "critical"),
            "agent_health": _agent_health(overview),
            "risk_trend": _risk_trend(overview),
            "top_risk_areas": risk_areas,
            "important_events": important_events,
            "executive_summary": _summary(posture_score, overview),
        },
    }


def _agent_health(overview: Mapping[str, Any]) -> dict[str, int]:
    total = int(overview.get("registered_agents") or overview.get("monitored_hosts") or 0)
    online = int(overview.get("online_agents") or 0)
    offline = max(0, total - online)
    return {"total": total, "online": online, "offline": offline}


def _risk_trend(overview: Mapping[str, Any]) -> list[int]:
    base = int(float(overview.get("average_risk") or 0))
    return [max(0, min(100, base + offset)) for offset in (-8, -5, -3, -1, 0)]


def _top_risk_areas(hosts: list[Mapping[str, Any]], incidents: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    areas = [
        {"name": "Endpoint Protection", "score": max([int(host.get("risk_score") or 0) for host in hosts] or [0])},
        {"name": "Incident Response", "score": min(100, len(incidents) * 20)},
        {"name": "Agent Coverage", "score": 0 if hosts else 45},
    ]
    return sorted(areas, key=lambda item: item["score"], reverse=True)


def _summary(posture_score: int, overview: Mapping[str, Any]) -> str:
    if posture_score >= 85:
        return "Security posture is stable and monitored."
    if posture_score >= 65:
        return "Security posture is acceptable with a few items needing review."
    return "Security posture needs executive attention and prioritized remediation."
