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


def build_app_product_context(context: Mapping[str, Any], *, active_page: str) -> dict[str, Any]:
    enriched = build_client_dashboard_context(context)
    hosts = list(enriched.get("hosts") or [])
    incidents = list(enriched.get("incidents") or [])
    events = list(enriched.get("recent_events") or enriched.get("events") or [])
    dashboard = dict(enriched.get("client_dashboard") or {})
    enriched.update(
        {
            "active_app_page": active_page,
            "app_assets": _client_assets(hosts),
            "app_incidents": _client_incidents(incidents),
            "app_events": events[:8],
            "app_reports": _client_reports(dashboard, incidents),
            "app_action_items": _action_items(dashboard, incidents),
        }
    )
    return enriched


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


def _client_assets(hosts: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    assets = []
    for host in hosts[:24]:
        risk = int(float(host.get("risk_score") or host.get("risk") or 0))
        online = bool(host.get("online") or host.get("agent_online") or host.get("is_online"))
        status = str(host.get("status") or host.get("agent_status") or ("online" if online else "monitored"))
        assets.append(
            {
                "id": host.get("host_id") or host.get("id") or "unknown",
                "name": host.get("hostname") or host.get("host_id") or "Protected asset",
                "platform": host.get("platform") or host.get("os") or "endpoint",
                "status": status,
                "risk": max(0, min(100, risk)),
                "last_seen": host.get("last_seen") or host.get("updated_at") or "recently",
            }
        )
    return assets


def _client_incidents(incidents: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    normalized = []
    for item in incidents[:20]:
        normalized.append(
            {
                "id": item.get("incident_id") or item.get("id") or "incident",
                "title": item.get("title") or item.get("rule_name") or item.get("summary") or "Security incident",
                "severity": str(item.get("severity") or "medium").lower(),
                "status": str(item.get("status") or "open").lower(),
                "host": item.get("host_id") or item.get("asset") or "environment",
                "updated_at": item.get("updated_at") or item.get("created_at") or item.get("timestamp") or "recently",
            }
        )
    return normalized


def _client_reports(dashboard: Mapping[str, Any], incidents: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "title": "Executive Incident Export",
            "description": "Tenant-scoped incident package with redaction controls.",
            "href": "/api/incidents/export?format=json&limit=100",
            "format": "JSON",
        },
        {
            "title": "Board Security Summary",
            "description": dashboard.get("executive_summary") or "Current posture, assets, incidents, and action focus.",
            "href": "/app/overview",
            "format": "HTML",
        },
        {
            "title": "Critical Incident CSV",
            "description": f"{sum(1 for item in incidents if str(item.get('severity', '')).lower() == 'critical')} critical items available.",
            "href": "/api/incidents/export?format=csv&severity=critical&limit=100",
            "format": "CSV",
        },
    ]


def _action_items(dashboard: Mapping[str, Any], incidents: list[Mapping[str, Any]]) -> list[dict[str, str]]:
    critical = sum(1 for item in incidents if str(item.get("severity", "")).lower() == "critical")
    posture = int(dashboard.get("posture_score") or 0)
    items = []
    if critical:
        items.append({"label": "Review critical incidents", "detail": f"{critical} critical incident(s) need attention."})
    if posture < 85:
        items.append({"label": "Improve posture score", "detail": "Prioritize the highest risk areas shown in SAFE."})
    if not items:
        items.append({"label": "Maintain current posture", "detail": "Keep agents online and review executive reports weekly."})
    return items


def _summary(posture_score: int, overview: Mapping[str, Any]) -> str:
    if posture_score >= 85:
        return "Security posture is stable and monitored."
    if posture_score >= 65:
        return "Security posture is acceptable with a few items needing review."
    return "Security posture needs executive attention and prioritized remediation."
