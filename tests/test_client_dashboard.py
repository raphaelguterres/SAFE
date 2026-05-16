from __future__ import annotations

from jinja2 import Environment, FileSystemLoader

from server.client_dashboard import build_client_dashboard_context


def test_client_dashboard_context_summarizes_executive_metrics():
    context = build_client_dashboard_context(
        {
            "overview": {"average_risk": 22, "registered_agents": 5, "online_agents": 4},
            "hosts": [{"risk_score": 80}],
            "incidents": [{"severity": "critical"}],
            "recent_events": [{"event_type": "process"}],
        }
    )

    dashboard = context["client_dashboard"]
    assert dashboard["posture_score"] == 78
    assert dashboard["protected_assets"] == 5
    assert dashboard["critical_incidents"] == 1
    assert dashboard["agent_health"]["offline"] == 1


def test_client_overview_template_renders_clean_experience():
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("client_overview.html")

    html = template.render(
        tenant_name="Acme",
        overview={"average_risk": 10, "registered_agents": 3, "online_agents": 2, "open_incidents": 0, "events_24h": 12},
        hosts=[],
        incidents=[],
        recommendation={"label": "Review posture", "route": "/soc"},
        client_dashboard={
            "posture_score": 90,
            "protected_assets": 3,
            "critical_incidents": 0,
            "agent_health": {"total": 3, "online": 2, "offline": 1},
            "risk_trend": [12, 10, 9, 8, 7],
            "top_risk_areas": [{"name": "Agent Coverage", "score": 20}],
            "important_events": [],
            "executive_summary": "Security posture is stable and monitored.",
        },
    )

    assert "Security Posture Score" in html
    assert "Executive Mode" in html
    assert "Technical Mode" in html
    assert "Last 5 Important Events" in html
