from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from xdr.posture_engine import PostureEngine
from xdr.story_engine import StoryEngine


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_story_engine_turns_technical_events_into_investigation_story():
    story = StoryEngine().build_story(
        host_id="SAFE-WS-14",
        events=[
            {
                "host_id": "SAFE-WS-14",
                "event_type": "process",
                "command_line": "powershell.exe -enc abc",
                "mitre_tactic": "execution",
            },
            {
                "host_id": "SAFE-WS-14",
                "event_type": "network",
                "summary": "external beaconing observed",
                "mitre_tactic": "command_and_control",
            },
        ],
    )

    assert "SAFE-WS-14" in story.summary
    assert "execution" in story.progression
    assert "command_and_control" in story.progression
    assert story.likely_objective == "remote_control"
    assert "encoded_powershell" in story.evidence_tags


def test_posture_engine_scores_environment_without_raw_secrets():
    posture = PostureEngine().calculate(
        hosts=[
            {"host_id": "h1", "status": "online", "risk_score": 10, "agent_enrolled": True},
            {"host_id": "h2", "status": "offline", "risk_score": 85, "agent_enrolled": True},
        ],
        incidents=[{"severity": "critical", "status": "open"}],
        response_queue={"pending_approvals": 1, "failed": 0},
        telemetry={"events_24h": 50},
    ).to_dict()

    assert 0 <= posture["score"] <= 100
    assert posture["label"] in {"Excellent", "Good", "Attention Needed", "Critical Risk"}
    assert "triage_high_risk_hosts" in posture["recommendations"]


def test_safe_soc_experience_routes_and_rbac_are_wired():
    app_src = _read("app.py")
    routes_src = _read("routes/soc.py")

    for marker in (
        '@app.route("/soc/campaigns", methods=["GET"])',
        '@app.route("/soc/response-center", methods=["GET"])',
        '@app.route("/executive", methods=["GET"])',
        "SOC_CAMPAIGNS_VIEW",
        "EXECUTIVE_VIEW",
    ):
        assert marker in app_src

    assert '@bp.route("/soc/overview")' in routes_src
    assert '@bp.route("/soc/host/<host_id>")' in routes_src
    assert '@require_role("analyst", "admin")' in app_src


def test_safe_soc_templates_and_partials_render_without_data():
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")))
    for template_name in (
        "partials/threat_timeline.html",
        "soc/overview.html",
        "soc/campaigns.html",
        "soc/host_detail.html",
        "live_response.html",
        "executive.html",
    ):
        env.get_template(template_name)

    partial = _read("templates/partials/threat_timeline.html")
    assert "No security activity yet" in partial


def test_executive_and_soc_experience_do_not_expose_sensitive_material():
    combined = "\n".join(
        _read(path)
        for path in (
            "templates/executive.html",
            "templates/client_overview.html",
            "templates/soc/overview.html",
            "templates/soc/campaigns.html",
            "templates/partials/threat_timeline.html",
            "static/css/safe-ui.css",
        )
    ).lower()
    for marker in (
        "token_signing_secret",
        "host key",
        "host_key",
        "hmac secret",
        "api_key=",
        "sk_live_",
        "sk_test_",
    ):
        assert marker not in combined


def test_safe_ui_system_is_loaded_by_soc_base():
    base = _read("templates/soc/base.html")
    css = _read("static/css/safe-ui.css")

    assert "css/safe-ui.css" in base
    for marker in (
        "SAFE SOC Experience Platform design system",
        "--safe-space-4",
        ".safe-threat-timeline",
        ".safe-campaign-card",
        ".safe-executive-hero",
        "@keyframes safePulse",
    ):
        assert marker in css
