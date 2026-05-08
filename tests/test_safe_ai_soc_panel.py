from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from xdr.executive_summary_engine import ExecutiveSummaryEngine
from xdr.playbook_engine import PlaybookRecommendationEngine
from xdr.threat_intel import ThreatIntelEnrichmentEngine


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_safe_copilot_routes_are_registered_and_protected():
    app_src = _read("app.py")
    sidebar = _read("templates/soc/partials/sidebar.html")

    assert '@app.route("/soc/copilot", methods=["GET"])' in app_src
    assert '@app.route("/api/soc/copilot", methods=["GET"])' in app_src
    assert "SOC_COPILOT_VIEW" in app_src
    assert '@require_role("analyst", "admin")' in app_src
    assert "/soc/copilot" in sidebar


def test_safe_copilot_template_renders_without_data_and_no_secret_words():
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")))
    env.globals["url_for"] = lambda endpoint, **values: f"/static/{values.get('filename', '')}"
    template = env.get_template("soc/copilot.html")
    html = template.render()

    assert "SAFE Copilot" in html
    assert "No active alert context yet" in html
    forbidden = ("token_signing_secret", "host_key", "hmac secret", "api_key=", "sk_live_", "sk_test_")
    assert not any(marker in html.lower() for marker in forbidden)


def test_playbook_recommendations_are_approval_gated_for_containment():
    recs = PlaybookRecommendationEngine().recommend(
        stage="impact",
        objective="business_disruption",
        behaviors=["impact_behavior"],
        severity="critical",
    )

    isolation = [item for item in recs if item.playbook == "host_isolation_review"]
    assert isolation
    assert isolation[0].requires_approval is True
    assert isolation[0].destructive is False


def test_threat_intel_enrichment_is_offline_safe():
    enriched = ThreatIntelEnrichmentEngine().enrich_ioc("198.51.100.66").to_dict()

    assert enriched["ioc_type"] == "ip"
    assert "ioc_confidence" in enriched
    assert "geo_context" in enriched


def test_executive_summary_uses_nontechnical_language():
    summary = ExecutiveSummaryEngine().explain(
        posture_score=42,
        active_threats=3,
        critical_hosts=2,
        open_incidents=1,
        attack_progression=80,
    ).to_dict()

    assert summary["risk_level"] == "Critical"
    assert "Immediate security risk" in summary["operational_risk"]
