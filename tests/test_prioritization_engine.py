from xdr.prioritization_engine import IncidentPrioritizationEngine


def test_prioritization_escalates_critical_asset_with_progression():
    priority = IncidentPrioritizationEngine().prioritize(
        severity="high",
        business_impact="critical service interruption possible",
        affected_hosts=["dc-01", "ws-01"],
        critical_assets=["dc-01"],
        attack_progression=82,
        persistence=True,
        lateral_movement=True,
        credential_access=True,
        threat_intel_severity="high",
    ).to_dict()

    assert priority["priority"] == "Critical"
    assert priority["score"] >= 86
    assert "critical_asset_involved" in priority["reasons"]
    assert priority["recommended_sla"] == "immediate_review"


def test_prioritization_keeps_low_noise_as_low():
    priority = IncidentPrioritizationEngine().prioritize(severity="low", attack_progression=0)

    assert priority.priority == "Low"
