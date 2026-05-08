from xdr.alert_context_engine import AlertContextEngine


def test_alert_context_generates_business_and_investigation_context():
    context = AlertContextEngine().contextualize(
        detections=[
            {
                "host_id": "SAFE-WS-14",
                "severity": "high",
                "summary": "PowerShell encoded command followed by external beaconing",
                "tactic": "command_and_control",
                "confidence": 0.82,
            }
        ],
        threat_intel=[{"matched": True, "severity": "high", "confidence": 85, "score": 70}],
        critical_assets=["SAFE-WS-14"],
    ).to_dict()

    assert context["likely_attack_stage"] == "command_and_control"
    assert context["likely_objective"] == "remote_control"
    assert context["confidence"] >= 0.8
    assert "SAFE-WS-14" in context["affected_assets"]
    assert "review_network_destinations" in context["recommended_investigation"]
    assert "prepare_network_containment_approval" in context["recommended_response"]
    assert context["false_positive_probability"] < 0.5


def test_alert_context_is_tenant_scope_neutral_without_cross_tenant_merge():
    first = AlertContextEngine().contextualize(detections=[{"host_id": "tenant-a-host", "severity": "medium"}])
    second = AlertContextEngine().contextualize(detections=[{"host_id": "tenant-b-host", "severity": "medium"}])

    assert first.affected_assets == ["tenant-a-host"]
    assert second.affected_assets == ["tenant-b-host"]
