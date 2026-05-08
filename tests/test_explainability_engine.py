from xdr.explainability_engine import ExplainabilityEngine


def test_explainability_engine_builds_evidence_chain():
    explanation = ExplainabilityEngine().explain_detection(
        {
            "rule_id": "SAFE-EDR-001",
            "rule_name": "Suspicious PowerShell",
            "summary": "Encoded PowerShell command",
            "confidence": 0.81,
            "related_events": [{"event_id": "evt-1", "event_type": "process_execution", "host_id": "h1"}],
        },
        event={"event_id": "evt-1", "event_type": "process_execution", "process_name": "powershell.exe", "host_id": "h1"},
        correlations=[{"rule_id": "SAFE-COR-001"}],
        killchain_findings=[{"stage": "execution"}],
    ).to_dict()

    assert "Suspicious PowerShell" in explanation["why_generated"]
    assert "detection:SAFE-EDR-001" in explanation["evidence_chain"]
    assert "correlation_engine" in explanation["contributing_engines"]
    assert "killchain_engine" in explanation["contributing_engines"]
    assert explanation["confidence"] >= 0.8
