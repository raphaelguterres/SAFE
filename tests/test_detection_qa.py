from xdr.detection_qa import DetectionQAEngine


def test_detection_qa_flags_missing_mitre_and_duplicates():
    rules = [
        {"rule_id": "R1", "severity": "medium", "event_types": ["process_execution"], "mitre": {"tactic": "", "technique": ""}},
        {"rule_id": "R1", "severity": "medium", "event_types": ["process_execution"], "mitre": {"tactic": "execution", "technique": "T1059"}},
    ]

    report = DetectionQAEngine().evaluate(rules, telemetry_counts={"R1": 800})

    assert report.total_rules == 2
    assert "R1" in report.duplicate_rules
    assert "R1" in report.missing_mitre
    assert "R1" in report.noisy_rules
    assert report.score < 100


def test_detection_qa_accepts_clean_rule():
    rules = [{"rule_id": "R2", "severity": "high", "event_types": ["network_connection"], "mitre": {"tactic": "command_and_control", "technique": "T1071"}, "confidence_score": 0.9}]

    report = DetectionQAEngine().evaluate(rules)

    assert report.findings == []
    assert report.score == 100
