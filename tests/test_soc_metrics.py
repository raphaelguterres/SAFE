from xdr.reporting_engine import ReportingEngine
from xdr.soc_metrics import calculate_soc_metrics


def test_soc_metrics_calculates_core_kpis():
    metrics = calculate_soc_metrics(
        cases=[
            {
                "status": "investigating",
                "severity": "critical",
                "assigned_to": "alice",
                "created_at": "2026-05-08T10:00:00Z",
            },
            {
                "status": "closed",
                "severity": "low",
                "assigned_to": "bob",
                "created_at": "2026-05-08T09:00:00Z",
                "updated_at": "2026-05-08T10:00:00Z",
            },
        ],
        incidents=[],
        response_actions=[{"status": "succeeded"}, {"status": "failed"}],
        analysts=["alice", "bob"],
    )

    assert metrics["incident_volume"] == 2
    assert metrics["unresolved_criticals"] == 1
    assert metrics["containment_success"] == 0.5
    assert metrics["analyst_workload"]["alice"] == 1


def test_reporting_engine_outputs_json_csv_and_pdf_ready_structure():
    report = ReportingEngine().generate(
        generated_at="2026-05-08T10:00:00Z",
        cases=[{"severity": "critical", "mitre_tactics": ["execution"]}],
        metrics={"unresolved_criticals": 1, "open_cases": 1, "containment_success": 1.0},
    )

    payload = report.to_dict()
    csv_payload = report.to_csv()
    assert payload["pdf_ready"]["layout"] == "executive"
    assert "SAFE SOC Executive Report" in csv_payload
