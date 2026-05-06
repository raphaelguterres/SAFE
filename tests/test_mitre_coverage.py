from __future__ import annotations

import os
import textwrap

from xdr.detections.process_rules import SuspiciousPowerShellRule
from xdr.rule_catalog import build_detection_coverage


def test_mitre_coverage_reads_yaml_mitre_and_survives_invalid_rule(tmp_path):
    (tmp_path / "valid.yml").write_text(
        textwrap.dedent(
            """
            title: Coverage PowerShell Rule
            id: NG-COVERAGE-001
            level: high
            logsource:
              product: windows
              category: process_creation
            mitre:
              tactic: execution
              technique: T1059.001
            detection:
              selection:
                CommandLine|contains: "-enc"
              condition: selection
            """
        ).strip(),
        encoding="utf-8",
    )
    (tmp_path / "broken.yml").write_text("id: broken\nseverity: high\ndetection: []\n", encoding="utf-8")

    coverage = build_detection_coverage(rules=[SuspiciousPowerShellRule()], yaml_dir=tmp_path)

    assert coverage["total_rules"] == 2
    assert coverage["yaml_health"]["loaded_files"] == 1
    assert coverage["yaml_health"]["skipped_files"] == 1
    assert coverage["rules_by_tactic"]["execution"] >= 2
    assert "T1059.001" in coverage["rules_by_technique"]
    assert coverage["killchain_coverage_score"] > 0


def test_detection_coverage_endpoint_returns_json():
    os.environ.setdefault("IDS_ENV", "test")
    os.environ.setdefault("IDS_AUTH", "false")
    os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
    os.environ.setdefault("HTTPS_ONLY", "false")
    os.environ.setdefault("TOKEN_SIGNING_SECRET", "coverage-test-signing-secret-32-bytes")

    import app as app_module

    app_module.app.config["TESTING"] = True
    response = app_module.app.test_client().get("/api/detection/coverage")

    assert response.status_code == 200
    payload = response.get_json()
    assert "total_rules" in payload
    assert "rules_by_technique" in payload
    assert "killchain_coverage_score" in payload
