from pathlib import Path

from demo.seed_demo import build_demo_dataset, write_dataset
from scripts.branding_check import run_branding_check
from scripts.project_health_report import build_health_report, write_reports
import scripts.release_check as release_check
from scripts.release_check import GateResult
from scripts.template_check import run_template_check


def test_template_quality_check_has_no_blockers():
    result = run_template_check(Path.cwd())
    assert result["ok"], result


def test_branding_check_has_no_visible_blockers():
    result = run_branding_check(Path.cwd())
    assert result["ok"], result


def test_release_check_quick_mode_completes_static_gates(monkeypatch):
    monkeypatch.setattr(
        release_check,
        "_import_smoke",
        lambda: GateResult("import_smoke", "pass", "stubbed import smoke", 100),
    )
    monkeypatch.setattr(
        release_check,
        "_route_smoke",
        lambda: GateResult("route_smoke", "pass", "stubbed route smoke", 100),
    )
    result = release_check.run_release_check(Path.cwd(), quick=True)
    assert result["status"] == "PASS", result
    assert result["release_readiness_score"] >= 80


def test_project_health_report_can_export(tmp_path):
    report = build_health_report(Path.cwd())
    assert report.modules_count > 0
    assert report.routes_count > 0
    exported = write_reports(report, tmp_path)
    assert Path(exported["markdown"]).exists()
    assert Path(exported["json"]).exists()


def test_demo_dataset_is_synthetic_and_exportable(tmp_path):
    dataset = build_demo_dataset()
    assert dataset.tenant["tenant_id"] == "safe-demo-enterprise"
    assert dataset.hosts
    assert dataset.incidents
    assert dataset.response_approvals
    output = write_dataset(dataset, tmp_path / "demo.json")
    text = output.read_text(encoding="utf-8")
    assert "safe-demo-enterprise" in text
    assert "ng_" not in text
