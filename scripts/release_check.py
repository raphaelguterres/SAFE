"""SAFE release quality gate.

Default mode runs the real quality gates used for a release candidate. Use
--quick for documentation/static validation during development or unit tests.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.branding_check import run_branding_check
from scripts.security_self_check import run_self_check
from scripts.template_check import run_template_check
from server.config_validator import validate_production_config


REQUIRED_DOCS = [
    "README.md",
    "INSTALL.md",
    "CHANGELOG.md",
    "RELEASE_NOTES.md",
    "KNOWN_LIMITATIONS.md",
    "docs/PRODUCT_OVERVIEW.md",
    "docs/ARCHITECTURE.md",
    "docs/SECURITY_MODEL.md",
    "docs/DEMO_GUIDE.md",
    "docs/DEMO_ASSETS.md",
    "docs/SCREENSHOT_GUIDE.md",
    "docs/API_REFERENCE.md",
    "docs/ROADMAP.md",
    "docs/PORTFOLIO_SUMMARY.md",
    "openapi/safe-api.yaml",
]
IMPORT_MODULES = [
    "app",
    "schema.canonical_event",
    "xdr.normalization_engine",
    "xdr.enrichment_pipeline",
    "xdr.event_lineage",
    "xdr.detection_qa",
    "xdr.replay_engine",
    "xdr.security_graph",
    "xdr.retention_engine",
    "xdr.security_search",
]


@dataclass(slots=True)
class GateResult:
    name: str
    status: str
    message: str
    score: int
    duration_seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_release_check(root: str | Path = ".", *, quick: bool = False) -> dict[str, Any]:
    base = Path(root).resolve()
    _apply_release_env()
    gates: list[GateResult] = []
    if not quick:
        gates.append(_run_command_gate("pytest", [sys.executable, "-m", "pytest", "-q"], base))
        gates.append(_run_command_gate("pentest_audit", [sys.executable, "run_pentest_audit.py"], base))
    else:
        gates.append(GateResult("pytest", "warn", "Skipped in quick mode.", 70, warnings=["quick_mode"]))
        gates.append(GateResult("pentest_audit", "warn", "Skipped in quick mode.", 70, warnings=["quick_mode"]))

    gates.extend(
        [
            _timed_gate("import_smoke", lambda: _import_smoke()),
            _timed_gate("route_smoke", lambda: _route_smoke()),
            _timed_gate("config_validation", lambda: _config_validation()),
            _timed_gate("security_self_check", lambda: _security_self_check(base)),
            _timed_gate("migration_check", lambda: _migration_check()),
            _timed_gate("template_render_check", lambda: _template_check(base)),
            _timed_gate("docs_presence_check", lambda: _docs_check(base)),
            _timed_gate("branding_check", lambda: _branding_check(base)),
            _timed_gate("demo_readiness_check", lambda: _demo_readiness_check(base)),
        ]
    )
    blockers = [blocker for gate in gates for blocker in gate.blockers]
    warnings = [warning for gate in gates for warning in gate.warnings]
    score = round(sum(gate.score for gate in gates) / max(len(gates), 1))
    return {
        "status": "PASS" if not blockers else "FAIL",
        "release_readiness_score": score,
        "gates": [gate.to_dict() for gate in gates],
        "summary": {
            "total_gates": len(gates),
            "passed": sum(1 for gate in gates if gate.status == "pass"),
            "warnings": len(warnings),
            "blockers": len(blockers),
        },
        "warnings": warnings,
        "blockers": blockers,
    }


def _release_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(_release_env_overrides())
    return env


def _release_env_overrides() -> dict[str, str]:
    return {
        "SAFE_ENV": "development",
        "IDS_ENV": "development",
        "IDS_AUTH": "false",
        "IDS_DASHBOARD_AUTH": "false",
        "HTTPS_ONLY": "false",
        "TOKEN_SIGNING_SECRET": "release-check-token-signing-secret-32chars",
        "SECRET_KEY": "release-check-secret-key-32-characters-min",
        "NETGUARD_RESPONSE_POLICY_SECRET": "release-check-response-policy-secret-32chars",
        "IDS_AUTOSTART_BACKGROUND": "false",
        "IDS_AUTOSTART_SOC_ENGINE": "false",
        "IDS_AUTOSTART_MONITOR": "false",
    }


def _apply_release_env() -> None:
    for key, value in _release_env_overrides().items():
        os.environ[key] = value


def _run_command_gate(name: str, command: list[str], cwd: Path) -> GateResult:
    start = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        env=_release_env(),
        text=True,
        capture_output=True,
        timeout=600,
    )
    duration = time.perf_counter() - start
    output = (completed.stdout + "\n" + completed.stderr).strip()
    tail = "\n".join(output.splitlines()[-12:])
    if completed.returncode == 0:
        return GateResult(name, "pass", tail or "Command passed.", 100, duration)
    return GateResult(name, "fail", tail or "Command failed.", 0, duration, blockers=[f"{name}_failed"])


def _timed_gate(name: str, fn: Callable[[], GateResult]) -> GateResult:
    start = time.perf_counter()
    try:
        result = fn()
    except Exception as exc:  # pragma: no cover - defensive release guard
        result = GateResult(name, "fail", f"{exc.__class__.__name__}: {exc}", 0, blockers=[f"{name}_exception"])
    result.duration_seconds = round(time.perf_counter() - start, 3)
    return result


def _import_smoke() -> GateResult:
    imported: list[str] = []
    for module in IMPORT_MODULES:
        importlib.import_module(module)
        imported.append(module)
    return GateResult("import_smoke", "pass", f"Imported {len(imported)} core modules.", 100)


def _route_smoke() -> GateResult:
    app_module = importlib.import_module("app")
    client = app_module.app.test_client()
    paths = ["/api/health", "/login", "/pricing", "/soc-preview", "/executive", "/client/overview", "/api/openapi.yaml"]
    failures: list[str] = []
    for path in paths:
        response = client.get(path, headers={"Accept": "text/html"})
        if response.status_code >= 500:
            failures.append(f"{path}:{response.status_code}")
        body = response.get_data(as_text=True)
        if "Traceback (most recent call last)" in body:
            failures.append(f"{path}:traceback")
    if failures:
        return GateResult("route_smoke", "fail", "Route smoke failures detected.", 0, blockers=failures)
    return GateResult("route_smoke", "pass", f"Checked {len(paths)} representative routes.", 100)


def _config_validation() -> GateResult:
    env = {
        "IDS_ENV": "production",
        "SECRET_KEY": "prod-secret-key-minimum-32-characters",
        "IDS_AUTH": "true",
        "IDS_CSRF_DISABLED": "false",
        "HTTPS_ONLY": "true",
        "SESSION_COOKIE_SECURE": "true",
        "SESSION_COOKIE_SAMESITE": "Strict",
        "NETGUARD_XDR_INGEST_V2": "true",
        "NETGUARD_XDR_QUEUE_MAX": "5000",
        "NETGUARD_XDR_BATCH_SIZE": "100",
        "NETGUARD_XDR_CONSUMERS": "2",
        "NETGUARD_STORAGE_BACKEND": "postgresql",
    }
    result = validate_production_config(env)
    if result.get("ok"):
        return GateResult("config_validation", "pass", "Reference production config passes.", 100)
    return GateResult("config_validation", "fail", "Reference production config failed.", 0, blockers=["config_validation_failed"])


def _security_self_check(base: Path) -> GateResult:
    result = run_self_check(base, environ=_release_env())
    failed = [
        item["name"]
        for item in result.get("checks", [])
        if item.get("status") == "fail" and item.get("severity") == "critical"
    ]
    warnings = [
        item["name"]
        for item in result.get("checks", [])
        if item.get("status") == "warn"
    ]
    if failed:
        return GateResult("security_self_check", "fail", "Critical security self-check failure.", 0, warnings, failed)
    status = "warn" if warnings else "pass"
    score = 85 if warnings else 100
    return GateResult("security_self_check", status, "Security self-check completed.", score, warnings)


def _migration_check() -> GateResult:
    from storage.storage_adapter import SQLiteStorageAdapter

    with tempfile.TemporaryDirectory() as tmp:
        adapter = SQLiteStorageAdapter(Path(tmp) / "release-storage.db")
        adapter.write_hot_event("release-tenant", {"event_id": "release-smoke", "timestamp": "2026-01-01T00:00:00Z"})
        rows = adapter.query_hot_events(tenant_id="release-tenant", limit=1)
    if rows:
        return GateResult("migration_check", "pass", "Storage adapter schema initializes and queries.", 100)
    return GateResult("migration_check", "fail", "Storage adapter smoke query returned no rows.", 0, blockers=["storage_adapter_empty"])


def _template_check(base: Path) -> GateResult:
    result = run_template_check(base)
    blockers = [item["name"] for item in result["checks"] if item["status"] == "fail" and item["severity"] == "critical"]
    if blockers:
        return GateResult("template_render_check", "fail", "Template quality blockers found.", 0, blockers=blockers)
    return GateResult("template_render_check", "pass", "Template quality checks passed.", 100)


def _docs_check(base: Path) -> GateResult:
    missing = [path for path in REQUIRED_DOCS if not (base / path).exists()]
    if missing:
        return GateResult("docs_presence_check", "fail", "Required release docs are missing.", 0, blockers=missing)
    return GateResult("docs_presence_check", "pass", f"Found {len(REQUIRED_DOCS)} release docs.", 100)


def _branding_check(base: Path) -> GateResult:
    result = run_branding_check(base)
    blockers = [f"{item['path']}:{item['line']}" for item in result.get("blockers", [])]
    warnings = [f"{item['path']}:{item['line']}" for item in result.get("warnings", [])[:20]]
    if blockers:
        return GateResult("branding_check", "fail", "Branding blockers found.", 0, warnings, blockers)
    status = "warn" if warnings else "pass"
    score = 85 if warnings else 100
    return GateResult("branding_check", status, "Branding check completed.", score, warnings)


def _demo_readiness_check(base: Path) -> GateResult:
    from scripts.demo_readiness_check import run_demo_readiness_check

    result = run_demo_readiness_check(base)
    warnings = list(result.get("warnings") or [])
    failures = list(result.get("failures") or [])
    if failures:
        return GateResult(
            "demo_readiness_check",
            "warn",
            "Demo readiness has non-blocking findings.",
            80,
            warnings=warnings + failures,
        )
    status = "warn" if warnings else "pass"
    score = 90 if warnings else 100
    return GateResult("demo_readiness_check", status, "Demo readiness check completed.", score, warnings)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SAFE release quality gates.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--quick", action="store_true", help="Skip slow pytest and pentest audit gates.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_release_check(args.root, quick=args.quick)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"SAFE release readiness: {result['status']} ({result['release_readiness_score']}/100)")
        for gate in result["gates"]:
            print(f"[{gate['status'].upper():4}] {gate['name']}: {gate['message'].splitlines()[-1] if gate['message'] else ''}")
        if result["blockers"]:
            print("Blockers:")
            for blocker in result["blockers"]:
                print(f"  - {blocker}")
        if result["warnings"]:
            print("Warnings:")
            for warning in result["warnings"][:30]:
                print(f"  - {warning}")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
