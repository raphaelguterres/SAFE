"""Non-blocking SAFE demo readiness checks."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


@dataclass(slots=True)
class DemoCheck:
    name: str
    status: str
    message: str


def run_demo_readiness_check(root: str | Path = ".") -> dict:
    base = Path(root).resolve()
    checks = [
        _docs_check(base),
        _branding_context_check(base),
        _template_import_check(),
        _route_check(),
    ]
    warnings = [check.name for check in checks if check.status == "warn"]
    failures = [check.name for check in checks if check.status == "fail"]
    return {
        "ok": not failures,
        "status": "PASS" if not failures else "FAIL",
        "checks": [asdict(check) for check in checks],
        "warnings": warnings,
        "failures": failures,
    }


def _docs_check(base: Path) -> DemoCheck:
    required = ["README.md", "INSTALL.md", "DEPLOY.md", "docs/DEMO_GUIDE.md", "docs/DEMO_ASSETS.md", "docs/SCREENSHOT_GUIDE.md"]
    missing = [path for path in required if not (base / path).exists()]
    if missing:
        return DemoCheck("demo_docs", "fail", "Missing demo docs: " + ", ".join(missing))
    return DemoCheck("demo_docs", "pass", "Demo docs are present.")


def _branding_context_check(base: Path) -> DemoCheck:
    targets = ["README.md", "templates/client_overview.html", "docs/DEMO_ASSETS.md"]
    combined = "\n".join((base / path).read_text(encoding="utf-8", errors="ignore") for path in targets)
    if "SAFE" not in combined:
        return DemoCheck("safe_branding", "fail", "SAFE brand not visible in demo surfaces.")
    suspicious = [line for line in combined.splitlines() if "NetGuard" in line and "legacy" not in line.lower() and "compat" not in line.lower()]
    if suspicious:
        return DemoCheck("legacy_branding_context", "warn", "NetGuard appears outside clear legacy compatibility context.")
    return DemoCheck("safe_branding", "pass", "SAFE branding is visible with legacy context preserved.")


def _template_import_check() -> DemoCheck:
    try:
        from jinja2 import Environment, FileSystemLoader

        env = Environment(loader=FileSystemLoader(str(ROOT / "templates")))
        for name in ("client_overview.html", "executive.html", "soc/overview.html"):
            env.get_template(name)
    except Exception as exc:
        return DemoCheck("template_render", "fail", f"Template check failed: {exc}")
    return DemoCheck("template_render", "pass", "Core demo templates load.")


def _route_check() -> DemoCheck:
    try:
        _apply_demo_env()
        app_module = importlib.import_module("app")
        client = app_module.app.test_client()
        failures = []
        for path in ("/api/health", "/client/overview", "/executive", "/api/openapi.yaml"):
            response = client.get(path)
            if response.status_code >= 500:
                failures.append(f"{path}:{response.status_code}")
        if failures:
            return DemoCheck("demo_routes", "fail", "Route failures: " + ", ".join(failures))
    except Exception as exc:
        return DemoCheck("demo_routes", "fail", f"Route check failed: {exc}")
    return DemoCheck("demo_routes", "pass", "Core demo routes respond without 500.")


def _apply_demo_env() -> None:
    os.environ.setdefault("IDS_AUTH", "false")
    os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
    os.environ.setdefault("IDS_AUTOSTART_BACKGROUND", "false")
    os.environ.setdefault("IDS_AUTOSTART_SOC_ENGINE", "false")
    os.environ.setdefault("IDS_AUTOSTART_MONITOR", "false")
    os.environ.setdefault("SECRET_KEY", "demo-readiness-secret-key-32-characters")
    os.environ.setdefault("TOKEN_SIGNING_SECRET", "demo-readiness-token-secret-32-chars")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SAFE demo readiness checks.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_demo_readiness_check(args.root)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"SAFE demo readiness: {result['status']}")
        for check in result["checks"]:
            print(f"[{check['status'].upper():4}] {check['name']}: {check['message']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
