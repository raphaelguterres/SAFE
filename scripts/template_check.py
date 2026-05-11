"""Template quality checks for SAFE release readiness."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


REQUIRED_TEMPLATES = [
    "templates/login.html",
    "templates/admin_dashboard.html",
    "templates/soc/base.html",
    "templates/soc/overview.html",
    "templates/soc/detection_packs.html",
    "templates/soc/search.html",
    "templates/host_triage.html",
    "templates/executive.html",
]
REQUIRED_PARTIALS = [
    "templates/soc/partials/sidebar.html",
    "templates/partials/status_badge.html",
    "templates/partials/risk_card.html",
    "templates/partials/empty_state.html",
]
SECRET_PATTERNS = [
    re.compile(r"\bng_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnga_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnge_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b"),
]


@dataclass(frozen=True, slots=True)
class TemplateFinding:
    name: str
    status: str
    message: str
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_template_check(root: str | Path = ".") -> dict[str, Any]:
    base = Path(root)
    findings: list[TemplateFinding] = []
    findings.extend(_check_required_files(base, REQUIRED_TEMPLATES, "template"))
    findings.extend(_check_required_files(base, REQUIRED_PARTIALS, "partial"))
    findings.extend(_check_template_content(base))
    blockers = [item for item in findings if item.status == "fail" and item.severity == "critical"]
    warnings = [item for item in findings if item.status != "pass" and item.severity != "critical"]
    return {
        "ok": not blockers,
        "checks": [item.to_dict() for item in findings],
        "summary": {
            "checks": len(findings),
            "blockers": len(blockers),
            "warnings": len(warnings),
        },
    }


def _check_required_files(base: Path, paths: list[str], label: str) -> list[TemplateFinding]:
    findings: list[TemplateFinding] = []
    for rel in paths:
        if (base / rel).exists():
            findings.append(TemplateFinding(f"{label}:{rel}", "pass", "File exists."))
        else:
            findings.append(TemplateFinding(f"{label}:{rel}", "fail", "Required file is missing.", "critical"))
    return findings


def _check_template_content(base: Path) -> list[TemplateFinding]:
    findings: list[TemplateFinding] = []
    for path in (base / "templates").rglob("*.html"):
        rel = path.relative_to(base).as_posix()
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            findings.append(TemplateFinding(f"secrets:{rel}", "fail", "Potential secret/token rendered in template.", "critical"))
        if "Traceback (most recent call last)" in text or "werkzeug.debug" in text:
            findings.append(TemplateFinding(f"debug:{rel}", "fail", "Debug/stack trace text appears in template.", "critical"))
        if any(term in text for term in ("NetGuard Dashboard", "NetGuard SOC", "NetGuard Agent")):
            findings.append(TemplateFinding(f"branding:{rel}", "fail", "Legacy product copy remains in visible template.", "critical"))
    if "SAFE" in (base / "templates" / "login.html").read_text(encoding="utf-8", errors="ignore"):
        findings.append(TemplateFinding("branding:login", "pass", "Login page includes SAFE branding."))
    else:
        findings.append(TemplateFinding("branding:login", "fail", "Login page should include SAFE branding.", "critical"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Check SAFE template quality.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_template_check(args.root)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        status = "PASS" if result["ok"] else "FAIL"
        print(f"{status} template check: {result['summary']['blockers']} blockers, {result['summary']['warnings']} warnings")
        for item in result["checks"]:
            if item["status"] != "pass":
                print(f"  {item['severity'].upper()} {item['name']}: {item['message']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
