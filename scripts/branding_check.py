"""SAFE branding consistency check.

The project intentionally keeps some legacy compatibility identifiers such as
NETGUARD_* environment variables and X-NetGuard-Agent-Key headers. This check
focuses on user-visible product copy and release surfaces while reporting
legacy compatibility references as warnings instead of false blockers.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


VISIBLE_EXTENSIONS = {".html", ".css", ".js", ".md", ".txt", ".yml", ".yaml"}
SKIP_DIRS = {
    ".git",
    ".pytest_cache",
    ".pytest_cache_netguard",
    ".pytest_tmp",
    ".tmp",
    ".venv",
    "venv",
    "__pycache__",
    "agent/.venv-build",
    "build",
    "dist",
    "htmlcov",
}
LEGACY_ALLOWED_PATTERNS = [
    re.compile(r"\bNETGUARD_[A-Z0-9_]+\b"),
    re.compile(r"\bX-NetGuard-Agent-Key\b"),
    re.compile(r"\bnetguard\.css\b"),
    re.compile(r"\bnetguard-ui\.js\b"),
    re.compile(r"\bdata-netguard-[a-z0-9-]+\b"),
    re.compile(r"\bnetguard[_-](audit|events|security|soc|edr)\b", re.IGNORECASE),
]
BLOCKER_PATTERNS = [
    "NetGuard Dashboard",
    "NetGuard SOC",
    "NetGuard Agent",
    "NetGuard XDR",
    "NetGuard IDS",
]


@dataclass(frozen=True, slots=True)
class BrandingFinding:
    path: str
    line: int
    term: str
    severity: str
    context: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_branding_check(root: str | Path = ".", *, strict: bool = False) -> dict[str, Any]:
    base = Path(root)
    findings: list[BrandingFinding] = []
    for path in _iter_visible_files(base):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            findings.extend(_find_line_issues(base, path, line_no, line, strict=strict))

    blockers = [item for item in findings if item.severity == "blocker"]
    warnings = [item for item in findings if item.severity == "warning"]
    return {
        "ok": not blockers,
        "blockers": [item.to_dict() for item in blockers],
        "warnings": [item.to_dict() for item in warnings],
        "summary": {
            "files_scanned": sum(1 for _ in _iter_visible_files(base)),
            "blockers": len(blockers),
            "warnings": len(warnings),
        },
    }


def _iter_visible_files(base: Path) -> Iterable[Path]:
    for path in base.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(base).as_posix()
        if _is_skipped(rel):
            continue
        if path.suffix.lower() in VISIBLE_EXTENSIONS:
            yield path


def _is_skipped(rel: str) -> bool:
    parts = rel.split("/")
    if any(part.startswith("tenant-isolation-") for part in parts):
        return True
    if any(part.startswith(".tmp") or part.startswith("ci_pytest") for part in parts):
        return True
    return any(skip in {parts[0], "/".join(parts[:2])} for skip in SKIP_DIRS)


def _find_line_issues(base: Path, path: Path, line_no: int, line: str, *, strict: bool) -> list[BrandingFinding]:
    rel = path.relative_to(base).as_posix()
    issues: list[BrandingFinding] = []
    for term in BLOCKER_PATTERNS:
        if term in line and not _is_allowed_legacy_line(line, rel):
            severity = "blocker" if _is_product_surface(rel) or strict else "warning"
            issues.append(BrandingFinding(rel, line_no, term, severity, _compact(line)))
    if strict:
        for term in ("NetGuard", "netguard"):
            if term in line and not _is_allowed_legacy_line(line, rel):
                issues.append(BrandingFinding(rel, line_no, term, "warning", _compact(line)))
    return issues


def _is_product_surface(rel: str) -> bool:
    return rel.startswith(("templates/", "static/")) or rel in {"README.md", "INSTALL.md"}


def _is_allowed_legacy_line(line: str, rel: str) -> bool:
    lowered = line.lower()
    if any(word in lowered for word in ("compat", "legacy", "migration", "original", "rebrand")):
        return True
    if rel.startswith(("NETGUARD_", "docs/screenshots/")):
        return True
    return any(pattern.search(line) for pattern in LEGACY_ALLOWED_PATTERNS)


def _compact(text: str, limit: int = 180) -> str:
    text = " ".join(text.strip().split())
    return text[:limit]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check SAFE branding consistency.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = run_branding_check(args.root, strict=args.strict)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        status = "PASS" if result["ok"] else "FAIL"
        summary = result["summary"]
        print(f"{status} branding check: {summary['blockers']} blockers, {summary['warnings']} warnings")
        for item in result["blockers"][:20]:
            print(f"  BLOCKER {item['path']}:{item['line']} {item['term']} -> {item['context']}")
        for item in result["warnings"][:20]:
            print(f"  WARN    {item['path']}:{item['line']} {item['term']} -> {item['context']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
