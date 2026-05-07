"""Local production-readiness and secrets hygiene checks for SAFE."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SECRET_PATTERNS = [
    re.compile(r"\bng_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnga_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bnge_[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b"),
]


@dataclass(frozen=True, slots=True)
class SelfCheck:
    name: str
    status: str
    message: str
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_self_check(root: str | Path | None = None, environ: dict[str, str] | None = None) -> dict[str, Any]:
    base = Path(root or Path.cwd())
    env = environ if environ is not None else os.environ
    checks = [
        _env_not_committed(base),
        _docs_do_not_contain_tokens(base),
        _hmac_secret_configured(env),
        _debug_off_in_production(env),
        _sensitive_file_permissions(base),
    ]
    return {
        "ok": not any(item.status == "fail" and item.severity == "critical" for item in checks),
        "checks": [item.to_dict() for item in checks],
    }


def _env_not_committed(base: Path) -> SelfCheck:
    gitignore = base / ".gitignore"
    ignore_text = gitignore.read_text(encoding="utf-8", errors="ignore") if gitignore.exists() else ""
    if ".env" in ignore_text:
        return SelfCheck(".env_gitignore", "pass", ".env is ignored.")
    return SelfCheck(".env_gitignore", "fail", "Add .env to .gitignore.", "critical")


def _docs_do_not_contain_tokens(base: Path) -> SelfCheck:
    findings: list[str] = []
    for path in [base / "README.md", base / "SECURITY.md", base / "DEPLOY.md"]:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            findings.append(path.name)
    if findings:
        return SelfCheck("docs_secret_scan", "fail", f"Potential token examples in: {', '.join(findings)}", "critical")
    return SelfCheck("docs_secret_scan", "pass", "No legacy token patterns found in main docs.")


def _hmac_secret_configured(env: dict[str, str]) -> SelfCheck:
    secret = env.get("NETGUARD_RESPONSE_POLICY_SECRET") or env.get("NETGUARD_RESPONSE_ACTION_SECRET") or ""
    if len(secret) >= 32:
        return SelfCheck("response_hmac_secret", "pass", "Response HMAC secret is configured.")
    return SelfCheck("response_hmac_secret", "warn", "Configure NETGUARD_RESPONSE_POLICY_SECRET for guarded actions.", "warning")


def _debug_off_in_production(env: dict[str, str]) -> SelfCheck:
    prod = (env.get("IDS_ENV") or env.get("NETGUARD_ENV") or "").lower() in {"prod", "production"}
    debug = str(env.get("FLASK_DEBUG") or env.get("NETGUARD_DEBUG") or "").lower() in {"1", "true", "yes", "on"}
    if prod and debug:
        return SelfCheck("debug_mode", "fail", "Debug mode is enabled in production.", "critical")
    return SelfCheck("debug_mode", "pass", "Debug mode posture is acceptable.")


def _sensitive_file_permissions(base: Path) -> SelfCheck:
    sensitive = [base / ".netguard_token", base / ".netguard_totp"]
    weak: list[str] = []
    if os.name == "nt":
        return SelfCheck("sensitive_file_permissions", "pass", "Permission check skipped on Windows ACLs.")
    for path in sensitive:
        if not path.exists():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            weak.append(path.name)
    if weak:
        return SelfCheck("sensitive_file_permissions", "fail", f"Weak permissions: {', '.join(weak)}", "critical")
    return SelfCheck("sensitive_file_permissions", "pass", "Sensitive files are owner-only.")


if __name__ == "__main__":
    import json

    print(json.dumps(run_self_check(), indent=2))
