"""Secure incident export with tenant scope and redaction."""

from __future__ import annotations

import csv
import io
import json
from typing import Any


SENSITIVE_HINTS = ("token", "secret", "password", "passwd", "api_key", "host_key", "hmac", "signature")


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if any(hint in lowered for hint in SENSITIVE_HINTS):
                redacted[str(key)] = "[REDACTED]"
            else:
                redacted[str(key)] = redact_sensitive(item)
        return redacted
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str) and _looks_like_secret(value):
        return value[:6] + "***"
    return value


def export_incidents(
    incidents: list[dict[str, Any]],
    *,
    tenant_id: str,
    fmt: str = "json",
    limit: int = 500,
) -> tuple[str, str]:
    tenant = str(tenant_id or "").strip()
    if not tenant:
        raise ValueError("tenant_id_required")
    safe_limit = max(1, min(int(limit), 1000))
    rows = [
        redact_sensitive(dict(item))
        for item in incidents[:safe_limit]
        if str(item.get("tenant_id") or tenant) == tenant
    ]
    if fmt == "csv":
        return "text/csv; charset=utf-8", _to_csv(rows)
    if fmt != "json":
        raise ValueError("unsupported_export_format")
    return "application/json; charset=utf-8", json.dumps(
        {"tenant_id": tenant, "count": len(rows), "total": len(rows), "incidents": rows},
        ensure_ascii=False,
        indent=2,
        default=str,
    )


def _to_csv(rows: list[dict[str, Any]]) -> str:
    fields = [
        "id",
        "incident_id",
        "title",
        "severity",
        "status",
        "host_id",
        "assigned_to",
        "created_at",
        "updated_at",
        "mitre_tactic",
        "mitre_tech",
        "summary",
    ]
    handle = io.StringIO()
    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        clean = {
            key: json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else value
            for key, value in row.items()
        }
        writer.writerow(clean)
    return handle.getvalue()


def _looks_like_secret(value: str) -> bool:
    text = value.strip()
    if text.startswith(("ng_", "nga_", "nge_", "sk_live_", "sk_test_", "whsec_")):
        return True
    return len(text) >= 48 and any(ch.isdigit() for ch in text) and any(ch.isalpha() for ch in text)
