"""Tenant scope helpers for defensive multi-tenant code paths.

This file intentionally lives under `security/` for documentation and static
analysis of tenant-scope rules. The legacy project also has `security.py`, so
runtime imports should avoid `import security.tenant_scope` unless the project
is later converted to a package.
"""

from __future__ import annotations

from typing import Any


def require_tenant_scope(tenant_id: str | None) -> str:
    tenant = str(tenant_id or "").strip()
    if not tenant:
        raise ValueError("tenant_id_required")
    if tenant in {"*", "all", "global"}:
        raise ValueError("wildcard_tenant_scope_forbidden")
    return tenant


def assert_same_tenant(expected_tenant_id: str, actual_tenant_id: str) -> str:
    expected = require_tenant_scope(expected_tenant_id)
    actual = require_tenant_scope(actual_tenant_id)
    if expected != actual:
        raise PermissionError("tenant_scope_mismatch")
    return actual


def safe_tenant_filter(tenant_id: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(extra or {})
    payload["tenant_id"] = require_tenant_scope(tenant_id)
    return payload
