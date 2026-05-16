from __future__ import annotations

import yaml

from server.openapi import OPENAPI_PATH, load_openapi_spec


def test_openapi_yaml_is_parseable_and_documents_required_routes():
    spec = load_openapi_spec()

    assert spec["openapi"].startswith("3.")
    for path in (
        "/api/events",
        "/api/agent/register",
        "/api/agent/heartbeat",
        "/api/agent/events",
        "/api/xdr/events",
        "/api/incidents",
        "/api/incidents/export",
        "/api/detection/rules",
        "/api/detection/coverage",
        "/api/admin/performance",
        "/api/admin/observability",
        "/api/admin/config/status",
        "/api/admin/audit/integrity",
    ):
        assert path in spec["paths"]
    assert "LegacyAgentKey" in spec["components"]["securitySchemes"]


def test_openapi_yaml_file_parses_with_pyyaml_directly():
    raw = OPENAPI_PATH.read_text(encoding="utf-8")

    parsed = yaml.safe_load(raw)

    assert parsed["info"]["title"].startswith("SAFE")
