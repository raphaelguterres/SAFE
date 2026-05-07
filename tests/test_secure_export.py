from __future__ import annotations

import json

from xdr.export_engine import export_incidents


def test_incident_export_is_tenant_scoped_and_redacted():
    incidents = [
        {"id": 1, "tenant_id": "tenant-a", "title": "A", "api_key": "nga_secret", "host_key": "host_secret"},
        {"id": 2, "tenant_id": "tenant-b", "title": "B", "token": "ng_other"},
    ]
    content_type, body = export_incidents(incidents, tenant_id="tenant-a", fmt="json", limit=10)
    payload = json.loads(body)

    assert content_type.startswith("application/json")
    assert payload["total"] == 1
    assert payload["incidents"][0]["tenant_id"] == "tenant-a"
    assert payload["incidents"][0]["api_key"] == "[REDACTED]"
    assert "tenant-b" not in body
    assert "secret" not in body


def test_incidents_export_endpoint_returns_redacted_download():
    import app as app_mod
    from auth import get_or_create_token

    resp = app_mod.app.test_client().get(
        "/api/incidents/export?format=json&limit=5",
        headers={"X-API-Token": get_or_create_token()},
    )

    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("application/json")
    assert "attachment;" in resp.headers["Content-Disposition"]
    assert "api_key" not in resp.get_data(as_text=True).lower()
