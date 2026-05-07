from __future__ import annotations

import os

os.environ.setdefault("IDS_AUTH", "false")
os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
os.environ.setdefault("HTTPS_ONLY", "false")
os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "t16-enterprise-test-signing-secret-32")


def test_attack_timeline_endpoint_returns_killchain_json():
    import app as app_module

    host_id = "host-t16-timeline"
    app_module.app.config["TESTING"] = True
    app_module._get_xdr_pipeline().process_payload(
        {
            "host_id": host_id,
            "event_type": "process_execution",
            "severity": "high",
            "timestamp": "2026-05-06T12:00:00Z",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "source": "agent",
            "details": {},
        }
    )

    response = app_module.app.test_client().get(f"/api/host/admin/{host_id}/attack-timeline")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["ok"] is True
    assert payload["tenant_id"] == "admin"
    assert "execution" in payload["active_stages"]
    assert payload["progression_score"] > 0
    assert payload["likely_attack_story"]
    assert payload["recommended_next_action"]
    assert payload["timeline"]


def test_dashboard_host_detail_does_not_break_without_data():
    import app as app_module

    app_module.app.config["TESTING"] = True
    response = app_module.app.test_client().get("/soc-preview/hosts/host-without-t16-data")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Kill Chain Timeline" in html
    assert "Protection" in html
