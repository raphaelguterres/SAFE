from __future__ import annotations

import os

os.environ.setdefault("IDS_AUTH", "false")
os.environ.setdefault("IDS_DASHBOARD_AUTH", "false")
os.environ.setdefault("HTTPS_ONLY", "false")
os.environ.setdefault("IDS_ENV", "test")
os.environ.setdefault("TOKEN_SIGNING_SECRET", "defense-core-test-signing-secret-32")


def test_live_response_api_and_page_render_without_data():
    import app as app_module

    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()

    api_response = client.get("/api/soc/live-response")
    page_response = client.get("/soc-preview/live-response")

    assert api_response.status_code == 200
    assert api_response.get_json()["ok"] is True
    assert "response_queue" in api_response.get_json()
    assert page_response.status_code == 200
    assert "Live Response Console" in page_response.get_data(as_text=True)


def test_soc_host_and_killchain_apis_return_defense_core_json():
    import app as app_module

    host_id = "host-defense-core-api"
    app_module.app.config["TESTING"] = True
    app_module._get_xdr_pipeline().process_payload(
        {
            "host_id": host_id,
            "event_type": "script_execution",
            "severity": "high",
            "timestamp": "2026-05-06T13:00:00Z",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "source": "agent",
            "details": {},
        }
    )
    client = app_module.app.test_client()

    killchain_response = client.get(f"/api/soc/killchain/{host_id}")
    host_response = client.get(f"/api/soc/host/{host_id}")
    hunts_response = client.get("/api/soc/threat-hunts")
    incidents_response = client.get("/api/soc/incidents")

    assert killchain_response.status_code == 200
    assert killchain_response.get_json()["progression_score"] > 0
    assert host_response.status_code == 200
    assert "host_defense_state" in host_response.get_json()
    assert hunts_response.status_code == 200
    assert hunts_response.get_json()["ok"] is True
    assert incidents_response.status_code == 200
