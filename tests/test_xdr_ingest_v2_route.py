from __future__ import annotations


def _payload(**overrides):
    event = {
        "host_id": "host-v2-01",
        "event_type": "process_execution",
        "severity": "medium",
        "timestamp": "2026-05-07T12:00:00Z",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
        "parent_process": "cmd.exe",
        "source": "agent",
        "platform": "windows",
        "details": {},
    }
    event.update(overrides)
    return {"events": [event]}


def test_xdr_ingest_v2_feature_flag_queues_without_replacing_default(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.setenv("NETGUARD_XDR_INGEST_V2", "true")
    monkeypatch.setenv("NETGUARD_XDR_INGEST_V2_DRAIN_INLINE", "true")
    with app_mod._engine_singletons_lock:
        app_mod._xdr_ingestion_pipeline_singleton = None

    client = app_mod.app.test_client()
    resp = client.post(
        "/api/xdr/events",
        json=_payload(host_id="host-v2-feature-flag"),
        headers={"X-API-Token": get_or_create_token()},
    )

    assert resp.status_code == 202
    data = resp.get_json()
    assert data["ok"] is True
    assert data["mode"] == "ingest_v2"
    assert data["queued"] == 1
    assert data["processed_inline"] >= 1
    assert data["queue_depth"] == 0
    assert app_mod._get_xdr_ingestion_pipeline().snapshot()["last_handler_result"]["processed"] >= 1


def test_xdr_ingest_v2_rejects_cross_tenant_payload(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.setenv("NETGUARD_XDR_INGEST_V2", "true")
    with app_mod._engine_singletons_lock:
        app_mod._xdr_ingestion_pipeline_singleton = None

    client = app_mod.app.test_client()
    resp = client.post(
        "/api/xdr/events",
        json=_payload(tenant_id="tenant-forged"),
        headers={"X-API-Token": get_or_create_token()},
    )

    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "invalid_event"
    assert data["detail"] == "tenant_mismatch"
