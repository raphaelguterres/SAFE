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


def _reset_ingest_pipeline(app_mod):
    with app_mod._engine_singletons_lock:
        pipeline = app_mod._xdr_ingestion_pipeline_singleton
        if pipeline is not None:
            pipeline.stop()
        app_mod._xdr_ingestion_pipeline_singleton = None


def test_xdr_ingest_v2_feature_flag_queues_without_replacing_default(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.setenv("NETGUARD_XDR_INGEST_V2", "true")
    monkeypatch.setenv("NETGUARD_XDR_INGEST_V2_DRAIN_INLINE", "true")
    _reset_ingest_pipeline(app_mod)

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
    _reset_ingest_pipeline(app_mod)


def test_xdr_ingest_v2_rejects_cross_tenant_payload(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.setenv("NETGUARD_XDR_INGEST_V2", "true")
    _reset_ingest_pipeline(app_mod)

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
    _reset_ingest_pipeline(app_mod)


def test_admin_ingest_v2_control_blocks_start_when_feature_flag_disabled(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.delenv("NETGUARD_XDR_INGEST_V2", raising=False)
    _reset_ingest_pipeline(app_mod)

    client = app_mod.app.test_client()
    resp = client.post(
        "/api/admin/ingest-v2/control",
        json={"action": "start"},
        headers={"X-API-Token": get_or_create_token()},
    )

    assert resp.status_code == 409
    data = resp.get_json()
    assert data["error"] == "ingest_v2_disabled"
    assert data["config"]["enabled"] is False
    assert data["ingestion"]["running"] is False


def test_admin_ingest_v2_control_drains_queued_events(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.setenv("NETGUARD_XDR_INGEST_V2", "true")
    _reset_ingest_pipeline(app_mod)
    pipeline = app_mod._get_xdr_ingestion_pipeline()
    pipeline.stop()
    result = pipeline.submit_batch(
        [
            _payload(
                host_id="host-v2-admin-drain",
                timestamp="2026-05-07T12:01:00Z",
                command_line="powershell.exe -enc DRAINTEST",
            )["events"][0]
        ],
        tenant_id="admin",
    )
    assert result.accepted == 1

    client = app_mod.app.test_client()
    resp = client.post(
        "/api/admin/ingest-v2/control",
        json={"action": "drain", "max_batches": 5},
        headers={"X-API-Token": get_or_create_token()},
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["action"] == "drain"
    assert data["processed"] >= 1
    assert data["ingestion"]["total_depth"] == 0
    assert data["ingestion"]["last_handler_result"]["processed"] >= 1
    _reset_ingest_pipeline(app_mod)


def test_admin_ingest_v2_control_rejects_invalid_action():
    import app as app_mod
    from auth import get_or_create_token

    client = app_mod.app.test_client()
    resp = client.post(
        "/api/admin/ingest-v2/control",
        json={"action": "delete_everything"},
        headers={"X-API-Token": get_or_create_token()},
    )

    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "invalid_action"
    assert "delete_everything" not in data["allowed"]
