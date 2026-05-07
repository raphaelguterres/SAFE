from __future__ import annotations


def test_admin_performance_dashboard_loads_without_telemetry():
    import app as app_mod

    client = app_mod.app.test_client()
    resp = client.get("/admin/performance", headers={"Accept": "text/html"})

    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "Performance Core" in body
    assert ".env" not in body
    assert "nga_" not in body


def test_admin_performance_api_returns_safe_metrics_payload():
    import app as app_mod

    client = app_mod.app.test_client()
    resp = client.get("/api/admin/performance")

    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["ok"] is True
    assert "metrics" in payload
    assert "ingestion" in payload
    assert "queue_depths" in payload["ingestion"]
