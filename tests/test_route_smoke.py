import importlib


def test_primary_pages_do_not_render_stack_traces():
    app_mod = importlib.import_module("app")
    client = app_mod.app.test_client()
    for path in ["/login", "/pricing", "/soc-preview", "/executive", "/soc/search", "/soc/detection-packs", "/soc/identities"]:
        response = client.get(path, headers={"Accept": "text/html"})
        assert response.status_code < 500, path
        assert "Traceback (most recent call last)" not in response.get_data(as_text=True)


def test_admin_pages_are_available_or_protected_not_openly_broken():
    app_mod = importlib.import_module("app")
    client = app_mod.app.test_client()
    for path in ["/admin", "/admin/performance", "/admin/observability", "/admin/performance-live"]:
        response = client.get(path, headers={"Accept": "text/html"})
        assert response.status_code in {200, 302, 401, 403}, path


def test_core_health_api_returns_json():
    app_mod = importlib.import_module("app")
    response = app_mod.app.test_client().get("/api/health")
    assert response.status_code == 200
    assert response.is_json
    body = response.get_json()
    assert body.get("ok") is True or body.get("status") in {"ok", "healthy"}
