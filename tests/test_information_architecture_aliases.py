from __future__ import annotations

import importlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _client():
    app_mod = importlib.import_module("app")
    return app_mod.app.test_client()


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_app_overview_is_primary_and_client_routes_are_legacy_redirects():
    client = _client()

    overview = client.get("/app/overview", headers={"Accept": "text/html"})
    assert overview.status_code in {200, 302}
    if overview.status_code == 302:
        assert "/login" in overview.headers["Location"]
    else:
        assert b"SAFE" in overview.data

    assert client.get("/client/overview").status_code == 301
    assert client.get("/client/overview").headers["Location"].endswith("/app/overview")
    assert client.get("/client").headers["Location"].endswith("/app/overview")
    assert client.get("/client/dashboard").headers["Location"].endswith("/app/dashboard")


def test_soc_and_platform_aliases_redirect_without_removing_legacy_routes():
    client = _client()

    aliases = {
        "/soc/inbox": "/admin/inbox",
        "/soc/host/default/host-1": "/admin/host/default/host-1",
        "/platform/tenants": "/admin",
        "/platform/tenants/default": "/admin/view/default",
        "/platform/observability": "/admin/observability",
        "/platform/performance": "/admin/performance",
        "/platform/performance-live": "/admin/performance-live",
    }
    for source, target in aliases.items():
        response = client.get(source)
        assert response.status_code == 301, source
        assert response.headers["Location"].endswith(target), source


def test_platform_home_renders_profile_topbar():
    response = _client().get("/platform", headers={"Accept": "text/html"})

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Platform Operations" in body
    assert "Storage Backend" in body
    assert "Queue Backend" in body
    assert "Migration Status" in body
    assert "Health Summary" in body
    assert "/platform/observability" in body
    assert "/api/admin/audit/integrity" in body
    assert "/api/admin/config/status" in body


def test_app_product_routes_render_or_require_login():
    client = _client()

    for path in ("/app/assets", "/app/incidents", "/app/dashboard", "/app/reports"):
        response = client.get(path, headers={"Accept": "text/html"})
        assert response.status_code in {200, 302}, path
        if response.status_code == 302:
            assert "/login" in response.headers["Location"], path
        else:
            body = response.get_data(as_text=True)
            assert "safe-app-topbar" in body, path
            assert "/admin" not in body, path


def test_visible_navigation_uses_new_information_architecture_links():
    combined = "\n".join(
        _read(path)
        for path in (
            "templates/client_overview.html",
            "templates/partials/app_topbar.html",
            "templates/executive.html",
            "templates/operator_inbox.html",
            "templates/soc/partials/sidebar.html",
            "templates/soc/incidents.html",
            "templates/soc/overview.html",
        )
    )

    for marker in ("/app/overview", "/app/dashboard", "/soc/inbox", "/soc/host/", "/platform"):
        assert marker in combined


def test_client_profile_navigation_does_not_link_to_admin():
    combined = "\n".join(
        _read(path)
        for path in (
            "templates/client_overview.html",
            "templates/app_assets.html",
            "templates/app_dashboard.html",
            "templates/app_incidents.html",
            "templates/app_reports.html",
            "templates/partials/app_topbar.html",
        )
    )

    assert "/admin" not in combined
    for marker in ("/app/overview", "/app/dashboard", "/app/assets", "/app/incidents"):
        assert marker in combined


def test_profile_topbar_partials_exist():
    app_topbar = _read("templates/partials/app_topbar.html")
    platform_topbar = _read("templates/partials/platform_topbar.html")

    assert "safe-app-topbar" in app_topbar
    assert "Platform Operations" in platform_topbar


def test_app_templates_use_app_topbar_and_platform_uses_platform_topbar():
    for path in (
        "templates/app_assets.html",
        "templates/app_dashboard.html",
        "templates/app_incidents.html",
        "templates/app_reports.html",
    ):
        assert 'include "partials/app_topbar.html"' in _read(path)
    assert 'include "partials/platform_topbar.html"' in _read("templates/platform_home.html")
