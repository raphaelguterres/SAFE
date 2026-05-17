from __future__ import annotations

import importlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _client():
    app_mod = importlib.import_module("app")
    return app_mod.app.test_client()


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_client_app_aliases_redirect_to_existing_routes():
    client = _client()

    assert client.get("/app").status_code == 301
    assert client.get("/app").headers["Location"].endswith("/client/overview")
    assert client.get("/app/overview").headers["Location"].endswith("/client/overview")
    assert client.get("/app/dashboard").headers["Location"].endswith("/client/dashboard")


def test_soc_and_platform_aliases_redirect_without_removing_legacy_routes():
    client = _client()

    aliases = {
        "/soc/inbox": "/admin/inbox",
        "/soc/host/default/host-1": "/admin/host/default/host-1",
        "/platform": "/admin",
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


def test_visible_navigation_uses_new_information_architecture_links():
    combined = "\n".join(
        _read(path)
        for path in (
            "templates/client_overview.html",
            "templates/executive.html",
            "templates/operator_inbox.html",
            "templates/soc/partials/sidebar.html",
            "templates/soc/incidents.html",
            "templates/soc/overview.html",
        )
    )

    for marker in ("/app/overview", "/app/dashboard", "/soc/inbox", "/soc/host/", "/platform"):
        assert marker in combined
