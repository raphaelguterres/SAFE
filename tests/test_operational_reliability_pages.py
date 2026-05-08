from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_operational_admin_routes_are_registered_and_admin_guarded():
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")

    assert '@app.route("/admin/observability")' in app_py
    assert '@app.route("/admin/performance-live")' in app_py
    assert '@app.route("/api/admin/observability")' in app_py
    assert '@app.route("/api/admin/performance-live")' in app_py
    for route in ("/admin/observability", "/admin/performance-live", "/api/admin/observability", "/api/admin/performance-live"):
        route_index = app_py.index(route)
        decorator_window = app_py[max(0, route_index - 120):route_index + 180]
        assert "@_admin_only" in decorator_window


def test_operational_templates_exist_and_do_not_render_secret_words():
    for template_name in ("observability.html", "performance_live.html"):
        content = (ROOT / "templates" / template_name).read_text(encoding="utf-8").lower()
        assert "/api/admin/" in content
        assert "token" not in content
        assert "api_key" not in content
        assert "host_key" not in content
