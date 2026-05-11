from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_security_data_platform_routes_are_registered_and_protected():
    app_py = (ROOT / "app.py").read_text(encoding="utf-8")

    for route in ("/soc/detection-packs", "/soc/search", "/api/soc/security-data"):
        assert route in app_py
        route_index = app_py.index(route)
        decorator_window = app_py[max(0, route_index - 180): route_index + 220]
        assert "require_session" in decorator_window or "@auth" in decorator_window
        assert "require_role" in decorator_window


def test_security_data_templates_exist_without_sensitive_terms():
    for template_name in ("detection_packs.html", "search.html"):
        content = (ROOT / "templates" / "soc" / template_name).read_text(encoding="utf-8").lower()
        assert "safe" in content
        assert "api_key" not in content
        assert "host_key" not in content
        assert "secret" not in content
