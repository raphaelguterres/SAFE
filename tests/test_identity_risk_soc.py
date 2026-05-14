from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_identity_risk_routes_are_registered_and_protected():
    app_src = _read("app.py")
    for marker in (
        '@app.route("/soc/identities", methods=["GET"])',
        '@app.route("/api/soc/identities", methods=["GET"])',
        "SOC_IDENTITIES_VIEW",
        "SOC_IDENTITIES_API_VIEW",
    ):
        assert marker in app_src
    route_index = app_src.index('@app.route("/soc/identities", methods=["GET"])')
    page_window = app_src[route_index: route_index + 240]
    assert "@require_session" in page_window
    assert '@require_role("analyst", "admin")' in page_window
    api_index = app_src.index('@app.route("/api/soc/identities", methods=["GET"])')
    api_window = app_src[api_index: api_index + 260]
    assert "@auth" in api_window
    assert "@csrf_protect" in api_window
    assert '@require_role("analyst", "admin")' in api_window


def test_identity_risk_template_renders_without_secrets():
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")))
    env.globals["url_for"] = lambda endpoint, **values: f"/static/{values.get('filename', '')}"
    html = env.get_template("soc/identities.html").render()
    assert "SAFE" in html
    assert "Identity Risk" in html
    assert "host_key" not in html.lower()
    assert "api_key" not in html.lower()
    assert "secret" not in html.lower()


def test_identity_risk_sidebar_link_exists():
    sidebar = _read("templates/soc/partials/sidebar.html")
    assert "/soc/identities" in sidebar
    assert "Identity Risk" in sidebar
