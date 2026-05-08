from pathlib import Path

from jinja2 import Environment, FileSystemLoader


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_soc_operations_routes_are_registered_and_rbac_protected():
    app_src = _read("app.py")

    for marker in (
        '@app.route("/soc/case/<case_id>", methods=["GET"])',
        '@app.route("/soc/hunts", methods=["GET"])',
        '@app.route("/soc/approvals", methods=["GET"])',
        '@app.route("/soc/metrics", methods=["GET"])',
        "SOC_CASE_VIEW",
        "SOC_HUNTS_VIEW",
        "SOC_APPROVALS_VIEW",
        "SOC_METRICS_VIEW",
    ):
        assert marker in app_src
    assert app_src.count('@require_role("analyst", "admin")') >= 4


def test_soc_operations_templates_render_without_data_and_no_secret_exposure():
    env = Environment(loader=FileSystemLoader(str(ROOT / "templates")))
    env.globals["url_for"] = lambda endpoint, **values: f"/static/{values.get('filename', '')}"
    for template_name in ("soc/case_detail.html", "soc/hunts.html", "soc/approvals.html", "soc/metrics.html"):
        html = env.get_template(template_name).render()
        assert "SAFE" in html
        assert "token_signing_secret" not in html.lower()
        assert "host_key" not in html.lower()


def test_sidebar_links_soc_operations_pages():
    sidebar = _read("templates/soc/partials/sidebar.html")
    for href in ("/soc/hunts", "/soc/approvals", "/soc/metrics"):
        assert href in sidebar
