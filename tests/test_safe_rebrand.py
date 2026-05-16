from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_safe_brand_is_present_on_primary_surfaces():
    assert "# SAFE" in _read("README.md")
    assert "Enterprise XDR / EDR Platform" in _read("README.md")
    assert "SAFE Console" in _read("templates/login.html")
    assert "Enterprise Defense Platform" in _read("templates/login.html")
    assert '<span class="brand-mark">S</span>' in _read("templates/landing.html")
    assert '<span class="brand-mark">S</span>' in _read("templates/pricing.html")
    assert '<span class="brand-mark">S</span>' in _read("templates/welcome.html")
    assert "safe-agent ~ stream" in _read("templates/landing.html")
    assert "Instale o SAFE Agent" in _read("templates/welcome.html")
    assert "SAFE" in _read("templates/soc/partials/sidebar.html")
    assert "Security Operations" in _read("templates/soc/partials/sidebar.html")
    assert "Client Security Overview" in _read("templates/client_overview.html")
    assert "Executive View" in _read("templates/client_overview.html")


def test_safe_dashboard_visible_branding_replaces_legacy_copy():
    dashboard = _read("dashboard.html")
    webhook_engine = _read("engine/webhook_engine.py")
    app = _read("app.py")

    for marker in (
        '<div class="logo-name">SAFE</div>',
        "ENTERPRISE DEFENSE PLATFORM",
        "SAFE — INCIDENT REPORT",
        "safe-relatorio-",
        "safe-deteccoes-",
        "safe_onboarded_v1",
        "X-SAFE-Secret",
    ):
        assert marker in dashboard

    assert '<div class="logo-name">NETGUARD</div>' not in dashboard
    assert "NETGUARD IDS — INCIDENT REPORT" not in dashboard
    assert "netguard-relatorio-" not in dashboard
    assert "netguard-deteccoes-" not in dashboard
    assert 'headers["X-SAFE-Secret"]' in webhook_engine
    assert "contact@safe.local" in app


def test_safe_client_overview_is_wired_without_secret_exposure():
    app_src = _read("app.py")
    template = _read("templates/client_overview.html")
    css = _read("static/css/safe.css")

    assert '@app.route("/client/overview")' in app_src
    assert "CLIENT_OVERVIEW_VIEW" in app_src
    assert "client-overview-page" in template
    assert "Executive View" in template
    assert "Technical View" in template
    assert "Security Overview" in template
    assert "SAFE client clean experience" in css
    assert "token" not in template.lower()
    assert "secret" not in template.lower()


def test_safe_dark_enterprise_tokens_exist():
    css = _read("static/css/safe.css")
    for marker in (
        "SAFE rebrand premium dark layer",
        "--safe-bg",
        "--safe-panel",
        "--safe-accent",
        "--safe-critical",
        "--safe-success",
    ):
        assert marker in css


def test_legacy_contract_names_are_documented_not_removed():
    readme = _read("README.md")
    assert "Compatibility note" in readme
    assert "X-NetGuard-Agent-Key" in readme
    assert "NETGUARD_*" in readme


def test_safe_theme_toggle_supports_light_login_and_admin():
    css = _read("static/css/safe.css")
    for marker in (
        "SAFE theme repair",
        'html[data-theme="light"] body.auth-page',
        "body.theme-light.admin-enterprise",
        'html[data-theme="light"] .theme-toggle .icon-sun',
        'html[data-theme="light"] .theme-toggle .icon-moon',
    ):
        assert marker in css


def test_safe_admin_console_has_isolated_theme_shell():
    admin = _read("admin.html")
    css = _read("static/css/safe.css")
    js = _read("static/js/theme-toggle.js")

    for marker in (
        'body class="safe-admin-shell"',
        "Admin Console",
        "safe-admin-top-tools",
        "Dia / Noite",
        "gv-filter-panel",
        "gv-split-shell",
        "gv-tenant-column",
        "gv-feed-column",
    ):
        assert marker in admin

    for marker in (
        "SAFE admin console polish",
        "body.safe-admin-shell #sidebar",
        "body.safe-admin-shell .safe-admin-top-tools",
        "body.safe-admin-shell .gv-tenant-column",
        "body.safe-admin-shell.theme-light #sidebar",
        "@media (max-width: 980px)",
    ):
        assert marker in css

    assert 'var STORAGE_KEY = "safe-theme";' in js
    assert 'if (stored === "light" || stored === "dark") return stored;\n    return "dark";' in js
    assert "prefers-color-scheme" not in js
