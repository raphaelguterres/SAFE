from __future__ import annotations

from server.config_validator import validate_production_config


def test_config_validator_marks_insecure_production_settings_without_leaking_values():
    env = {
        "IDS_ENV": "production",
        "SECRET_KEY": "short",
        "IDS_AUTH": "false",
        "WTF_CSRF_ENABLED": "false",
        "SESSION_COOKIE_SECURE": "false",
        "SESSION_COOKIE_SAMESITE": "None",
        "NETGUARD_RATE_LIMIT_DISABLED": "true",
        "DATABASE_URL": "sqlite:///local.db",
    }
    status = validate_production_config(env)
    checks = {item["name"]: item for item in status["checks"]}

    assert status["ok"] is False
    assert checks["secret_key"]["severity"] == "critical"
    assert checks["ids_auth"]["severity"] == "critical"
    assert "short" not in str(status)


def test_admin_config_status_endpoint_returns_safe_shape():
    import app as app_mod
    from auth import get_or_create_token

    resp = app_mod.app.test_client().get(
        "/api/admin/config/status",
        headers={"X-API-Token": get_or_create_token()},
    )

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert "checks" in body["config"]
    assert "local-dev-token" not in str(body)
