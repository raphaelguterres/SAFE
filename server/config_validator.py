"""Production readiness validator for NetGuard deployments."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ConfigCheck:
    name: str
    status: str
    message: str
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProductionConfigValidator:
    def __init__(self, environ: dict[str, str] | None = None):
        self.environ = environ if environ is not None else os.environ

    def validate(self) -> dict[str, Any]:
        checks = [
            self._secret_key(),
            self._auth_enabled(),
            self._csrf_enabled(),
            self._cookie_samesite(),
            self._secure_cookies(),
            self._rate_limit(),
            self._ingest_v2_bounds(),
            self._storage_backend(),
        ]
        critical = sum(1 for item in checks if item.severity == "critical" and item.status != "ok")
        warning = sum(1 for item in checks if item.severity == "warning" and item.status != "ok")
        return {
            "ok": critical == 0,
            "environment": self.environ.get("IDS_ENV") or self.environ.get("NETGUARD_ENV") or "local",
            "summary": {
                "critical": critical,
                "warning": warning,
                "checks": len(checks),
            },
            "checks": [item.to_dict() for item in checks],
        }

    def _secret_key(self) -> ConfigCheck:
        value = self.environ.get("SECRET_KEY") or self.environ.get("NETGUARD_SECRET_KEY") or ""
        if len(value) >= 32 and value.lower() not in {"change_me", "secret", "dev"}:
            return ConfigCheck("secret_key", "ok", "Strong application secret appears configured.")
        return ConfigCheck("secret_key", "critical", "Configure a strong SECRET_KEY/NETGUARD_SECRET_KEY.", "critical")

    def _auth_enabled(self) -> ConfigCheck:
        if _env_bool(self.environ, "IDS_AUTH"):
            return ConfigCheck("ids_auth", "ok", "IDS_AUTH is enabled.")
        return ConfigCheck("ids_auth", "critical", "Set IDS_AUTH=true for production.", "critical")

    def _csrf_enabled(self) -> ConfigCheck:
        if _env_bool(self.environ, "IDS_CSRF_DISABLED"):
            return ConfigCheck("csrf", "critical", "CSRF is disabled.", "critical")
        return ConfigCheck("csrf", "ok", "CSRF protection is enabled.")

    def _cookie_samesite(self) -> ConfigCheck:
        value = (self.environ.get("SESSION_COOKIE_SAMESITE") or "Strict").strip().lower()
        if value in {"strict", "lax"}:
            return ConfigCheck("cookie_samesite", "ok", f"SameSite={value.title()} is acceptable.")
        return ConfigCheck("cookie_samesite", "warning", "Use SameSite=Strict or Lax.", "warning")

    def _secure_cookies(self) -> ConfigCheck:
        https = _env_bool(self.environ, "HTTPS_ONLY") or _env_bool(self.environ, "IDS_HTTPS")
        secure_cookie = _env_bool(self.environ, "SESSION_COOKIE_SECURE")
        if https and not secure_cookie:
            return ConfigCheck("secure_cookies", "warning", "Enable secure cookies when HTTPS is enabled.", "warning")
        return ConfigCheck("secure_cookies", "ok", "Secure cookie posture is acceptable for current transport.")

    def _rate_limit(self) -> ConfigCheck:
        if _env_bool(self.environ, "NETGUARD_RATE_LIMIT_DISABLED"):
            return ConfigCheck("rate_limit", "critical", "Rate limiting is explicitly disabled.", "critical")
        return ConfigCheck("rate_limit", "ok", "Rate limiting is not disabled.")

    def _ingest_v2_bounds(self) -> ConfigCheck:
        if not _env_bool(self.environ, "NETGUARD_XDR_INGEST_V2"):
            return ConfigCheck("ingest_v2", "warning", "Ingest V2 is disabled; sync path is acceptable for local/demo only.", "warning")
        queue_max = _int(self.environ.get("NETGUARD_XDR_QUEUE_MAX"), 0)
        batch = _int(self.environ.get("NETGUARD_XDR_BATCH_SIZE"), 0)
        consumers = _int(self.environ.get("NETGUARD_XDR_CONSUMERS"), 0)
        if queue_max < 100 or batch < 1 or consumers < 1:
            return ConfigCheck("ingest_v2", "critical", "Ingest V2 needs bounded queue, batch size and consumers.", "critical")
        return ConfigCheck("ingest_v2", "ok", "Ingest V2 queue bounds are configured.")

    def _storage_backend(self) -> ConfigCheck:
        backend = (self.environ.get("NETGUARD_STORAGE_BACKEND") or self.environ.get("IDS_STORAGE_BACKEND") or "sqlite").lower()
        if backend in {"postgres", "postgresql"}:
            return ConfigCheck("storage_backend", "ok", "PostgreSQL storage backend is selected.")
        return ConfigCheck("storage_backend", "warning", "SQLite is fine for demo/local; PostgreSQL is recommended for production.", "warning")


def validate_production_config(environ: dict[str, str] | None = None) -> dict[str, Any]:
    return ProductionConfigValidator(environ).validate()


def _env_bool(environ: dict[str, str], name: str) -> bool:
    return str(environ.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
