"""Queue backend selection for SAFE operational reliability."""

from __future__ import annotations

import logging
import os
from typing import Any

from xdr.queue_backends import build_memory_queue_backend

logger = logging.getLogger("safe.queue_config")


def build_operational_queue_manager(
    *,
    max_size: int = 10_000,
    dead_letter_size: int = 1_000,
    per_tenant_limit: int = 2_500,
    redis_client: Any | None = None,
):
    backend = os.environ.get("SAFE_QUEUE_BACKEND", "memory").strip().lower() or "memory"
    redis_required = _env_bool("SAFE_REDIS_REQUIRED", default=False)
    if backend != "redis":
        queue = build_memory_queue_backend(
            max_size=max_size,
            dead_letter_size=dead_letter_size,
            per_tenant_limit=per_tenant_limit,
        )
        queue.backend = "memory"  # harmless runtime hint for dashboards/tests
        return queue

    try:
        from xdr.redis_queue_backend import RedisQueueBackend, build_redis_client

        client = redis_client or build_redis_client(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
        if redis_client is not None and hasattr(client, "ping"):
            client.ping()
        return RedisQueueBackend(
            client=client,
            max_size=max_size,
            dead_letter_size=dead_letter_size,
        )
    except Exception as exc:
        if redis_required:
            raise RuntimeError(f"SAFE_QUEUE_BACKEND=redis unavailable: {exc}") from exc
        logger.warning("Redis queue backend unavailable; falling back to memory: %s", exc)
        queue = build_memory_queue_backend(
            max_size=max_size,
            dead_letter_size=dead_letter_size,
            per_tenant_limit=per_tenant_limit,
        )
        queue.backend = "memory-fallback"
        return queue


def queue_config_status() -> dict[str, Any]:
    backend = os.environ.get("SAFE_QUEUE_BACKEND", "memory").strip().lower() or "memory"
    return {
        "backend": backend if backend in {"memory", "redis"} else "memory",
        "redis_configured": backend == "redis",
        "redis_required": _env_bool("SAFE_REDIS_REQUIRED", default=False),
        "redis_url_set": bool(os.environ.get("REDIS_URL")),
    }


def _env_bool(name: str, *, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}
