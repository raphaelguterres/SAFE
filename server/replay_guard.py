"""Bounded nonce replay protection for SAFE agent trust."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class ReplayDecision:
    allowed: bool
    reason: str
    tenant_id: str
    agent_id: str
    nonce: str
    expires_in: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReplayGuard:
    """Small in-process TTL cache keyed by tenant, agent and nonce.

    The cache is intentionally bounded. If it reaches capacity, older entries
    are evicted first so a noisy agent cannot grow process memory without bound.
    """

    def __init__(self, *, ttl_seconds: int = 60, max_nonces: int = 50000):
        self.ttl_seconds = max(1, int(ttl_seconds))
        self.max_nonces = max(100, int(max_nonces))
        self._lock = threading.RLock()
        self._seen: OrderedDict[str, float] = OrderedDict()

    def check_and_store(
        self,
        *,
        tenant_id: str,
        agent_id: str,
        nonce: str,
        now: float | None = None,
    ) -> ReplayDecision:
        tenant = _required(tenant_id, "tenant_id")
        agent = _required(agent_id, "agent_id")
        nonce_text = _required(nonce, "nonce")
        now_value = time.time() if now is None else float(now)
        key = f"{tenant}\0{agent}\0{nonce_text}"

        with self._lock:
            self.cleanup(now=now_value)
            first_seen = self._seen.get(key)
            if first_seen is not None:
                return ReplayDecision(
                    allowed=False,
                    reason="nonce_replay",
                    tenant_id=tenant,
                    agent_id=agent,
                    nonce=nonce_text,
                    expires_in=max(0, int(self.ttl_seconds - (now_value - first_seen))),
                )
            self._seen[key] = now_value
            self._seen.move_to_end(key)
            while len(self._seen) > self.max_nonces:
                self._seen.popitem(last=False)
            return ReplayDecision(
                allowed=True,
                reason="ok",
                tenant_id=tenant,
                agent_id=agent,
                nonce=nonce_text,
                expires_in=self.ttl_seconds,
            )

    def cleanup(self, *, now: float | None = None) -> int:
        now_value = time.time() if now is None else float(now)
        expired = [
            key for key, first_seen in self._seen.items()
            if now_value - first_seen > self.ttl_seconds
        ]
        for key in expired:
            self._seen.pop(key, None)
        return len(expired)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ttl_seconds": self.ttl_seconds,
                "max_nonces": self.max_nonces,
                "active_nonces": len(self._seen),
            }


_DEFAULT_REPLAY_GUARD = ReplayGuard()


def get_default_replay_guard() -> ReplayGuard:
    return _DEFAULT_REPLAY_GUARD


def _required(value: str, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{name}_required")
    return text
