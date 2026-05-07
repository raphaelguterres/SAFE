"""Agent Trust Model V2: HMAC, timestamp and nonce validation."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .replay_guard import ReplayGuard, get_default_replay_guard


TRUST_WINDOW_SECONDS = 60
MIN_AGENT_KEY_LENGTH = 16
MIN_NONCE_LENGTH = 12


@dataclass(frozen=True, slots=True)
class AgentTrustResult:
    valid: bool
    reason: str
    tenant_id: str = ""
    agent_id: str = ""
    host_id: str = ""
    timestamp: int = 0
    nonce: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def extract_agent_key_from_headers(headers: Any) -> str:
    explicit = (
        str(headers.get("X-NetGuard-Agent-Key", "") or "").strip()
        or str(headers.get("X-API-Key", "") or "").strip()
        or str(headers.get("X-Agent-Key", "") or "").strip()
    )
    if explicit:
        return explicit
    auth_header = str(headers.get("Authorization", "") or "").strip()
    if auth_header.lower().startswith("agent "):
        return auth_header[6:].strip()
    return ""


def body_sha256(body: bytes | str | None) -> str:
    if body is None:
        body_bytes = b""
    elif isinstance(body, bytes):
        body_bytes = body
    else:
        body_bytes = str(body).encode("utf-8")
    return hashlib.sha256(body_bytes).hexdigest()


def canonical_agent_message(
    *,
    method: str,
    path: str,
    tenant_id: str,
    agent_id: str,
    host_id: str,
    timestamp: int | str,
    nonce: str,
    body_hash: str,
) -> bytes:
    return "\n".join(
        [
            "netguard-agent-trust-v2",
            str(method or "POST").upper(),
            str(path or "/"),
            str(tenant_id or "").strip(),
            str(agent_id or "").strip(),
            str(host_id or "").strip(),
            str(int(timestamp)),
            str(nonce or "").strip(),
            str(body_hash or "").strip().lower(),
        ]
    ).encode("utf-8")


def sign_agent_request(
    agent_key: str,
    *,
    method: str,
    path: str,
    tenant_id: str,
    agent_id: str,
    host_id: str,
    timestamp: int | str,
    nonce: str,
    body: bytes | str | None = b"",
) -> str:
    if not agent_key or len(str(agent_key)) < MIN_AGENT_KEY_LENGTH:
        raise ValueError("agent_key_too_short")
    message = canonical_agent_message(
        method=method,
        path=path,
        tenant_id=tenant_id,
        agent_id=agent_id,
        host_id=host_id,
        timestamp=timestamp,
        nonce=nonce,
        body_hash=body_sha256(body),
    )
    return hmac.new(str(agent_key).encode("utf-8"), message, hashlib.sha256).hexdigest()


class AgentTrustValidator:
    """Validates signed endpoint agent requests.

    The raw host API key is used as the request-signing secret. This preserves
    the current enrollment model while adding timestamp and nonce protection.
    """

    def __init__(
        self,
        *,
        replay_guard: ReplayGuard | None = None,
        max_skew_seconds: int = TRUST_WINDOW_SECONDS,
    ):
        self.replay_guard = replay_guard or get_default_replay_guard()
        self.max_skew_seconds = max(1, min(int(max_skew_seconds), TRUST_WINDOW_SECONDS))

    def validate(
        self,
        *,
        method: str,
        path: str,
        headers: Any,
        body: bytes | str | None,
        agent_key: str,
        expected_tenant_id: str,
        expected_host_id: str,
        host_lookup: Callable[[str, str], dict[str, Any] | None],
        now: float | None = None,
    ) -> AgentTrustResult:
        now_value = time.time() if now is None else float(now)
        tenant_id = _header(headers, "X-NetGuard-Tenant-ID")
        agent_id = _header(headers, "X-NetGuard-Agent-ID")
        host_id = _header(headers, "X-NetGuard-Host-ID")
        timestamp_raw = _header(headers, "X-NetGuard-Timestamp")
        nonce = _header(headers, "X-NetGuard-Nonce")
        signature = _signature(_header(headers, "X-NetGuard-Signature"))

        if not agent_key or len(agent_key) < MIN_AGENT_KEY_LENGTH:
            return AgentTrustResult(False, "agent_key_required")
        for field, value in {
            "tenant_id": tenant_id,
            "agent_id": agent_id,
            "host_id": host_id,
            "timestamp": timestamp_raw,
            "nonce": nonce,
            "signature": signature,
        }.items():
            if not value:
                return AgentTrustResult(False, f"{field}_required")
        if tenant_id != str(expected_tenant_id or ""):
            return AgentTrustResult(False, "tenant_scope_mismatch", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id)
        if host_id != str(expected_host_id or ""):
            return AgentTrustResult(False, "host_scope_mismatch", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id)
        if len(nonce) < MIN_NONCE_LENGTH:
            return AgentTrustResult(False, "nonce_too_short", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id)

        try:
            timestamp = int(timestamp_raw)
        except (TypeError, ValueError):
            return AgentTrustResult(False, "timestamp_invalid", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id)
        if abs(now_value - timestamp) > self.max_skew_seconds:
            return AgentTrustResult(False, "timestamp_out_of_window", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id, timestamp=timestamp, nonce=nonce)

        host = host_lookup(tenant_id, host_id)
        if not host:
            return AgentTrustResult(False, "host_not_registered", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id, timestamp=timestamp, nonce=nonce)
        if str(host.get("status") or "").lower() == "revoked":
            return AgentTrustResult(False, "agent_revoked", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id, timestamp=timestamp, nonce=nonce)

        expected_signature = sign_agent_request(
            agent_key,
            method=method,
            path=path,
            tenant_id=tenant_id,
            agent_id=agent_id,
            host_id=host_id,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        if not hmac.compare_digest(expected_signature, signature):
            return AgentTrustResult(False, "invalid_signature", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id, timestamp=timestamp, nonce=nonce)

        try:
            replay = self.replay_guard.check_and_store(
                tenant_id=tenant_id,
                agent_id=agent_id,
                nonce=nonce,
                now=now_value,
            )
        except ValueError as exc:
            return AgentTrustResult(False, str(exc), tenant_id=tenant_id, agent_id=agent_id, host_id=host_id, timestamp=timestamp, nonce=nonce)
        if not replay.allowed:
            return AgentTrustResult(False, replay.reason, tenant_id=tenant_id, agent_id=agent_id, host_id=host_id, timestamp=timestamp, nonce=nonce)

        return AgentTrustResult(True, "ok", tenant_id=tenant_id, agent_id=agent_id, host_id=host_id, timestamp=timestamp, nonce=nonce)


def _header(headers: Any, name: str) -> str:
    return str(headers.get(name, "") or "").strip()


def _signature(value: str) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("sha256="):
        return text[7:]
    return text
