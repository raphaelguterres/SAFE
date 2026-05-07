"""Response Action Signing V2 for server-to-agent trust."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import asdict, dataclass
from typing import Any


MIN_ACTION_SECRET_LENGTH = 32


@dataclass(frozen=True, slots=True)
class SignedActionEnvelope:
    action_id: str
    tenant_id: str
    host_id: str
    action_type: str
    parameters_hash: str
    issued_at: int
    expires_at: int
    policy_mode: str
    approval_id: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parameters_hash(parameters: dict[str, Any] | None) -> str:
    normalized = dict(parameters or {})
    # The signature envelope can travel inside the action payload; it is not
    # part of the signed business parameters.
    normalized.pop("policy_v2", None)
    text = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_action_message(
    *,
    action_id: str,
    tenant_id: str,
    host_id: str,
    action_type: str,
    parameters_hash_value: str,
    issued_at: int | str,
    expires_at: int | str,
    policy_mode: str,
    approval_id: str,
) -> bytes:
    return "\n".join(
        [
            "netguard-response-action-v2",
            str(action_id or "").strip(),
            str(tenant_id or "").strip(),
            str(host_id or "").strip(),
            str(action_type or "").strip().lower(),
            str(parameters_hash_value or "").strip().lower(),
            str(int(issued_at)),
            str(int(expires_at)),
            str(policy_mode or "").strip().lower(),
            str(approval_id or "").strip(),
        ]
    ).encode("utf-8")


def sign_action(
    secret: str,
    *,
    action_id: str,
    tenant_id: str,
    host_id: str,
    action_type: str,
    parameters: dict[str, Any] | None,
    issued_at: int | None = None,
    expires_at: int | None = None,
    policy_mode: str = "manual_approval",
    approval_id: str = "",
) -> SignedActionEnvelope:
    if not secret or len(secret) < MIN_ACTION_SECRET_LENGTH:
        raise ValueError("action_signing_secret_not_configured")
    issued = int(issued_at if issued_at is not None else time.time())
    expires = int(expires_at if expires_at is not None else issued + 300)
    param_hash = parameters_hash(parameters)
    message = canonical_action_message(
        action_id=action_id,
        tenant_id=tenant_id,
        host_id=host_id,
        action_type=action_type,
        parameters_hash_value=param_hash,
        issued_at=issued,
        expires_at=expires,
        policy_mode=policy_mode,
        approval_id=approval_id,
    )
    signature = hmac.new(str(secret).encode("utf-8"), message, hashlib.sha256).hexdigest()
    return SignedActionEnvelope(
        action_id=action_id,
        tenant_id=tenant_id,
        host_id=host_id,
        action_type=str(action_type or "").strip().lower(),
        parameters_hash=param_hash,
        issued_at=issued,
        expires_at=expires,
        policy_mode=str(policy_mode or "").strip().lower(),
        approval_id=str(approval_id or "").strip(),
        signature=signature,
    )


def verify_signed_action(
    secret: str,
    envelope: dict[str, Any],
    *,
    parameters: dict[str, Any] | None,
    expected_tenant_id: str = "",
    expected_host_id: str = "",
    expected_action_type: str = "",
    now: float | None = None,
) -> tuple[bool, str]:
    if not secret or len(secret) < MIN_ACTION_SECRET_LENGTH:
        return False, "action_signing_secret_not_configured"
    item = dict(envelope or {})
    try:
        issued_at = int(item.get("issued_at"))
        expires_at = int(item.get("expires_at"))
    except (TypeError, ValueError):
        return False, "invalid_action_time"
    now_value = int(now if now is not None else time.time())
    if expires_at <= now_value:
        return False, "action_signature_expired"
    if issued_at > now_value + 60:
        return False, "action_issued_in_future"

    tenant_id = str(item.get("tenant_id") or "").strip()
    host_id = str(item.get("host_id") or "").strip()
    action_type = str(item.get("action_type") or "").strip().lower()
    if expected_tenant_id and tenant_id != expected_tenant_id:
        return False, "action_tenant_mismatch"
    if expected_host_id and host_id != expected_host_id:
        return False, "action_host_mismatch"
    if expected_action_type and action_type != expected_action_type:
        return False, "action_type_mismatch"
    if str(item.get("parameters_hash") or "").lower() != parameters_hash(parameters):
        return False, "action_parameters_tampered"

    expected = sign_action(
        secret,
        action_id=str(item.get("action_id") or ""),
        tenant_id=tenant_id,
        host_id=host_id,
        action_type=action_type,
        parameters=parameters,
        issued_at=issued_at,
        expires_at=expires_at,
        policy_mode=str(item.get("policy_mode") or ""),
        approval_id=str(item.get("approval_id") or ""),
    )
    if not hmac.compare_digest(expected.signature, str(item.get("signature") or "").lower()):
        return False, "invalid_action_signature"
    return True, "ok"
