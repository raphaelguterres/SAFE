from __future__ import annotations

import json
import time

from server.agent_trust import AgentTrustValidator, sign_agent_request
from server.replay_guard import ReplayGuard


def _headers(*, key: str, tenant_id: str, agent_id: str, host_id: str, body: bytes, nonce: str = "nonce-123456"):
    ts = int(time.time())
    signature = sign_agent_request(
        key,
        method="POST",
        path="/api/agent/heartbeat",
        tenant_id=tenant_id,
        agent_id=agent_id,
        host_id=host_id,
        timestamp=ts,
        nonce=nonce,
        body=body,
    )
    return {
        "X-NetGuard-Agent-ID": agent_id,
        "X-NetGuard-Tenant-ID": tenant_id,
        "X-NetGuard-Host-ID": host_id,
        "X-NetGuard-Timestamp": str(ts),
        "X-NetGuard-Nonce": nonce,
        "X-NetGuard-Signature": signature,
    }


def test_agent_trust_accepts_signed_request_and_blocks_replay():
    key = "k" * 32
    body = b'{"host_id":"host-1"}'
    validator = AgentTrustValidator(replay_guard=ReplayGuard(ttl_seconds=60, max_nonces=100))
    headers = _headers(key=key, tenant_id="tenant-a", agent_id="agent-1", host_id="host-1", body=body)
    lookup = lambda tenant, host: {"tenant_id": tenant, "host_id": host, "status": "active"}

    first = validator.validate(
        method="POST",
        path="/api/agent/heartbeat",
        headers=headers,
        body=body,
        agent_key=key,
        expected_tenant_id="tenant-a",
        expected_host_id="host-1",
        host_lookup=lookup,
    )
    replay = validator.validate(
        method="POST",
        path="/api/agent/heartbeat",
        headers=headers,
        body=body,
        agent_key=key,
        expected_tenant_id="tenant-a",
        expected_host_id="host-1",
        host_lookup=lookup,
    )

    assert first.valid is True
    assert replay.valid is False
    assert replay.reason == "nonce_replay"


def test_agent_trust_blocks_old_timestamp_invalid_signature_and_wrong_tenant():
    key = "k" * 32
    body = b"{}"
    validator = AgentTrustValidator(replay_guard=ReplayGuard(ttl_seconds=60, max_nonces=100))
    lookup = lambda tenant, host: {"tenant_id": tenant, "host_id": host, "status": "active"}
    headers = _headers(key=key, tenant_id="tenant-a", agent_id="agent-1", host_id="host-1", body=body)

    old = dict(headers)
    old["X-NetGuard-Timestamp"] = str(int(time.time()) - 120)
    bad_sig = dict(headers)
    bad_sig["X-NetGuard-Nonce"] = "nonce-abcdef"
    bad_sig["X-NetGuard-Signature"] = "00" * 32

    assert not validator.validate(
        method="POST",
        path="/api/agent/heartbeat",
        headers=old,
        body=body,
        agent_key=key,
        expected_tenant_id="tenant-a",
        expected_host_id="host-1",
        host_lookup=lookup,
    ).valid
    assert validator.validate(
        method="POST",
        path="/api/agent/heartbeat",
        headers=bad_sig,
        body=body,
        agent_key=key,
        expected_tenant_id="tenant-a",
        expected_host_id="host-1",
        host_lookup=lookup,
    ).reason == "invalid_signature"
    assert validator.validate(
        method="POST",
        path="/api/agent/heartbeat",
        headers=headers,
        body=body,
        agent_key=key,
        expected_tenant_id="tenant-b",
        expected_host_id="host-1",
        host_lookup=lookup,
    ).reason == "tenant_scope_mismatch"


def test_agent_trust_v2_route_rejects_unsigned_agent_request(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.setenv("NETGUARD_AGENT_TRUST_V2", "true")
    client = app_mod.app.test_client()
    host_id = f"trust-host-{int(time.time())}"
    registered = client.post(
        "/api/agent/register",
        json={"host_id": host_id, "platform": "windows", "tenant_id": "admin"},
        headers={"X-API-Token": get_or_create_token()},
    )
    agent_key = registered.get_json()["api_key"]

    rejected = client.post(
        "/api/agent/heartbeat",
        json={"host_id": host_id, "platform": "windows"},
        headers={"X-NetGuard-Agent-Key": agent_key},
    )
    assert rejected.status_code == 401
    assert rejected.get_json()["error"] == "agent_trust_denied"


def test_agent_trust_v2_route_accepts_signed_agent_request(monkeypatch):
    import app as app_mod
    from auth import get_or_create_token

    monkeypatch.setenv("NETGUARD_AGENT_TRUST_V2", "true")
    client = app_mod.app.test_client()
    host_id = f"trust-host-signed-{int(time.time())}"
    registered = client.post(
        "/api/agent/register",
        json={"host_id": host_id, "platform": "windows", "tenant_id": "admin"},
        headers={"X-API-Token": get_or_create_token()},
    )
    agent_key = registered.get_json()["api_key"]
    payload = {"host_id": host_id, "platform": "windows"}
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {
        "X-NetGuard-Agent-Key": agent_key,
        **_headers(
            key=agent_key,
            tenant_id="admin",
            agent_id=host_id,
            host_id=host_id,
            body=body,
            nonce=f"nonce-{host_id}",
        ),
    }

    accepted = client.post(
        "/api/agent/heartbeat",
        data=body,
        content_type="application/json",
        headers=headers,
    )
    assert accepted.status_code == 200
    assert accepted.get_json()["ok"] is True
