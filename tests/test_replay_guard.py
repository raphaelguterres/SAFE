from __future__ import annotations

import pytest

from server.replay_guard import ReplayGuard


def test_replay_guard_blocks_nonce_reuse_per_tenant_and_agent():
    guard = ReplayGuard(ttl_seconds=60, max_nonces=100)

    first = guard.check_and_store(
        tenant_id="tenant-a",
        agent_id="agent-1",
        nonce="nonce-123",
        now=1000.0,
    )
    replay = guard.check_and_store(
        tenant_id="tenant-a",
        agent_id="agent-1",
        nonce="nonce-123",
        now=1001.0,
    )
    other_tenant = guard.check_and_store(
        tenant_id="tenant-b",
        agent_id="agent-1",
        nonce="nonce-123",
        now=1001.0,
    )

    assert first.allowed is True
    assert replay.allowed is False
    assert replay.reason == "nonce_replay"
    assert other_tenant.allowed is True


def test_replay_guard_expires_and_requires_scope():
    guard = ReplayGuard(ttl_seconds=2, max_nonces=100)
    assert guard.check_and_store(tenant_id="t", agent_id="a", nonce="n", now=10).allowed
    assert guard.cleanup(now=13) == 1
    assert guard.check_and_store(tenant_id="t", agent_id="a", nonce="n", now=13).allowed

    with pytest.raises(ValueError, match="tenant_id_required"):
        guard.check_and_store(tenant_id="", agent_id="a", nonce="n2")
