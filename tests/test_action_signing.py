from __future__ import annotations

import time

from xdr.action_signing import sign_action, verify_signed_action


def test_signed_action_detects_parameter_tamper_and_scope_mismatch():
    secret = "s" * 40
    parameters = {"target_ip": "10.0.0.5", "policy": {"approval": "yes"}}
    envelope = sign_action(
        secret,
        action_id="act-1",
        tenant_id="tenant-a",
        host_id="host-1",
        action_type="block_ip",
        parameters=parameters,
    ).to_dict()

    assert verify_signed_action(
        secret,
        envelope,
        parameters={**parameters, "policy_v2": envelope},
        expected_tenant_id="tenant-a",
        expected_host_id="host-1",
        expected_action_type="block_ip",
    ) == (True, "ok")
    assert verify_signed_action(secret, envelope, parameters={"target_ip": "10.0.0.6"})[1] == "action_parameters_tampered"
    assert verify_signed_action(secret, envelope, parameters=parameters, expected_host_id="host-2")[1] == "action_host_mismatch"


def test_signed_action_refuses_expired_or_future_issued_envelopes():
    secret = "s" * 40
    expired = sign_action(
        secret,
        action_id="act-old",
        tenant_id="tenant-a",
        host_id="host-1",
        action_type="isolate_host",
        parameters={},
        issued_at=int(time.time()) - 600,
        expires_at=int(time.time()) - 1,
    ).to_dict()
    future = sign_action(
        secret,
        action_id="act-future",
        tenant_id="tenant-a",
        host_id="host-1",
        action_type="isolate_host",
        parameters={},
        issued_at=int(time.time()) + 120,
        expires_at=int(time.time()) + 300,
    ).to_dict()

    assert verify_signed_action(secret, expired, parameters={})[1] == "action_signature_expired"
    assert verify_signed_action(secret, future, parameters={})[1] == "action_issued_in_future"
