from __future__ import annotations

from server.api_guard import ApiAbuseGuard


def test_api_guard_enforces_batch_size_event_type_and_rate_limit():
    guard = ApiAbuseGuard(max_batch_events=1, rate_limit_per_minute=2)
    allowed_event = {"event_type": "process_execution", "host_id": "h"}

    assert guard.inspect(endpoint="/api/xdr/events", tenant_id="t", agent_id="a", payload={"events": [allowed_event]}).allowed
    assert not guard.inspect(
        endpoint="/api/xdr/events",
        tenant_id="t",
        agent_id="a",
        payload={"events": [allowed_event, allowed_event]},
    ).allowed
    invalid = guard.inspect(
        endpoint="/api/xdr/events",
        tenant_id="t",
        agent_id="b",
        payload={"events": [{"event_type": "raw_kernel_dump"}]},
    )
    assert invalid.reason == "event_type_not_allowed"

    assert guard.inspect(endpoint="/api/xdr/events", tenant_id="rate", agent_id="a", payload={}).allowed
    assert guard.inspect(endpoint="/api/xdr/events", tenant_id="rate", agent_id="a", payload={}).allowed
    assert guard.inspect(endpoint="/api/xdr/events", tenant_id="rate", agent_id="a", payload={}).reason == "rate_limited"


def test_api_guard_scopes_rate_limit_per_tenant():
    guard = ApiAbuseGuard(rate_limit_per_minute=1)

    assert guard.inspect(endpoint="/api/agent/events", tenant_id="tenant-a", agent_id="a", payload={}).allowed
    assert guard.inspect(endpoint="/api/agent/events", tenant_id="tenant-b", agent_id="a", payload={}).allowed
    assert guard.inspect(endpoint="/api/agent/events", tenant_id="tenant-a", agent_id="a", payload={}).reason == "rate_limited"
