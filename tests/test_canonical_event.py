from schema.canonical_event import CanonicalEvent, NetworkContext, ProcessContext, canonical_hash


def test_canonical_event_redacts_hash_inputs_and_serializes():
    event = CanonicalEvent(
        event_id="ce_test",
        tenant_id="tenant-a",
        host_id="host-1",
        user_id="alice",
        event_type="process_execution",
        category="process",
        timestamp="2026-05-11T00:00:00Z",
        telemetry_source="agent",
        severity="high",
        process=ProcessContext(name="powershell.exe", command_line="powershell -enc test"),
        network=NetworkContext(dst_ip="10.0.0.5", dst_port=443),
        raw_event_ref="raw:abc",
        confidence=0.91,
    )

    payload = event.to_dict()

    assert payload["process"]["name"] == "powershell.exe"
    assert payload["network"]["dst_ip"] == "10.0.0.5"
    assert payload["confidence"] == 0.91
    assert canonical_hash({"api_key": "secret"}) == canonical_hash({"api_key": "other"})
