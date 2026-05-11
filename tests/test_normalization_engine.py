from xdr.normalization_engine import TelemetryNormalizationEngine


def test_normalization_engine_maps_process_event_consistently():
    result = TelemetryNormalizationEngine().normalize(
        {
            "tenant_id": "tenant-a",
            "host_id": "host-1",
            "event_type": "process_execution",
            "timestamp": "2026-05-11T12:00:00-03:00",
            "process_name": "powershell.exe",
            "pid": "123",
            "network_dst_ip": "8.8.8.8",
            "network_dst_port": "443",
            "username": "alice",
            "severity": "high",
        }
    )

    event = result.canonical_event
    assert event is not None
    assert event.category == "process"
    assert event.process.pid == 123
    assert event.network.dst_port == 443
    assert event.timestamp.endswith("Z")


def test_normalization_engine_handles_malformed_events_fail_closed():
    result = TelemetryNormalizationEngine().normalize("not-a-dict")

    assert result.canonical_event is None
    assert result.malformed is True
    assert result.issues[0].reason == "empty_or_unsupported"


def test_normalization_engine_records_missing_timestamp_issue():
    result = TelemetryNormalizationEngine().normalize({"tenant_id": "t1", "host_id": "h1", "event_type": "authentication"})

    assert result.canonical_event is not None
    assert any(issue.field == "timestamp" for issue in result.issues)
