from __future__ import annotations

from storage.storage_adapter import SQLiteStorageAdapter
from xdr.correlation_engine import IncidentCorrelationV2
from xdr.dedup_engine import EventDeduplicationEngine
from xdr.ingestion_pipeline import TelemetryIngestionPipeline


def _event(tenant_id: str, host_id: str, source_ip: str = "203.0.113.10"):
    return {
        "tenant_id": tenant_id,
        "host_id": host_id,
        "event_id": f"{tenant_id}-{host_id}",
        "event_type": "network_connection",
        "severity": "high",
        "process_name": "powershell.exe",
        "network_dst_ip": source_ip,
        "network_dst_port": 443,
        "mitre_tactic": "command_and_control",
        "timestamp": "2026-05-06T12:00:00Z",
    }


def test_dedup_cache_does_not_suppress_across_tenants():
    engine = EventDeduplicationEngine(ttl_seconds=60)

    first = engine.check(_event("tenant-a", "host-1"), now=1000)
    second = engine.check(_event("tenant-b", "host-1"), now=1001)

    assert first.is_duplicate is False
    assert second.is_duplicate is False


def test_ingestion_queue_rejects_cross_tenant_payload_override():
    pipeline = TelemetryIngestionPipeline(max_queue_size=100)

    result = pipeline.submit(_event("tenant-b", "host-1"), tenant_id="tenant-a")

    assert result.accepted is False
    assert result.reason == "tenant_mismatch"


def test_storage_adapter_never_returns_other_tenant_records(tmp_path):
    adapter = SQLiteStorageAdapter(tmp_path / "xdr_storage.db")
    adapter.write_hot_event("tenant-a", _event("tenant-a", "host-a"))
    adapter.write_hot_event("tenant-b", _event("tenant-b", "host-b"))

    records = adapter.query_hot_events(tenant_id="tenant-a", limit=10)

    assert len(records) == 1
    assert records[0].tenant_id == "tenant-a"
    assert records[0].payload["host_id"] == "host-a"


def test_correlation_v2_groups_multi_host_attack_without_cross_tenant_leak():
    engine = IncidentCorrelationV2(window_seconds=3600)
    events = [
        _event("tenant-a", "host-a1", "203.0.113.50"),
        _event("tenant-a", "host-a2", "203.0.113.50"),
        _event("tenant-b", "host-b1", "203.0.113.50"),
        _event("tenant-b", "host-b2", "203.0.113.50"),
    ]

    tenant_a_campaigns = engine.correlate_events(events, tenant_id="tenant-a")

    assert tenant_a_campaigns
    assert tenant_a_campaigns[0].affected_hosts == ["host-a1", "host-a2"]
    assert "host-b1" not in tenant_a_campaigns[0].affected_hosts
