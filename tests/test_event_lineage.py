from xdr.event_lineage import EventLineageEngine
from xdr.normalization_engine import TelemetryNormalizationEngine


def test_event_lineage_tracks_steps_by_tenant():
    event = TelemetryNormalizationEngine().normalize({"tenant_id": "tenant-a", "host_id": "host-1", "event_type": "process_execution"}).canonical_event
    engine = EventLineageEngine()

    engine.start(event)
    engine.add_enrichment(event, "asset_context")
    engine.add_detection(event, {"rule_id": "R1", "api_key": "secret"})

    trace = engine.trace(tenant_id="tenant-a", event_id=event.event_id)
    other = engine.trace(tenant_id="tenant-b", event_id=event.event_id)

    assert trace["step_count"] == 3
    assert other["step_count"] == 0
    assert trace["steps"][2]["detail"]["api_key"] == "[redacted]"
