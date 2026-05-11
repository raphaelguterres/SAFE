from xdr.enrichment_pipeline import EnrichmentPipeline
from xdr.normalization_engine import TelemetryNormalizationEngine


def test_enrichment_pipeline_adds_network_mitre_and_campaign_context():
    normalized = TelemetryNormalizationEngine().normalize(
        {
            "tenant_id": "tenant-a",
            "host_id": "host-1",
            "event_type": "network_connection",
            "network_dst_ip": "10.0.0.10",
            "network_dst_port": 8443,
            "domain": "example.internal",
        }
    )

    result = EnrichmentPipeline().enrich(normalized.canonical_event)

    assert "network_context" in result.applied_enrichments
    assert "campaign_linkage" in result.applied_enrichments
    assert result.event.enrichment["network_context"]["scope"] == "private"


def test_enrichment_pipeline_redacts_inventory_secrets():
    normalized = TelemetryNormalizationEngine().normalize({"tenant_id": "tenant-a", "host_id": "host-1", "event_type": "process_execution"})
    pipeline = EnrichmentPipeline(asset_inventory={"host-1": {"owner": "it", "api_key": "secret"}})

    result = pipeline.enrich(normalized.canonical_event)

    assert result.event.enrichment["asset"]["api_key"] == "[redacted]"
