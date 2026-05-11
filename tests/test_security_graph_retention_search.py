from datetime import datetime, timezone

from xdr.normalization_engine import TelemetryNormalizationEngine
from xdr.retention_engine import RetentionEngine, days_ago
from xdr.security_graph import SecurityKnowledgeGraph
from xdr.security_search import SecurityDataSearchEngine


def test_security_graph_keeps_tenant_views_isolated():
    normalizer = TelemetryNormalizationEngine()
    event_a = normalizer.normalize({"tenant_id": "tenant-a", "host_id": "h1", "event_type": "network_connection", "network_dst_ip": "10.0.0.9"}).canonical_event
    event_b = normalizer.normalize({"tenant_id": "tenant-b", "host_id": "h2", "event_type": "network_connection", "network_dst_ip": "10.0.0.8"}).canonical_event
    graph = SecurityKnowledgeGraph()

    graph.ingest_event(event_a)
    graph.ingest_event(event_b)

    view = graph.tenant_view("tenant-a")
    assert view["node_count"] > 0
    assert all(node["tenant_id"] == "tenant-a" for node in view["nodes"])


def test_retention_engine_classifies_hot_warm_archive_and_expired():
    engine = RetentionEngine()
    plan = engine.build_plan(
        [
            {"tenant_id": "tenant-a", "event_id": "hot", "category": "telemetry", "timestamp": days_ago(1)},
            {"tenant_id": "tenant-a", "event_id": "archive", "category": "telemetry", "timestamp": days_ago(200)},
            {"tenant_id": "tenant-a", "event_id": "expired", "category": "telemetry", "timestamp": days_ago(500)},
        ],
        tenant_id="tenant-a",
        now=datetime.now(timezone.utc),
    )

    assert plan["summary"]["hot"] == 1
    assert plan["summary"]["archive"] == 1
    assert plan["summary"]["expired"] == 1


def test_security_search_redacts_and_builds_pivots():
    result = SecurityDataSearchEngine().search(
        tenant_id="tenant-a",
        query="powershell",
        datasets={"telemetry": [{"tenant_id": "tenant-a", "host_id": "h1", "event_type": "powershell", "api_key": "secret"}]},
    )

    assert result["total"] == 1
    assert result["results"][0]["record"]["api_key"] == "[redacted]"
    assert result["pivots"]["hosts"] == ["h1"]
