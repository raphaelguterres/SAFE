from xdr.observability import ObservabilityRegistry


def test_observability_snapshot_includes_queue_and_stream_metrics():
    registry = ObservabilityRegistry()
    registry.increment("telemetry_events", 3, tenant_id="tenant-a")
    registry.observe_latency("worker_latency", 12.5)
    snapshot = registry.snapshot(
        queue_snapshot={"max_size": 10, "total_depth": 5, "dropped": 1},
        stream_snapshot={"active_clients": 2},
        worker_snapshot={"active_workers": 1},
    )

    assert snapshot["telemetry_throughput"] == 3
    assert snapshot["queue_pressure"] == 0.5
    assert snapshot["dropped_events"] == 1
    assert snapshot["tenant_counters"]["tenant-a"]["telemetry_events"] == 3
