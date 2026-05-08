from xdr.health_engine import HealthEngine


def test_health_engine_marks_queue_saturation_critical():
    health = HealthEngine().evaluate(
        db_ok=True,
        queue_snapshot={"max_size": 10, "total_depth": 10, "dead_letter_depth": 0},
        stream_snapshot={"active_clients": 0, "event_bus": {"dropped": 0}},
        worker_snapshot={"workers": {"telemetry": {}}, "active_workers": 1, "failed_workers": []},
        ingestion_snapshot={"dropped": 0},
    )

    assert health["status"] == "critical"
    assert any(component["name"] == "queues" and component["status"] == "critical" for component in health["components"])


def test_health_engine_marks_failed_worker_unstable_without_db_failure():
    health = HealthEngine().evaluate(
        db_ok=True,
        queue_snapshot={"max_size": 100, "total_depth": 1, "dead_letter_depth": 0},
        stream_snapshot={"active_clients": 1, "event_bus": {"dropped": 0}},
        worker_snapshot={"workers": {"telemetry": {}}, "active_workers": 0, "failed_workers": ["telemetry"]},
        ingestion_snapshot={"dropped": 0},
    )

    assert health["status"] == "unstable"
