from __future__ import annotations

from xdr.heartbeat_engine import HostHeartbeatEngine, HostHeartbeatState
from xdr.ingestion_pipeline import TelemetryIngestionPipeline


def _event(index: int, *, tenant_id: str = "tenant-a", severity: str = "low", command: str | None = None):
    return {
        "tenant_id": tenant_id,
        "host_id": f"host-{index % 12}",
        "event_type": "process_execution",
        "severity": severity,
        "process_name": "powershell.exe" if severity in {"high", "critical"} else "notepad.exe",
        "command_line": command or f"cmd.exe /c echo {index}",
        "timestamp": "2026-05-06T12:00:00Z",
    }


def test_ingestion_pipeline_processes_p0_before_p3():
    processed: list[str] = []
    pipeline = TelemetryIngestionPipeline(
        handler=lambda events: processed.extend(event["severity"] for event in events),
        max_queue_size=100,
        batch_size=1,
    )

    assert pipeline.submit(_event(1, severity="low")).queued is True
    assert pipeline.submit(_event(2, severity="critical", command="procdump lsass")).queued is True
    pipeline.process_available(max_batches=2)

    assert processed == ["critical", "low"]


def test_ingestion_pipeline_fails_closed_under_queue_flood():
    pipeline = TelemetryIngestionPipeline(max_queue_size=100, batch_size=25)

    result = pipeline.submit_batch([_event(i, command=f"cmd /c echo {i}") for i in range(1200)])

    assert result.accepted > 0
    assert result.rejected > 0
    assert pipeline.total_depth() <= 100
    assert pipeline.snapshot()["metrics"]["counters"]["events_dropped"] > 0


def test_ingestion_pipeline_rejects_tenant_mismatch():
    pipeline = TelemetryIngestionPipeline(max_queue_size=100)

    result = pipeline.submit(_event(1, tenant_id="tenant-b"), tenant_id="tenant-a")

    assert result.accepted is False
    assert result.reason == "tenant_mismatch"
    assert pipeline.total_depth() == 0


def test_heartbeat_engine_marks_stale_hosts_offline():
    engine = HostHeartbeatEngine(healthy_after_seconds=30, delayed_after_seconds=60, offline_after_seconds=120)
    engine.record_heartbeat(tenant_id="tenant-a", host_id="host-1", now=1000)
    engine.record_telemetry(tenant_id="tenant-a", host_id="host-1", now=1000)

    fresh = engine.evaluate_host(tenant_id="tenant-a", host_id="host-1", now=1010)
    stale = engine.evaluate_host(tenant_id="tenant-a", host_id="host-1", now=1200)

    assert fresh.state == HostHeartbeatState.HEALTHY
    assert stale.state == HostHeartbeatState.OFFLINE
