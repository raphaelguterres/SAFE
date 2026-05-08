from workers import TelemetryWorker, WorkerStatus, WorkerSupervisor
from xdr.queue_manager import ResilientQueueManager


def test_worker_process_once_records_failures_and_retries():
    queue = ResilientQueueManager(max_size=10)
    queue.submit(tenant_id="tenant-a", event_type="telemetry", payload={"ok": True}, max_attempts=2)

    def failing_handler(_message):
        raise RuntimeError("handler failed")

    worker = TelemetryWorker(queue_manager=queue, handler=failing_handler)
    processed = worker.process_once()

    assert processed == 0
    assert worker.status == WorkerStatus.degraded
    assert worker.metrics.failed == 1
    assert queue.snapshot()["retried"] == 1


def test_worker_supervisor_recovers_failed_workers():
    queue = ResilientQueueManager(max_size=10)
    worker = TelemetryWorker(queue_manager=queue)
    worker.status = WorkerStatus.failed
    supervisor = WorkerSupervisor([worker])

    restarted = supervisor.recover_failed()
    supervisor.stop_all()

    assert restarted == ["telemetry"]
    assert worker.metrics.restarts == 1
