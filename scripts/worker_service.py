"""Small container entrypoint for SAFE background workers."""

from __future__ import annotations

import signal
import time

from workers import CleanupWorker, CorrelationWorker, MetricsWorker, TelemetryWorker, WorkerSupervisor
from xdr.queue_manager import ResilientQueueManager


def main() -> int:
    queue_manager = ResilientQueueManager()
    supervisor = WorkerSupervisor(
        [
            TelemetryWorker(queue_manager=queue_manager),
            CorrelationWorker(queue_manager=queue_manager),
            CleanupWorker(queue_manager=queue_manager),
            MetricsWorker(queue_manager=queue_manager),
        ]
    )
    stopping = False

    def _stop(_signum, _frame):
        nonlocal stopping
        stopping = True
        supervisor.stop_all()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    supervisor.start_all()
    print("SAFE worker service started")
    while not stopping:
        supervisor.recover_failed()
        time.sleep(5)
    print("SAFE worker service stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
