"""Restart-safe background workers for SAFE operational core."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Event, RLock, Thread
import time
from typing import Any, Callable, Dict

from xdr.queue_manager import QueuedMessage, ResilientQueueManager


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class WorkerStatus(str, Enum):
    stopped = "stopped"
    starting = "starting"
    running = "running"
    degraded = "degraded"
    failed = "failed"
    stopping = "stopping"


@dataclass
class WorkerMetrics:
    processed: int = 0
    failed: int = 0
    restarts: int = 0
    last_error: str = ""
    last_heartbeat_at: str | None = None
    last_processed_at: str | None = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "processed": self.processed,
            "failed": self.failed,
            "restarts": self.restarts,
            "last_error": self.last_error,
            "last_heartbeat_at": self.last_heartbeat_at,
            "last_processed_at": self.last_processed_at,
        }


class BaseWorker:
    """Small thread-capable worker with bounded queue semantics."""

    def __init__(
        self,
        *,
        name: str,
        queue_manager: ResilientQueueManager,
        handler: Callable[[QueuedMessage], None] | None = None,
        batch_size: int = 25,
        idle_sleep_seconds: float = 0.25,
        max_backoff_seconds: float = 5.0,
    ) -> None:
        self.name = name
        self.queue_manager = queue_manager
        self.handler = handler or (lambda _message: None)
        self.batch_size = max(1, int(batch_size))
        self.idle_sleep_seconds = max(0.01, float(idle_sleep_seconds))
        self.max_backoff_seconds = max(self.idle_sleep_seconds, float(max_backoff_seconds))
        self.status = WorkerStatus.stopped
        self.metrics = WorkerMetrics()
        self._stop = Event()
        self._thread: Thread | None = None
        self._lock = RLock()

    def start(self) -> bool:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return False
            self._stop.clear()
            self.status = WorkerStatus.starting
            self._thread = Thread(target=self._run, name=f"safe-{self.name}", daemon=True)
            self._thread.start()
            return True

    def stop(self, timeout: float = 3.0) -> None:
        with self._lock:
            self.status = WorkerStatus.stopping
            self._stop.set()
            thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=timeout)
        with self._lock:
            self.status = WorkerStatus.stopped

    def restart(self) -> None:
        self.stop()
        with self._lock:
            self.metrics.restarts += 1
        self.start()

    def process_once(self, *, tenant_id: str | None = None) -> int:
        processed = 0
        self.status = WorkerStatus.running
        self.metrics.last_heartbeat_at = _now()
        batch = self.queue_manager.next_batch(self.batch_size, tenant_id=tenant_id)
        for message in batch:
            try:
                self.handler(message)
            except Exception as exc:  # pragma: no cover - defensive guard
                self.metrics.failed += 1
                self.metrics.last_error = safe_error(exc)
                self.status = WorkerStatus.degraded
                self.queue_manager.fail(message.message_id, self.metrics.last_error)
            else:
                self.queue_manager.ack(message.message_id)
                self.metrics.processed += 1
                self.metrics.last_processed_at = _now()
                processed += 1
        return processed

    def snapshot(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "batch_size": self.batch_size,
            "metrics": self.metrics.to_dict(),
            "queue": self.queue_manager.snapshot(),
        }

    def _run(self) -> None:
        backoff = self.idle_sleep_seconds
        self.status = WorkerStatus.running
        while not self._stop.is_set():
            try:
                processed = self.process_once()
                backoff = self.idle_sleep_seconds if processed else min(self.max_backoff_seconds, backoff * 1.5)
            except Exception as exc:  # pragma: no cover - defensive guard
                self.metrics.failed += 1
                self.metrics.last_error = safe_error(exc)
                self.status = WorkerStatus.failed
                backoff = min(self.max_backoff_seconds, backoff * 2)
            self._stop.wait(backoff)
        self.status = WorkerStatus.stopped


class TelemetryWorker(BaseWorker):
    def __init__(self, *, queue_manager: ResilientQueueManager, handler: Callable[[QueuedMessage], None] | None = None) -> None:
        super().__init__(name="telemetry", queue_manager=queue_manager, handler=handler)


class CorrelationWorker(BaseWorker):
    def __init__(self, *, queue_manager: ResilientQueueManager, handler: Callable[[QueuedMessage], None] | None = None) -> None:
        super().__init__(name="correlation", queue_manager=queue_manager, handler=handler)


class OrchestrationWorker(BaseWorker):
    def __init__(self, *, queue_manager: ResilientQueueManager, handler: Callable[[QueuedMessage], None] | None = None) -> None:
        super().__init__(name="orchestration", queue_manager=queue_manager, handler=handler)


class CleanupWorker(BaseWorker):
    def __init__(self, *, queue_manager: ResilientQueueManager, handler: Callable[[QueuedMessage], None] | None = None) -> None:
        super().__init__(name="cleanup", queue_manager=queue_manager, handler=handler)


class MetricsWorker(BaseWorker):
    def __init__(self, *, queue_manager: ResilientQueueManager, handler: Callable[[QueuedMessage], None] | None = None) -> None:
        super().__init__(name="metrics", queue_manager=queue_manager, handler=handler)


class HuntWorker(BaseWorker):
    def __init__(self, *, queue_manager: ResilientQueueManager, handler: Callable[[QueuedMessage], None] | None = None) -> None:
        super().__init__(name="hunt", queue_manager=queue_manager, handler=handler)


class WorkerSupervisor:
    def __init__(self, workers: list[BaseWorker] | None = None) -> None:
        self.workers: Dict[str, BaseWorker] = {worker.name: worker for worker in workers or []}

    def add_worker(self, worker: BaseWorker) -> None:
        self.workers[worker.name] = worker

    def start_all(self) -> None:
        for worker in self.workers.values():
            worker.start()

    def stop_all(self) -> None:
        for worker in self.workers.values():
            worker.stop()

    def recover_failed(self) -> list[str]:
        restarted: list[str] = []
        for name, worker in self.workers.items():
            if worker.status in {WorkerStatus.failed, WorkerStatus.degraded}:
                worker.restart()
                restarted.append(name)
        return restarted

    def snapshot(self) -> Dict[str, Any]:
        statuses = {name: worker.snapshot() for name, worker in self.workers.items()}
        return {
            "workers": statuses,
            "active_workers": sum(1 for worker in self.workers.values() if worker.status == WorkerStatus.running),
            "failed_workers": [name for name, worker in self.workers.items() if worker.status == WorkerStatus.failed],
        }


def safe_error(exc: Exception) -> str:
    text = str(exc) or exc.__class__.__name__
    return text.replace("\n", " ")[:240]
