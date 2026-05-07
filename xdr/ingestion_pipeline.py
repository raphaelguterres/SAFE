"""Scalable bounded ingestion pipeline for SAFE XDR telemetry."""

from __future__ import annotations

import queue
import threading
import time
import logging
from dataclasses import asdict, dataclass
from typing import Any, Callable

from .dedup_engine import EventDeduplicationEngine
from .performance_metrics import PerformanceMetrics, get_performance_metrics
from .priority_engine import PriorityDecision, TelemetryPriority, TelemetryPriorityEngine


IngestionHandler = Callable[[list[dict[str, Any]]], Any]
logger = logging.getLogger("netguard.xdr.ingestion")


@dataclass(frozen=True, slots=True)
class IngestionSubmitResult:
    accepted: bool
    queued: bool
    duplicate: bool
    tenant_id: str
    priority: str
    category: str
    reason: str
    queue_depth: int
    fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class IngestionBatchResult:
    accepted: int
    rejected: int
    duplicates: int
    results: list[IngestionSubmitResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "results": [item.to_dict() for item in self.results],
        }


@dataclass(slots=True)
class _QueueItem:
    event: dict[str, Any]
    tenant_id: str
    decision: PriorityDecision
    received_at: float


class TelemetryIngestionPipeline:
    """Bounded multi-priority queue with backpressure and deduplication.

    The pipeline is safe to use in-process today and can later be backed by
    Redis/Kafka without changing the XDR engines behind the handler.
    """

    PRIORITY_ORDER = (
        TelemetryPriority.P0,
        TelemetryPriority.P1,
        TelemetryPriority.P2,
        TelemetryPriority.P3,
    )

    def __init__(
        self,
        *,
        handler: IngestionHandler | None = None,
        max_queue_size: int = 5000,
        batch_size: int = 100,
        consumer_count: int = 1,
        priority_engine: TelemetryPriorityEngine | None = None,
        dedup_engine: EventDeduplicationEngine | None = None,
        metrics: PerformanceMetrics | None = None,
    ):
        self.handler = handler
        self.max_queue_size = max(100, int(max_queue_size))
        self.batch_size = max(1, int(batch_size))
        self.consumer_count = max(1, int(consumer_count))
        per_lane = max(25, self.max_queue_size // len(self.PRIORITY_ORDER))
        self._queues: dict[TelemetryPriority, queue.Queue[_QueueItem]] = {
            priority: queue.Queue(maxsize=per_lane)
            for priority in self.PRIORITY_ORDER
        }
        self.priority_engine = priority_engine or TelemetryPriorityEngine()
        self.dedup_engine = dedup_engine or EventDeduplicationEngine()
        self.metrics = metrics or get_performance_metrics()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._last_handler_result: Any = None
        self._last_error: str = ""
        self._last_started_at: float | None = None
        self._last_stopped_at: float | None = None
        self._last_processed_at: float | None = None
        self._start_count = 0

    def submit(self, event: Any, *, tenant_id: str | None = None) -> IngestionSubmitResult:
        payload = _event_dict(event)
        resolved_tenant = str(tenant_id or payload.get("tenant_id") or payload.get("tenant") or "default").strip() or "default"
        event_tenant = str(payload.get("tenant_id") or payload.get("tenant") or "").strip()
        if tenant_id and event_tenant and event_tenant != resolved_tenant:
            self.metrics.record_dropped(tenant_id=resolved_tenant, reason="tenant_mismatch")
            return IngestionSubmitResult(
                accepted=False,
                queued=False,
                duplicate=False,
                tenant_id=resolved_tenant,
                priority="",
                category="",
                reason="tenant_mismatch",
                queue_depth=self.total_depth(),
            )
        payload["tenant_id"] = resolved_tenant
        self.metrics.record_received(tenant_id=resolved_tenant)

        dedup = self.dedup_engine.check(payload)
        if dedup.is_duplicate:
            self.metrics.record_deduplicated(tenant_id=resolved_tenant)
            return IngestionSubmitResult(
                accepted=True,
                queued=False,
                duplicate=True,
                tenant_id=resolved_tenant,
                priority="",
                category="",
                reason=dedup.suppression_reason,
                queue_depth=self.total_depth(),
                fingerprint=dedup.fingerprint,
            )

        decision = self.priority_engine.classify(payload)
        item = _QueueItem(event=payload, tenant_id=resolved_tenant, decision=decision, received_at=time.monotonic())
        target = self._queues[decision.priority]
        if not self._try_put(target, item):
            self._apply_backpressure(decision.priority)
            if not self._try_put(target, item):
                self.metrics.record_dropped(tenant_id=resolved_tenant, reason="queue_full")
                return IngestionSubmitResult(
                    accepted=False,
                    queued=False,
                    duplicate=False,
                    tenant_id=resolved_tenant,
                    priority=decision.priority.value,
                    category=decision.category,
                    reason="queue_full",
                    queue_depth=self.total_depth(),
                    fingerprint=dedup.fingerprint,
                )

        self.metrics.record_accepted(tenant_id=resolved_tenant)
        self._record_depths()
        return IngestionSubmitResult(
            accepted=True,
            queued=True,
            duplicate=False,
            tenant_id=resolved_tenant,
            priority=decision.priority.value,
            category=decision.category,
            reason=decision.reason,
            queue_depth=self.total_depth(),
            fingerprint=dedup.fingerprint,
        )

    def submit_batch(self, events: list[Any], *, tenant_id: str | None = None) -> IngestionBatchResult:
        results = [self.submit(event, tenant_id=tenant_id) for event in events]
        return IngestionBatchResult(
            accepted=sum(1 for item in results if item.accepted and item.queued),
            rejected=sum(1 for item in results if not item.accepted),
            duplicates=sum(1 for item in results if item.duplicate),
            results=results,
        )

    def process_available(self, *, max_batches: int = 10) -> int:
        processed = 0
        for _ in range(max(1, int(max_batches))):
            item = self._get_next_item()
            if item is None:
                break
            batch = self._collect_batch(item)
            self._handle_batch(batch)
            processed += len(batch)
        self._record_depths()
        return processed

    def start(self) -> None:
        if any(thread.is_alive() for thread in self._threads):
            return
        self._threads.clear()
        self._stop.clear()
        self._last_started_at = time.time()
        self._start_count += 1
        for index in range(self.consumer_count):
            thread = threading.Thread(
                target=self._consumer_loop,
                name=f"netguard-xdr-ingest-{index + 1}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop.set()
        for thread in list(self._threads):
            thread.join(timeout=timeout)
        self._threads.clear()
        self._last_stopped_at = time.time()

    def total_depth(self) -> int:
        return sum(q.qsize() for q in self._queues.values())

    def queue_depths(self) -> dict[str, int]:
        return {priority.value: self._queues[priority].qsize() for priority in self.PRIORITY_ORDER}

    def snapshot(self) -> dict[str, Any]:
        running = any(thread.is_alive() for thread in self._threads)
        return {
            "queue_depths": self.queue_depths(),
            "total_depth": self.total_depth(),
            "max_queue_size": self.max_queue_size,
            "batch_size": self.batch_size,
            "consumer_count": self.consumer_count,
            "dedup": self.dedup_engine.stats(),
            "metrics": self.metrics.snapshot(),
            "running": running,
            "stop_requested": self._stop.is_set(),
            "start_count": self._start_count,
            "last_started_at": self._last_started_at,
            "last_stopped_at": self._last_stopped_at,
            "last_processed_at": self._last_processed_at,
            "last_error": self._last_error,
            "last_handler_result": self._last_handler_result,
        }

    def _consumer_loop(self) -> None:
        while not self._stop.is_set():
            processed = self.process_available(max_batches=1)
            if not processed:
                self._stop.wait(0.05)

    def _handle_batch(self, batch: list[_QueueItem]) -> None:
        if not batch:
            return
        started = time.monotonic()
        now = time.monotonic()
        for item in batch:
            self.metrics.record_queue_latency((now - item.received_at) * 1000)
        try:
            if self.handler:
                self._last_handler_result = self.handler([item.event for item in batch])
        except Exception as exc:
            self._last_error = type(exc).__name__
            for item in batch:
                self.metrics.record_dropped(tenant_id=item.tenant_id, reason="handler_error")
            logger.exception("XDR ingestion handler failed closed: %s", exc)
            return
        self._last_error = ""
        self._last_processed_at = time.time()
        elapsed_ms = (time.monotonic() - started) * 1000
        tenant_counts: dict[str, int] = {}
        for item in batch:
            tenant_counts[item.tenant_id] = tenant_counts.get(item.tenant_id, 0) + 1
        for tenant, count in tenant_counts.items():
            self.metrics.record_processed(tenant_id=tenant, count=count)
        self.metrics.record_ingestion_latency(elapsed_ms)

    def _collect_batch(self, first: _QueueItem) -> list[_QueueItem]:
        batch = [first]
        q = self._queues[first.decision.priority]
        while len(batch) < self.batch_size:
            try:
                batch.append(q.get_nowait())
            except queue.Empty:
                break
        return batch

    def _get_next_item(self) -> _QueueItem | None:
        for priority in self.PRIORITY_ORDER:
            try:
                return self._queues[priority].get_nowait()
            except queue.Empty:
                continue
        return None

    @staticmethod
    def _try_put(target: queue.Queue[_QueueItem], item: _QueueItem) -> bool:
        try:
            target.put_nowait(item)
            return True
        except queue.Full:
            return False

    def _apply_backpressure(self, incoming_priority: TelemetryPriority) -> None:
        """Free one lower-priority slot for P0/P1 events when possible."""
        if incoming_priority not in {TelemetryPriority.P0, TelemetryPriority.P1}:
            return
        for priority in reversed(self.PRIORITY_ORDER):
            if priority.rank <= incoming_priority.rank:
                continue
            q = self._queues[priority]
            try:
                dropped = q.get_nowait()
            except queue.Empty:
                continue
            self.metrics.record_dropped(tenant_id=dropped.tenant_id, reason="backpressure")
            break

    def _record_depths(self) -> None:
        self.metrics.set_queue_depths(self.queue_depths())


def _event_dict(event: Any) -> dict[str, Any]:
    if isinstance(event, dict):
        return dict(event)
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        return dict(to_dict())
    return {
        key: value for key, value in getattr(event, "__dict__", {}).items()
        if not key.startswith("_")
    }
