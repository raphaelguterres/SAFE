"""Queue backend contracts and memory adapter defaults for SAFE."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from .queue_manager import QueuedMessage, QueueSubmitResult, ResilientQueueManager


class QueueBackend(Protocol):
    def submit(
        self,
        *,
        tenant_id: str,
        event_type: str,
        payload: Mapping[str, Any],
        priority: str = "P2",
        trace_id: str | None = None,
        max_attempts: int = 3,
    ) -> QueueSubmitResult:
        ...

    def next_batch(self, limit: int = 100, *, tenant_id: str | None = None) -> list[QueuedMessage]:
        ...

    def ack(self, message_id: str) -> bool:
        ...

    def fail(self, message_id: str, reason: str = "worker_failed") -> bool:
        ...

    def recover_dead_letters(self, limit: int = 100, *, tenant_id: str | None = None) -> int:
        ...

    def snapshot(self) -> dict[str, Any]:
        ...

    def dead_letters(self, limit: int = 50) -> list[dict[str, Any]]:
        ...


def build_memory_queue_backend(
    *,
    max_size: int = 10_000,
    dead_letter_size: int = 1_000,
    per_tenant_limit: int = 2_500,
) -> ResilientQueueManager:
    return ResilientQueueManager(
        max_size=max_size,
        dead_letter_size=dead_letter_size,
        per_tenant_limit=per_tenant_limit,
    )
