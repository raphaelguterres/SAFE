"""Recovery and rollback orchestration for SAFE operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Mapping, Sequence
from uuid import uuid4

from .queue_manager import ResilientQueueManager
from workers.base import WorkerSupervisor


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class RecoveryAction:
    action_id: str
    action_type: str
    status: str
    reason: str
    tenant_id: str = "system"
    target_id: str = ""
    created_at: str = field(default_factory=lambda: _now().isoformat())
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "status": self.status,
            "reason": self.reason,
            "tenant_id": self.tenant_id,
            "target_id": self.target_id,
            "created_at": self.created_at,
            "details": dict(self.details),
        }


class RecoveryEngine:
    """Create safe recovery plans and execute reversible in-memory repairs."""

    def recover_queue(self, queue_manager: ResilientQueueManager, *, tenant_id: str | None = None, limit: int = 100) -> RecoveryAction:
        recovered = queue_manager.recover_dead_letters(limit=limit, tenant_id=tenant_id)
        return RecoveryAction(
            action_id=uuid4().hex,
            action_type="queue_recovery",
            status="completed" if recovered else "skipped",
            reason="dead_letters_requeued" if recovered else "no_dead_letters",
            tenant_id=tenant_id or "system",
            details={"recovered": recovered},
        )

    def recover_workers(self, supervisor: WorkerSupervisor) -> RecoveryAction:
        restarted = supervisor.recover_failed()
        return RecoveryAction(
            action_id=uuid4().hex,
            action_type="worker_recovery",
            status="completed" if restarted else "skipped",
            reason="workers_restarted" if restarted else "no_failed_workers",
            details={"restarted": restarted},
        )

    def cleanup_stale_approvals(self, approvals: Sequence[Mapping[str, Any]], *, now: datetime | None = None) -> list[RecoveryAction]:
        current = now or _now()
        actions: list[RecoveryAction] = []
        for approval in approvals:
            expires_raw = str(approval.get("expires_at") or "")
            try:
                expires = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
            except Exception:
                continue
            if expires <= current and str(approval.get("status") or "pending") == "pending":
                actions.append(
                    RecoveryAction(
                        action_id=uuid4().hex,
                        action_type="approval_expiry",
                        status="expired",
                        reason="approval_window_elapsed",
                        tenant_id=str(approval.get("tenant_id") or "system"),
                        target_id=str(approval.get("approval_id") or approval.get("action_id") or ""),
                    )
                )
        return actions

    def cleanup_expired_responses(self, responses: Sequence[Mapping[str, Any]], *, now: datetime | None = None) -> list[RecoveryAction]:
        current = now or _now()
        actions: list[RecoveryAction] = []
        for response in responses:
            expires_raw = str(response.get("expires_at") or "")
            try:
                expires = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
            except Exception:
                continue
            if expires <= current and str(response.get("status") or "pending") in {"pending", "approved"}:
                actions.append(
                    RecoveryAction(
                        action_id=uuid4().hex,
                        action_type="response_expiry",
                        status="expired",
                        reason="response_window_elapsed",
                        tenant_id=str(response.get("tenant_id") or "system"),
                        target_id=str(response.get("action_id") or ""),
                    )
                )
        return actions

    def plan_failed_containment_recovery(self, containment: Mapping[str, Any]) -> RecoveryAction:
        tenant_id = str(containment.get("tenant_id") or "system")
        host_id = str(containment.get("host_id") or containment.get("target_id") or "")
        rollback = {
            "rollback_required": True,
            "steps": [
                "verify_agent_reachable",
                "remove_partial_firewall_rules",
                "restore_network_policy_from_last_known_good",
                "record_audit_event",
            ],
        }
        return RecoveryAction(
            action_id=uuid4().hex,
            action_type="failed_containment_recovery",
            status="planned",
            reason="containment_failed_or_timed_out",
            tenant_id=tenant_id,
            target_id=host_id,
            details=rollback,
        )

    def rollback_orchestration(self, chain: Sequence[Mapping[str, Any]], *, tenant_id: str = "system") -> list[RecoveryAction]:
        actions: list[RecoveryAction] = []
        for step in reversed(list(chain)):
            rollback_action = step.get("rollback_action") or step.get("rollback")
            if not rollback_action:
                continue
            actions.append(
                RecoveryAction(
                    action_id=uuid4().hex,
                    action_type="orchestration_rollback",
                    status="planned",
                    reason=str(rollback_action),
                    tenant_id=str(step.get("tenant_id") or tenant_id),
                    target_id=str(step.get("host_id") or step.get("target_id") or ""),
                    details={"source_step": dict(step)},
                )
            )
        return actions


def expiry(minutes: int = 15) -> str:
    return (_now() + timedelta(minutes=max(1, minutes))).isoformat()
