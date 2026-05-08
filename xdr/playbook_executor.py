"""Defensive playbook execution planner for SAFE SOC operations."""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


CRITICAL_ACTIONS = {"isolate_host", "suspend_user", "force_password_reset", "network_containment"}
SUPPORTED_PLAYBOOKS = {
    "isolate_host": ("collect_diagnostics", "isolate_host", "verify_agent_heartbeat"),
    "collect_diagnostics": ("collect_diagnostics",),
    "ioc_hunt": ("hunt_iocs", "summarize_matches"),
    "suspend_user": ("collect_identity_context", "suspend_user"),
    "force_password_reset_recommendation": ("collect_identity_context", "force_password_reset"),
    "persistence_review": ("collect_diagnostics", "review_persistence_artifacts"),
    "network_containment_recommendation": ("collect_network_context", "network_containment"),
}


class PlaybookStepStatus(str, Enum):
    PENDING = "pending"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    EXECUTED = "executed"
    REFUSED = "refused"
    ROLLED_BACK = "rolled_back"
    SKIPPED = "skipped"


@dataclass(slots=True)
class PlaybookStep:
    step_id: str
    action_type: str
    approval_required: bool
    rollback_action: str = ""
    status: PlaybookStepStatus = PlaybookStepStatus.PENDING
    simulation_result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


@dataclass(slots=True)
class PlaybookRun:
    run_id: str
    tenant_id: str
    playbook: str
    target: str
    requested_by: str
    simulation_mode: bool
    created_at: float
    status: str
    reason: str = ""
    steps: list[PlaybookStep] = field(default_factory=list)
    audit_log: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["steps"] = [step.to_dict() for step in self.steps]
        return payload


class DefensivePlaybookExecutor:
    """Creates auditable, approval-gated defensive playbook runs."""

    def create_run(
        self,
        *,
        tenant_id: str,
        playbook: str,
        target: str,
        requested_by: str,
        reason: str = "",
        simulation_mode: bool = True,
    ) -> PlaybookRun:
        normalized = str(playbook or "").strip().lower()
        if normalized not in SUPPORTED_PLAYBOOKS:
            raise ValueError("unsupported_playbook")
        run = PlaybookRun(
            run_id=f"pbr_{uuid.uuid4().hex}",
            tenant_id=_tenant(tenant_id),
            playbook=normalized,
            target=str(target or "").strip(),
            requested_by=str(requested_by or "system")[:128],
            simulation_mode=bool(simulation_mode),
            created_at=time.time(),
            status="created",
            reason=str(reason or "")[:500],
        )
        for action in SUPPORTED_PLAYBOOKS[normalized]:
            approval = action in CRITICAL_ACTIONS
            run.steps.append(
                PlaybookStep(
                    step_id=f"pbs_{uuid.uuid4().hex}",
                    action_type=action,
                    approval_required=approval,
                    rollback_action=_rollback_for(action),
                    status=PlaybookStepStatus.WAITING_APPROVAL if approval else PlaybookStepStatus.APPROVED,
                )
            )
        self._audit(run, "playbook_created", {"playbook": normalized})
        run.status = "waiting_approval" if any(step.approval_required for step in run.steps) else "ready"
        return run

    def approve_step(self, run: PlaybookRun, *, step_id: str, approver: str) -> PlaybookStep:
        step = _find_step(run, step_id)
        if not step.approval_required:
            return step
        if step.status not in {PlaybookStepStatus.WAITING_APPROVAL, PlaybookStepStatus.REFUSED}:
            return step
        step.status = PlaybookStepStatus.APPROVED
        self._audit(run, "step_approved", {"step_id": step_id, "approver": approver})
        run.status = "ready"
        return step

    def execute_ready_steps(self, run: PlaybookRun) -> list[PlaybookStep]:
        executed = []
        for step in run.steps:
            if step.status != PlaybookStepStatus.APPROVED:
                continue
            step.status = PlaybookStepStatus.EXECUTED
            step.simulation_result = {
                "mode": "simulation" if run.simulation_mode else "planned",
                "action_type": step.action_type,
                "target": run.target,
                "executed": False if run.simulation_mode else "queued_for_safe_executor",
            }
            self._audit(run, "step_executed_simulated" if run.simulation_mode else "step_queued", step.simulation_result)
            executed.append(step)
        run.status = "executed" if all(step.status == PlaybookStepStatus.EXECUTED for step in run.steps) else run.status
        return executed

    def rollback(self, run: PlaybookRun, *, actor: str) -> list[dict[str, Any]]:
        rollbacks = []
        for step in run.steps:
            if step.status != PlaybookStepStatus.EXECUTED or not step.rollback_action:
                continue
            step.status = PlaybookStepStatus.ROLLED_BACK
            entry = {"step_id": step.step_id, "rollback_action": step.rollback_action, "actor": actor}
            rollbacks.append(entry)
            self._audit(run, "rollback_prepared", entry)
        run.status = "rolled_back" if rollbacks else run.status
        return rollbacks

    @staticmethod
    def _audit(run: PlaybookRun, event_type: str, metadata: dict[str, Any]) -> None:
        run.audit_log.append({
            "timestamp": time.time(),
            "event_type": event_type,
            "tenant_id": run.tenant_id,
            "run_id": run.run_id,
            "metadata": dict(metadata),
        })


def _find_step(run: PlaybookRun, step_id: str) -> PlaybookStep:
    for step in run.steps:
        if step.step_id == step_id:
            return step
    raise KeyError("step_not_found")


def _rollback_for(action: str) -> str:
    return {
        "isolate_host": "rollback_host_isolation",
        "network_containment": "remove_network_block",
        "suspend_user": "restore_user_after_authorized_review",
        "force_password_reset": "document_identity_recovery",
    }.get(action, "")


def _tenant(value: str | None) -> str:
    return str(value or "default").strip() or "default"


__all__ = ["DefensivePlaybookExecutor", "PlaybookRun", "PlaybookStep", "PlaybookStepStatus"]
