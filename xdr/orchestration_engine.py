"""Multi-host response orchestration for defensive EDR workflows."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ResponseStageStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REFUSED = "refused"
    EXPIRED = "expired"
    EXECUTED = "executed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass(slots=True)
class ResponseStage:
    stage_id: str
    host_id: str
    action_type: str
    approval_required: bool
    status: ResponseStageStatus = ResponseStageStatus.PENDING
    parameters: dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    retries: int = 0
    max_retries: int = 2
    approved_by: str = ""
    result: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        return payload


@dataclass(slots=True)
class OrchestrationPlan:
    plan_id: str
    tenant_id: str
    action_type: str
    host_ids: list[str]
    status: str
    created_at: float
    stages: list[ResponseStage] = field(default_factory=list)
    rollback_stages: list[ResponseStage] = field(default_factory=list)
    reason: str = ""
    checkpoints: list[dict[str, Any]] = field(default_factory=list)
    escalation_route: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["stages"] = [stage.to_dict() for stage in self.stages]
        payload["rollback_stages"] = [stage.to_dict() for stage in self.rollback_stages]
        return payload


class ResponseOrchestrationEngine:
    """Coordinates approved response actions across one or more hosts."""

    def __init__(self, *, default_timeout_seconds: int = 900):
        self.default_timeout_seconds = max(60, int(default_timeout_seconds))
        self._lock = threading.RLock()
        self._plans: dict[str, OrchestrationPlan] = {}

    def create_containment_plan(
        self,
        *,
        tenant_id: str,
        host_ids: list[str],
        reason: str = "",
        approval_required: bool = True,
        timeout_seconds: int | None = None,
    ) -> OrchestrationPlan:
        tenant = _tenant(tenant_id)
        hosts = [str(host).strip() for host in host_ids if str(host).strip()]
        if not hosts:
            raise ValueError("host_ids_required")
        now = time.time()
        expires = now + max(60, int(timeout_seconds or self.default_timeout_seconds))
        plan = OrchestrationPlan(
            plan_id=f"orch_{uuid.uuid4().hex}",
            tenant_id=tenant,
            action_type="multi_host_containment",
            host_ids=hosts,
            status="pending_approval" if approval_required else "ready",
            created_at=now,
            reason=reason,
        )
        for host_id in hosts:
            plan.stages.append(
                ResponseStage(
                    stage_id=f"stage_{uuid.uuid4().hex}",
                    host_id=host_id,
                    action_type="collect_diagnostics",
                    approval_required=False,
                    status=ResponseStageStatus.APPROVED,
                    expires_at=expires,
                )
            )
            plan.stages.append(
                ResponseStage(
                    stage_id=f"stage_{uuid.uuid4().hex}",
                    host_id=host_id,
                    action_type="safe_host_isolation",
                    approval_required=approval_required,
                    expires_at=expires,
                    parameters={"preserve_netguard_server": True},
                )
            )
            plan.rollback_stages.append(
                ResponseStage(
                    stage_id=f"rollback_{uuid.uuid4().hex}",
                    host_id=host_id,
                    action_type="rollback_host_isolation",
                    approval_required=False,
                    status=ResponseStageStatus.APPROVED,
                    expires_at=expires + 3600,
                )
            )
        with self._lock:
            self._plans[plan.plan_id] = plan
        return plan

    def create_chained_playbook_plan(
        self,
        *,
        tenant_id: str,
        host_id: str,
        playbook_steps: list[dict[str, Any]],
        reason: str = "",
        escalation_route: str = "soc_lead",
        timeout_seconds: int | None = None,
    ) -> OrchestrationPlan:
        """Create a conditional SOAR-like plan with analyst checkpoints."""
        tenant = _tenant(tenant_id)
        host = str(host_id or "").strip()
        if not host:
            raise ValueError("host_id_required")
        now = time.time()
        expires = now + max(60, int(timeout_seconds or self.default_timeout_seconds))
        plan = OrchestrationPlan(
            plan_id=f"orch_{uuid.uuid4().hex}",
            tenant_id=tenant,
            action_type="chained_playbook",
            host_ids=[host],
            status="pending_approval",
            created_at=now,
            reason=reason,
            escalation_route=str(escalation_route or "soc_lead")[:128],
        )
        for index, step in enumerate(playbook_steps or [], start=1):
            action_type = str(step.get("action_type") or "").strip().lower()
            if not action_type:
                continue
            approval_required = bool(step.get("approval_required", action_type not in {"collect_diagnostics", "hunt_iocs"}))
            plan.stages.append(
                ResponseStage(
                    stage_id=f"stage_{uuid.uuid4().hex}",
                    host_id=host,
                    action_type=action_type,
                    approval_required=approval_required,
                    status=ResponseStageStatus.PENDING if approval_required else ResponseStageStatus.APPROVED,
                    parameters=dict(step.get("parameters") or {}),
                    expires_at=expires,
                )
            )
            if step.get("checkpoint"):
                plan.checkpoints.append({
                    "checkpoint_id": f"chk_{uuid.uuid4().hex}",
                    "after_step": index,
                    "label": str(step.get("checkpoint"))[:180],
                    "confirmed": False,
                    "confirmed_by": "",
                })
            rollback_action = str(step.get("rollback_action") or _default_rollback(action_type))
            if rollback_action:
                plan.rollback_stages.insert(
                    0,
                    ResponseStage(
                        stage_id=f"rollback_{uuid.uuid4().hex}",
                        host_id=host,
                        action_type=rollback_action,
                        approval_required=False,
                        status=ResponseStageStatus.APPROVED,
                        expires_at=expires + 3600,
                    ),
                )
        if not plan.stages:
            raise ValueError("playbook_steps_required")
        with self._lock:
            self._plans[plan.plan_id] = plan
        return plan

    def approve_stage(self, *, plan_id: str, stage_id: str, approver: str) -> ResponseStage:
        stage = self._stage(plan_id, stage_id)
        with self._lock:
            if self._is_expired(stage):
                stage.status = ResponseStageStatus.EXPIRED
                return stage
            if stage.status not in {ResponseStageStatus.PENDING, ResponseStageStatus.REFUSED}:
                return stage
            stage.status = ResponseStageStatus.APPROVED
            stage.approved_by = str(approver or "unknown")[:128]
            self._refresh_plan_status(self._plans[plan_id])
            return stage

    def refuse_stage(self, *, plan_id: str, stage_id: str, approver: str, reason: str = "") -> ResponseStage:
        stage = self._stage(plan_id, stage_id)
        with self._lock:
            stage.status = ResponseStageStatus.REFUSED
            stage.approved_by = str(approver or "unknown")[:128]
            stage.result = {"reason": reason}
            self._refresh_plan_status(self._plans[plan_id])
            return stage

    def next_actions(self, *, plan_id: str, tenant_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            plan = self._plans.get(plan_id)
            if not plan:
                return []
            if tenant_id and plan.tenant_id != _tenant(tenant_id):
                return []
            actions = []
            for stage in plan.stages:
                if self._is_expired(stage):
                    stage.status = ResponseStageStatus.EXPIRED
                    continue
                if stage.status != ResponseStageStatus.APPROVED:
                    continue
                if not self._prior_stages_satisfied(plan, stage):
                    continue
                actions.append({
                    "plan_id": plan.plan_id,
                    "stage_id": stage.stage_id,
                    "tenant_id": plan.tenant_id,
                    "host_id": stage.host_id,
                    "action_type": stage.action_type,
                    "parameters": dict(stage.parameters),
                    "retries": stage.retries,
                    "max_retries": stage.max_retries,
                })
                if len(actions) >= limit:
                    break
            self._refresh_plan_status(plan)
            return actions

    def record_action_result(
        self,
        *,
        plan_id: str,
        stage_id: str,
        success: bool,
        result: dict[str, Any] | None = None,
    ) -> ResponseStage:
        stage = self._stage(plan_id, stage_id)
        with self._lock:
            stage.result = dict(result or {})
            if success:
                stage.status = ResponseStageStatus.EXECUTED
            else:
                stage.retries += 1
                stage.status = ResponseStageStatus.APPROVED if stage.retries <= stage.max_retries else ResponseStageStatus.FAILED
            self._refresh_plan_status(self._plans[plan_id])
            return stage

    def rollback_plan(self, *, plan_id: str, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            plan = self._plans.get(plan_id)
            if not plan:
                return []
            if tenant_id and plan.tenant_id != _tenant(tenant_id):
                return []
            plan.status = "rollback_ready"
            return [
                {
                    "plan_id": plan.plan_id,
                    "stage_id": stage.stage_id,
                    "tenant_id": plan.tenant_id,
                    "host_id": stage.host_id,
                    "action_type": stage.action_type,
                    "parameters": dict(stage.parameters),
                }
                for stage in plan.rollback_stages
                if stage.status == ResponseStageStatus.APPROVED
            ]

    def confirm_checkpoint(
        self,
        *,
        plan_id: str,
        checkpoint_id: str,
        analyst: str,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            plan = self._plans.get(plan_id)
            if not plan:
                raise KeyError("plan_not_found")
            if tenant_id and plan.tenant_id != _tenant(tenant_id):
                raise KeyError("plan_not_found")
            for checkpoint in plan.checkpoints:
                if checkpoint.get("checkpoint_id") == checkpoint_id:
                    checkpoint["confirmed"] = True
                    checkpoint["confirmed_by"] = str(analyst or "analyst")[:128]
                    self._refresh_plan_status(plan)
                    return dict(checkpoint)
        raise KeyError("checkpoint_not_found")

    def list_plans(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            plans = list(self._plans.values())
        tenant = _tenant(tenant_id) if tenant_id else None
        return [
            plan.to_dict()
            for plan in plans
            if not tenant or plan.tenant_id == tenant
        ]

    def _stage(self, plan_id: str, stage_id: str) -> ResponseStage:
        with self._lock:
            plan = self._plans.get(plan_id)
            if not plan:
                raise KeyError("plan_not_found")
            for stage in [*plan.stages, *plan.rollback_stages]:
                if stage.stage_id == stage_id:
                    return stage
        raise KeyError("stage_not_found")

    @staticmethod
    def _is_expired(stage: ResponseStage) -> bool:
        return bool(stage.expires_at and time.time() > stage.expires_at and stage.status in {ResponseStageStatus.PENDING, ResponseStageStatus.APPROVED})

    @staticmethod
    def _prior_stages_satisfied(plan: OrchestrationPlan, current: ResponseStage) -> bool:
        host_stages = [stage for stage in plan.stages if stage.host_id == current.host_id]
        for stage in host_stages:
            if stage.stage_id == current.stage_id:
                return True
            if stage.status != ResponseStageStatus.EXECUTED:
                return False
        return True

    @staticmethod
    def _refresh_plan_status(plan: OrchestrationPlan) -> None:
        statuses = {stage.status for stage in plan.stages}
        if ResponseStageStatus.FAILED in statuses:
            plan.status = "failed"
        elif ResponseStageStatus.REFUSED in statuses:
            plan.status = "refused"
        elif all(stage.status == ResponseStageStatus.EXECUTED for stage in plan.stages):
            plan.status = "executed"
        elif any(stage.status == ResponseStageStatus.APPROVED for stage in plan.stages):
            plan.status = "ready"
        elif any(stage.status == ResponseStageStatus.PENDING for stage in plan.stages):
            plan.status = "pending_approval"


def _tenant(value: str | None) -> str:
    return str(value or "default").strip() or "default"


def _default_rollback(action_type: str) -> str:
    return {
        "safe_host_isolation": "rollback_host_isolation",
        "isolate_host": "rollback_host_isolation",
        "block_ip": "remove_ip_block",
        "network_containment": "remove_network_containment",
        "suspend_user": "restore_user_after_authorized_review",
    }.get(str(action_type or "").strip().lower(), "")
