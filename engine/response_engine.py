"""Active defense response engine for SAFE EDR.

The existing project already has low-level remediation primitives
(`auto_block.py`, `remediation_engine.py`, and server-to-agent actions). This
module is the policy/orchestration layer: it decides what should happen for a
high-risk event and executes safely. Destructive execution is dry-run by
default and must be explicitly enabled by the caller/environment.
"""

from __future__ import annotations

import ipaddress
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


SAFE_LOCAL_IPS = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
}


@dataclass
class ActiveDefensePolicy:
    auto_response_threshold: int = 80
    destructive_enabled: bool = False
    allow_process_kill_auto: bool = False
    allow_user_disable_auto: bool = False
    allow_host_quarantine_auto: bool = False

    @classmethod
    def from_env(cls) -> "ActiveDefensePolicy":
        enabled = os.environ.get("NETGUARD_ACTIVE_RESPONSE_ENABLED", "false").lower() == "true"
        return cls(
            auto_response_threshold=int(os.environ.get("NETGUARD_ACTIVE_RESPONSE_THRESHOLD", "80")),
            destructive_enabled=enabled,
            allow_process_kill_auto=os.environ.get("NETGUARD_AUTO_KILL_PROCESS", "false").lower() == "true",
            allow_user_disable_auto=os.environ.get("NETGUARD_AUTO_DISABLE_USER", "false").lower() == "true",
            allow_host_quarantine_auto=os.environ.get("NETGUARD_AUTO_QUARANTINE_HOST", "false").lower() == "true",
        )


@dataclass
class ResponseAction:
    action_type: str
    target: str
    reason: str
    risk_score: int
    automatic: bool = True
    requires_approval: bool = True
    simulated: bool = True
    parameters: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "action_type": self.action_type,
            "target": self.target,
            "reason": self.reason,
            "risk_score": self.risk_score,
            "automatic": self.automatic,
            "requires_approval": self.requires_approval,
            "simulated": self.simulated,
            "parameters": self.parameters,
        }


@dataclass
class ResponseResult:
    ok: bool
    action: ResponseAction
    status: str
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0).isoformat())

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "status": self.status,
            "detail": self.detail,
            "timestamp": self.timestamp,
            "action": self.action.to_dict(),
        }


class ActiveDefenseEngine:
    """Plan and optionally execute high-risk endpoint response actions."""

    def __init__(
        self,
        *,
        policy: Optional[ActiveDefensePolicy] = None,
        dry_run: bool = True,
        auto_block_engine=None,
        remediation_engine=None,
    ):
        self.policy = policy or ActiveDefensePolicy.from_env()
        self.dry_run = bool(dry_run or not self.policy.destructive_enabled)
        self.auto_block_engine = auto_block_engine
        self.remediation_engine = remediation_engine
        self._history: deque[dict] = deque(maxlen=500)

    def plan(
        self,
        event: dict,
        *,
        risk_score: int,
        killchain_stage: str = "",
        threat_intel_score: int = 0,
    ) -> list[ResponseAction]:
        try:
            risk = int(risk_score)
        except (TypeError, ValueError):
            risk = 0
        if risk <= self.policy.auto_response_threshold:
            return []

        stage = (killchain_stage or event.get("killchain_stage") or "").lower()
        actions: list[ResponseAction] = []
        reason = self._reason(event, risk, stage, threat_intel_score)

        source_ip = self._source_ip(event)
        if source_ip and self._can_block_ip(source_ip):
            actions.append(
                ResponseAction(
                    action_type="block_ip",
                    target=source_ip,
                    reason=reason,
                    risk_score=risk,
                    requires_approval=False,
                    simulated=self.dry_run,
                    parameters={"threat_intel_score": threat_intel_score},
                )
            )

        pid = event.get("pid")
        if pid and self._suspicious_process_event(event):
            actions.append(
                ResponseAction(
                    action_type="kill_process",
                    target=str(pid),
                    reason=reason,
                    risk_score=risk,
                    requires_approval=not self.policy.allow_process_kill_auto,
                    simulated=self.dry_run or not self.policy.allow_process_kill_auto,
                    parameters={"process_name": event.get("process_name") or event.get("process") or ""},
                )
            )

        user = event.get("user") or event.get("username")
        if user and stage in {"delivery", "command_and_control"} and risk >= 90:
            actions.append(
                ResponseAction(
                    action_type="disable_user",
                    target=str(user),
                    reason=reason,
                    risk_score=risk,
                    requires_approval=not self.policy.allow_user_disable_auto,
                    simulated=True,
                    parameters={"host_id": event.get("host_id") or ""},
                )
            )

        host_id = event.get("host_id")
        if host_id and stage in {"command_and_control", "actions_on_objectives"}:
            actions.append(
                ResponseAction(
                    action_type="quarantine_host",
                    target=str(host_id),
                    reason=reason,
                    risk_score=risk,
                    requires_approval=not self.policy.allow_host_quarantine_auto,
                    simulated=True,
                    parameters={"stage": stage},
                )
            )

        return self._dedupe(actions)

    def execute(self, action: ResponseAction) -> ResponseResult:
        if action.simulated or self.dry_run:
            return self._record(True, action, "simulated", "Dry-run active defense action.")

        if action.requires_approval:
            return self._record(False, action, "approval_required", "Action requires analyst approval.")

        if action.action_type == "block_ip":
            return self._execute_block_ip(action)
        if action.action_type == "kill_process":
            return self._execute_kill_process(action)

        # Disable user and host quarantine remain simulated until the project has
        # a domain/MDM control plane. This avoids dangerous local-only shortcuts.
        return self._record(True, action, "simulated", "No enterprise control plane configured for this action.")

    def handle_event(
        self,
        event: dict,
        *,
        risk_score: int,
        killchain_stage: str = "",
        threat_intel_score: int = 0,
        execute: bool = False,
    ) -> dict:
        actions = self.plan(
            event,
            risk_score=risk_score,
            killchain_stage=killchain_stage,
            threat_intel_score=threat_intel_score,
        )
        results = [self.execute(action).to_dict() for action in actions] if execute else []
        return {
            "ok": True,
            "dry_run": self.dry_run,
            "actions": [action.to_dict() for action in actions],
            "results": results,
        }

    def history(self, limit: int = 50) -> list[dict]:
        return list(self._history)[-limit:][::-1]

    def _execute_block_ip(self, action: ResponseAction) -> ResponseResult:
        if not self.auto_block_engine:
            return self._record(False, action, "unavailable", "AutoBlock engine is not configured.")
        record = self.auto_block_engine.block(
            action.target,
            action.risk_score,
            action.reason,
            host_id=str(action.parameters.get("host_id") or ""),
            rule_name="active_defense",
        )
        if not record:
            return self._record(False, action, "not_applied", "AutoBlock did not apply the block.")
        return self._record(True, action, "applied", "IP block requested through AutoBlock engine.")

    def _execute_kill_process(self, action: ResponseAction) -> ResponseResult:
        if not self.remediation_engine:
            return self._record(False, action, "unavailable", "Remediation engine is not configured.")
        result = self.remediation_engine.kill_process(
            int(action.target),
            reason=action.reason,
            operator="active-defense",
            auto=True,
        )
        ok = result.get("result") == "ok"
        return self._record(ok, action, "applied" if ok else "failed", str(result.get("detail") or result))

    def _record(self, ok: bool, action: ResponseAction, status: str, detail: str) -> ResponseResult:
        result = ResponseResult(ok=ok, action=action, status=status, detail=detail)
        self._history.append(result.to_dict())
        return result

    @staticmethod
    def _source_ip(event: dict) -> str:
        return str(event.get("source_ip") or event.get("src_ip") or event.get("auth_source_ip") or "").strip()

    @staticmethod
    def _can_block_ip(value: str) -> bool:
        if value in SAFE_LOCAL_IPS:
            return False
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (ip.is_loopback or ip.is_multicast or ip.is_unspecified)

    @staticmethod
    def _suspicious_process_event(event: dict) -> bool:
        text = f"{event.get('process_name') or event.get('process') or ''} {event.get('command_line') or ''}".lower()
        suspicious = ("powershell", "cmd.exe", "certutil", "mshta", "rundll32", "regsvr32")
        return any(token in text for token in suspicious)

    @staticmethod
    def _reason(event: dict, risk: int, stage: str, threat_intel_score: int) -> str:
        signal = event.get("rule_name") or event.get("event_type") or "high-risk endpoint event"
        stage_part = f", stage={stage}" if stage else ""
        ti_part = f", ti={threat_intel_score}" if threat_intel_score else ""
        return f"{signal}: risk={risk}{stage_part}{ti_part}"

    @staticmethod
    def _dedupe(actions: list[ResponseAction]) -> list[ResponseAction]:
        out: list[ResponseAction] = []
        seen: set[tuple[str, str]] = set()
        for action in actions:
            key = (action.action_type, action.target)
            if key not in seen:
                out.append(action)
                seen.add(key)
        return out


__all__ = [
    "ActiveDefenseEngine",
    "ActiveDefensePolicy",
    "ResponseAction",
    "ResponseResult",
]
