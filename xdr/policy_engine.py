"""Policy decisions for safe NetGuard endpoint response."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


class ResponseMode(str, Enum):
    MONITOR_ONLY = "monitor_only"
    MANUAL_APPROVAL = "manual_approval"
    SEMI_AUTO = "semi_auto"
    FULL_AUTO_CONTAINMENT = "full_auto_containment"


SAFE_AUTOMATIC_ACTIONS = {"collect_diagnostics", "flush_buffer", "ping"}
SERVER_AUTOMATIC_ACTIONS = {"generate_incident_ticket", "tag_host_risk", "escalate_alert"}
APPROVAL_REQUIRED_ACTIONS = {
    "isolate_host",
    "isolate_host_simulated",
    "safe_host_isolation",
    "rollback_host_isolation",
    "kill_process",
    "kill_process_guarded",
}
APPROVAL_REQUIRED_ACTIONS.update({"block_execution_pattern"})
DISABLED_ACTIONS = {"delete_file", "delete_file_guarded"}


@dataclass(slots=True)
class ResponseDecision:
    action_type: str
    allowed: bool
    mode: str
    reason: str
    required_approval: bool
    safety_checks: list[str] = field(default_factory=list)
    expires_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ResponsePolicyEngine:
    """Decides whether a response action may run automatically or needs approval."""

    def __init__(self, mode: str | ResponseMode = ResponseMode.MANUAL_APPROVAL, *, ttl_seconds: int = 300):
        self.mode = _coerce_mode(mode)
        self.ttl_seconds = max(30, min(int(ttl_seconds), 900))

    def decide(
        self,
        action_type: str,
        context: dict[str, Any] | None = None,
        *,
        confidence: float | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> ResponseDecision:
        action = str(action_type or "").strip().lower()
        context = dict(context or {})
        evidence = dict(evidence or context.get("evidence") or {})
        confidence_value = _confidence(confidence if confidence is not None else context.get("confidence"))
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=self.ttl_seconds)).isoformat().replace("+00:00", "Z")

        if not action:
            return self._decision("", False, "missing_action_type", True, ["action_type_required"], expires_at)
        if action in DISABLED_ACTIONS:
            return self._decision(action, False, "delete_file is disabled by policy", True, ["destructive_delete_disabled"], expires_at)
        if self.mode == ResponseMode.MONITOR_ONLY:
            allowed = action in SAFE_AUTOMATIC_ACTIONS
            return self._decision(
                action,
                allowed,
                "monitor_only permits telemetry-only response actions" if allowed else "monitor_only blocks containment actions",
                not allowed,
                ["no_destructive_actions", "audit_required"],
                expires_at,
            )
        if action in SERVER_AUTOMATIC_ACTIONS:
            return self._decision(
                action,
                True,
                "server-side SOC orchestration action may run automatically",
                False,
                ["server_side_only", "audit_required", "no_endpoint_mutation"],
                expires_at,
            )
        if action in SAFE_AUTOMATIC_ACTIONS:
            return self._decision(
                action,
                True,
                "safe telemetry action may run automatically",
                False,
                ["audit_required", "no_system_modification"],
                expires_at,
            )
        if action in {"isolate_host", "isolate_host_simulated", "safe_host_isolation"}:
            return self._decision(
                action,
                self.mode == ResponseMode.FULL_AUTO_CONTAINMENT and confidence_value >= 0.95,
                "host isolation requires explicit approval unless full-auto high-confidence containment is enabled",
                not (self.mode == ResponseMode.FULL_AUTO_CONTAINMENT and confidence_value >= 0.95),
                ["signed_policy_required", "short_ttl_required", "rollback_required", "netguard_server_allowlist_required"],
                expires_at,
            )
        if action == "rollback_host_isolation":
            return self._decision(
                action,
                False,
                "isolation rollback is restorative but still requires explicit approval and audit",
                True,
                ["signed_policy_required", "audit_required", "netguard_owned_rules_only"],
                expires_at,
            )
        if action in {"kill_process", "kill_process_guarded"}:
            checks = ["signed_policy_required", "process_name_required", "pid_required", "protected_process_denylist"]
            has_process_evidence = bool(evidence.get("process_name") and (evidence.get("pid") or evidence.get("process_hash")))
            return self._decision(
                action,
                False,
                "process termination requires approval and process/hash evidence",
                True,
                checks if has_process_evidence else checks + ["missing_process_or_hash_evidence"],
                expires_at,
            )
        if action in {"block_ip", "block_source_ip", "block_ip_windows_firewall"}:
            checks = ["signed_policy_required", "valid_ip_required", "confidence_min_0_85"]
            valid = bool(evidence.get("ip") or evidence.get("dst_ip") or evidence.get("source_ip") or context.get("target"))
            high_confidence = confidence_value >= 0.85
            auto_allowed = self.mode in {ResponseMode.SEMI_AUTO, ResponseMode.FULL_AUTO_CONTAINMENT}
            return self._decision(
                action,
                bool(valid and high_confidence and auto_allowed),
                "IP blocking requires confidence >= 0.85 and policy-controlled automation",
                not bool(valid and high_confidence and auto_allowed),
                checks if valid else checks + ["missing_ip_evidence"],
                expires_at,
            )
        if action in {"quarantine_file", "quarantine_file_guarded"}:
            checks = ["signed_policy_required", "file_path_required", "sha256_required", "signature_or_origin_check_required"]
            has_file_evidence = bool(evidence.get("path") and (evidence.get("sha256") or evidence.get("hash")))
            has_safety = bool(evidence.get("signature_checked") or evidence.get("origin_checked"))
            auto_allowed = self.mode == ResponseMode.FULL_AUTO_CONTAINMENT and confidence_value >= 0.9
            return self._decision(
                action,
                bool(has_file_evidence and has_safety and auto_allowed),
                "file quarantine moves evidence to a safe folder and requires proof before automation",
                not bool(has_file_evidence and has_safety and auto_allowed),
                checks if has_file_evidence and has_safety else checks + ["missing_file_safety_evidence"],
                expires_at,
            )
        if action in APPROVAL_REQUIRED_ACTIONS:
            return self._decision(
                action,
                False,
                "guarded response action requires manual approval",
                True,
                ["signed_policy_required", "audit_required"],
                expires_at,
            )
        return self._decision(action, False, "unsupported response action", True, ["unsupported_action_type"], expires_at)

    def _decision(
        self,
        action_type: str,
        allowed: bool,
        reason: str,
        required_approval: bool,
        safety_checks: list[str],
        expires_at: str,
    ) -> ResponseDecision:
        return ResponseDecision(
            action_type=action_type,
            allowed=bool(allowed),
            mode=self.mode.value,
            reason=reason,
            required_approval=bool(required_approval),
            safety_checks=list(dict.fromkeys(safety_checks)),
            expires_at=expires_at,
        )


def decide_response_action(
    action_type: str,
    *,
    mode: str | ResponseMode = ResponseMode.MANUAL_APPROVAL,
    context: dict[str, Any] | None = None,
    confidence: float | None = None,
    evidence: dict[str, Any] | None = None,
) -> ResponseDecision:
    return ResponsePolicyEngine(mode).decide(action_type, context, confidence=confidence, evidence=evidence)


def _coerce_mode(value: str | ResponseMode) -> ResponseMode:
    if isinstance(value, ResponseMode):
        return value
    raw = str(value or "").strip().lower()
    try:
        return ResponseMode(raw)
    except ValueError:
        return ResponseMode.MANUAL_APPROVAL


def _confidence(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number > 1:
        number = number / 100.0
    return max(0.0, min(1.0, number))
