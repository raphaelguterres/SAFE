"""Host protection state evaluation for SAFE Defense Core."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from typing import Any, Iterable

from .severity import clamp_risk, normalize_severity, severity_weight


class HostProtectionState(str, Enum):
    MONITORED = "monitored"
    SUSPICIOUS = "suspicious"
    ELEVATED_RISK = "elevated_risk"
    CONTAINED = "contained"
    ISOLATED = "isolated"
    RECOVERY_MODE = "recovery_mode"


@dataclass(slots=True)
class HostSecurityState:
    host_id: str
    state: HostProtectionState
    risk_score: int
    confidence: float
    active_attack_stages: list[str] = field(default_factory=list)
    active_incidents: int = 0
    recommended_actions: list[str] = field(default_factory=list)
    containment_recommended: bool = False
    isolation_recommended: bool = False
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["risk_score"] = clamp_risk(self.risk_score)
        payload["confidence"] = round(max(0.0, min(1.0, float(self.confidence))), 2)
        return payload


class HostDefenseEngine:
    """Combines detections, Kill Chain, response and behavior into a host state."""

    def evaluate_host_security_state(
        self,
        *,
        host_id: str,
        base_risk_score: int = 0,
        detections: Iterable[Any] | None = None,
        correlations: Iterable[Any] | None = None,
        killchain_findings: Iterable[Any] | None = None,
        threat_intel: Iterable[Any] | dict[str, Any] | None = None,
        response_actions: Iterable[Any] | None = None,
        behavioral_anomalies: Iterable[Any] | None = None,
        active_incidents: int = 0,
    ) -> HostSecurityState:
        evidence: list[str] = []
        confidence_values: list[float] = []
        stages: list[str] = []
        risk = clamp_risk(base_risk_score)

        for record in list(detections or []) + list(correlations or []):
            item = _to_dict(record)
            risk += max(1, severity_weight(normalize_severity(item.get("severity"), default="low")) // 4)
            confidence_values.append(_confidence(item.get("confidence")))
            summary = str(item.get("summary") or item.get("rule_name") or "").strip()
            if summary:
                evidence.append(summary[:180])

        for finding in killchain_findings or []:
            item = _to_dict(finding)
            stage = str(item.get("stage") or "").strip()
            if stage and stage not in stages:
                stages.append(stage)
            risk += max(0, int(item.get("risk_modifier") or 0))
            confidence_values.append(_confidence(item.get("confidence")))
            evidence_text = str(item.get("evidence") or "").strip()
            if evidence_text:
                evidence.append(evidence_text[:180])

        for behavior in behavioral_anomalies or []:
            item = _to_dict(behavior)
            risk += max(1, severity_weight(normalize_severity(item.get("severity"), default="medium")) // 3)
            confidence_values.append(_confidence(item.get("confidence")))
            mapping = item.get("mitre_mapping") or {}
            tactic = str(mapping.get("tactic") or "").strip()
            if tactic and tactic not in stages:
                stages.append(tactic)
            evidence_text = str(item.get("evidence") or item.get("behavior_type") or "").strip()
            if evidence_text:
                evidence.append(evidence_text[:180])

        ti_score = _threat_intel_score(threat_intel)
        if ti_score:
            risk += ti_score
            confidence_values.append(min(1.0, ti_score / 100))
            evidence.append(f"Threat intelligence risk contribution: {ti_score}")

        risk = clamp_risk(risk + max(0, active_incidents) * 8)
        state = _state_from_actions(response_actions or [], risk, active_incidents)
        if state == HostProtectionState.MONITORED:
            if risk >= 75:
                state = HostProtectionState.ELEVATED_RISK
            elif risk >= 25 or evidence:
                state = HostProtectionState.SUSPICIOUS

        late_stages = {"command_and_control", "lateral_movement", "exfiltration", "impact"}
        containment_recommended = bool(risk >= 75 or late_stages.intersection(stages))
        isolation_recommended = bool(risk >= 90 or {"exfiltration", "impact"}.intersection(stages))
        if state == HostProtectionState.SUSPICIOUS and containment_recommended and risk >= 60:
            state = HostProtectionState.ELEVATED_RISK
        recommended_actions = _recommended_actions(state, stages, containment_recommended, isolation_recommended)

        return HostSecurityState(
            host_id=str(host_id or ""),
            state=state,
            risk_score=risk,
            confidence=max(confidence_values, default=0.0),
            active_attack_stages=stages,
            active_incidents=max(0, int(active_incidents or 0)),
            recommended_actions=recommended_actions,
            containment_recommended=containment_recommended,
            isolation_recommended=isolation_recommended,
            evidence=list(dict.fromkeys(evidence))[:8],
        )


def evaluate_host_security_state(**kwargs: Any) -> HostSecurityState:
    return HostDefenseEngine().evaluate_host_security_state(**kwargs)


def _state_from_actions(actions: Iterable[Any], risk: int, active_incidents: int) -> HostProtectionState:
    statuses = []
    action_types = []
    for action in actions:
        item = _to_dict(action)
        statuses.append(str(item.get("status") or item.get("parameters", {}).get("response_queue_status") or "").lower())
        action_types.append(str(item.get("action_type") or "").lower())
    if any(action in {"safe_host_isolation", "isolate_host", "isolate_host_simulated"} for action in action_types):
        if any(status in {"succeeded", "executed", "approved"} for status in statuses):
            return HostProtectionState.ISOLATED
        if any(status in {"pending", "requires_approval", "leased", "running"} for status in statuses):
            return HostProtectionState.CONTAINED
    if any(status in {"succeeded", "executed"} for status in statuses) and risk < 40 and not active_incidents:
        return HostProtectionState.RECOVERY_MODE
    return HostProtectionState.MONITORED


def _recommended_actions(
    state: HostProtectionState,
    stages: list[str],
    containment_recommended: bool,
    isolation_recommended: bool,
) -> list[str]:
    actions = ["collect_diagnostics"]
    if "credential_access" in stages:
        actions.append("review_user_sessions")
    if "persistence" in stages:
        actions.append("review_persistence_artifacts")
    if "command_and_control" in stages:
        actions.append("investigate_related_network_indicators")
    if containment_recommended:
        actions.append("prepare_containment_approval")
    if isolation_recommended:
        actions.append("request_host_isolation_approval")
    if state in {HostProtectionState.ISOLATED, HostProtectionState.CONTAINED}:
        actions.append("prepare_rollback_plan")
    return list(dict.fromkeys(actions))


def _threat_intel_score(value: Iterable[Any] | dict[str, Any] | None) -> int:
    if not value:
        return 0
    if isinstance(value, dict):
        candidates = [value]
    else:
        candidates = [_to_dict(item) for item in value]
    score = 0
    for item in candidates:
        score += int(item.get("risk_score") or item.get("score") or 0)
    return min(25, max(0, score))


def _confidence(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if number > 1:
        number = number / 100.0
    return max(0.0, min(1.0, number))


def _to_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return result if isinstance(result, dict) else {}
    if is_dataclass(item):
        return asdict(item)
    return {}
