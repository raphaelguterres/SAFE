"""Response planning for SAFE XDR."""

from __future__ import annotations

from typing import Any

from .policy_engine import ResponseMode, ResponsePolicyEngine
from .schema import CorrelationRecord, DetectionRecord, EndpointEvent, ResponseAction
from .severity import max_severity


class ResponseEngine:
    """Produces response plans without requiring heavy orchestration."""

    def __init__(
        self,
        *,
        policy_engine: ResponsePolicyEngine | None = None,
        response_mode: str | ResponseMode = ResponseMode.MANUAL_APPROVAL,
    ):
        self.policy_engine = policy_engine or ResponsePolicyEngine(response_mode)

    def plan(
        self,
        event: EndpointEvent,
        detections: list[DetectionRecord],
        correlations: list[CorrelationRecord],
    ) -> list[ResponseAction]:
        actions: list[ResponseAction] = []
        highest = max_severity(
            event.severity,
            *(item.severity for item in detections),
            *(item.severity for item in correlations),
        )

        if highest in {"high", "critical"}:
            actions.append(
                ResponseAction(
                    action_type="generate_incident_ticket",
                    target=event.host_id,
                    automatic=True,
                    requires_agent=False,
                    reason="Create an incident record for SOC handling.",
                )
            )
            actions.append(
                ResponseAction(
                    action_type="tag_host_risk",
                    target=event.host_id,
                    automatic=True,
                    requires_agent=False,
                    reason="Update host risk level based on current signals.",
                    parameters={"risk_level": highest},
                )
            )

        if correlations:
            actions.append(
                ResponseAction(
                    action_type="escalate_alert",
                    target=event.host_id,
                    automatic=True,
                    requires_agent=False,
                    reason="Correlation engine raised a higher-confidence incident.",
                )
            )

        if event.pid and any(self._has_any_tag(item, {"script_abuse", "process_tree", "execution_chain"}) for item in detections):
            actions.append(
                ResponseAction(
                    action_type="kill_process",
                    target=str(event.pid),
                    automatic=False,
                    requires_agent=True,
                    reason="Endpoint should terminate the suspicious process if approved.",
                    parameters={"process_name": event.process_name},
                )
            )

        if event.command_line and any(self._has_any_tag(item, {"script_abuse", "encoded_command"}) for item in detections):
            actions.append(
                ResponseAction(
                    action_type="block_execution_pattern",
                    target=event.host_id,
                    automatic=False,
                    requires_agent=True,
                    reason="Endpoint should locally block the malicious command pattern.",
                    parameters={"pattern": event.command_line[:256]},
                )
            )

        if event.auth_source_ip and any(self._has_any_tag(item, {"auth_abuse", "bruteforce", "credential_abuse"}) for item in detections):
            actions.append(
                ResponseAction(
                    action_type="block_source_ip",
                    target=event.auth_source_ip,
                    automatic=False,
                    requires_agent=True,
                    reason="Repeated auth abuse warrants source blocking if policy allows.",
                )
            )

        deduped: list[ResponseAction] = []
        seen = set()
        for action in actions:
            key = (action.action_type, action.target)
            if key not in seen:
                deduped.append(action)
                seen.add(key)
        return [self._apply_policy(action, event, detections, correlations) for action in deduped]

    @staticmethod
    def _has_any_tag(record: DetectionRecord, candidates: set[str]) -> bool:
        return any(tag in candidates for tag in (record.tags or []))

    def _apply_policy(
        self,
        action: ResponseAction,
        event: EndpointEvent,
        detections: list[DetectionRecord],
        correlations: list[CorrelationRecord],
    ) -> ResponseAction:
        decision = self.policy_engine.decide(
            action.action_type,
            {
                "target": action.target,
                "host_id": event.host_id,
                "severity": max_severity(
                    event.severity,
                    *(item.severity for item in detections),
                    *(item.severity for item in correlations),
                ),
                "confidence": _max_confidence(detections, correlations),
            },
            confidence=_max_confidence(detections, correlations),
            evidence=_policy_evidence(action, event, detections, correlations),
        )
        params = dict(action.parameters or {})
        params["policy_decision"] = decision.to_dict()
        params["response_queue_status"] = _queue_status(decision)
        return ResponseAction(
            action_type=action.action_type,
            target=action.target,
            automatic=bool(action.automatic and decision.allowed and not decision.required_approval),
            requires_agent=action.requires_agent,
            reason=action.reason if decision.allowed else f"{action.reason} Policy: {decision.reason}",
            parameters=params,
        )


def _max_confidence(
    detections: list[DetectionRecord],
    correlations: list[CorrelationRecord],
) -> float:
    values = [float(item.confidence or 0) for item in [*detections, *correlations]]
    return max(values, default=0.0)


def _queue_status(decision: Any) -> str:
    if bool(getattr(decision, "allowed", False)) and not bool(getattr(decision, "required_approval", False)):
        return "approved"
    if bool(getattr(decision, "required_approval", False)):
        return "requires_approval"
    return "blocked"


def _policy_evidence(
    action: ResponseAction,
    event: EndpointEvent,
    detections: list[DetectionRecord],
    correlations: list[CorrelationRecord],
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "host_id": event.host_id,
        "process_name": event.process_name or action.parameters.get("process_name"),
        "pid": event.pid,
        "process_hash": (event.details or {}).get("process_hash") or (event.details or {}).get("sha256"),
        "ip": action.target if action.action_type in {"block_source_ip", "block_ip"} else "",
        "source_ip": event.auth_source_ip,
        "dst_ip": event.network_dst_ip,
        "path": (event.details or {}).get("path") or (event.details or {}).get("file_path"),
        "sha256": (event.details or {}).get("sha256") or (event.details or {}).get("file_hash"),
        "signature_checked": bool((event.details or {}).get("signature_checked")),
    }
    evidence["detections"] = [item.rule_id for item in detections]
    evidence["correlations"] = [item.rule_id for item in correlations]
    return {key: value for key, value in evidence.items() if value not in (None, "", [], {})}
