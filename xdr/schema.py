"""Structured event schema for the NetGuard EDR/XDR layer."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from typing import Any

from models.event_model import make_event

from .severity import clamp_risk, max_severity, normalize_severity, risk_level

ALLOWED_EVENT_TYPES = {
    "process_execution",
    "script_execution",
    "authentication",
    "persistence_indicator",
    "network_connection",
    "behavioral_anomaly",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clean_text(value: Any, *, max_len: int = 512) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    return text[:max_len]


def _clean_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass
class EndpointEvent:
    host_id: str
    event_type: str
    severity: str
    timestamp: str
    source: str = "agent"
    event_id: str = field(default_factory=lambda: f"xdr_evt_{uuid.uuid4().hex}")
    platform: str = ""
    tenant_id: str = ""
    process_name: str = ""
    command_line: str = ""
    parent_process: str = ""
    grandparent_process: str = ""
    username: str = ""
    pid: int | None = None
    ppid: int | None = None
    process_guid: str = ""
    parent_guid: str = ""
    auth_result: str = ""
    auth_source_ip: str = ""
    persistence_target: str = ""
    persistence_method: str = ""
    network_dst_ip: str = ""
    network_dst_port: int | None = None
    network_direction: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "EndpointEvent":
        if not isinstance(payload, dict):
            raise ValueError("event payload must be an object")

        host_id = _clean_text(payload.get("host_id"), max_len=128)
        if not host_id:
            raise ValueError("host_id is required")

        event_type = _clean_text(payload.get("event_type"), max_len=64).lower().replace("-", "_").replace(" ", "_")
        if event_type not in ALLOWED_EVENT_TYPES:
            raise ValueError(f"unsupported event_type: {event_type or 'empty'}")

        timestamp = _clean_text(payload.get("timestamp"), max_len=64) or utc_now_iso()
        severity = normalize_severity(payload.get("severity"), default="medium")

        details = payload.get("details") or {}
        if not isinstance(details, dict):
            raise ValueError("details must be an object")

        tags = payload.get("tags") or []
        if not isinstance(tags, list):
            raise ValueError("tags must be a list")

        return cls(
            host_id=host_id,
            event_type=event_type,
            severity=severity,
            timestamp=timestamp,
            source=_clean_text(payload.get("source") or "agent", max_len=64).lower(),
            event_id=_clean_text(payload.get("event_id"), max_len=80) or f"xdr_evt_{uuid.uuid4().hex}",
            platform=_clean_text(payload.get("platform"), max_len=32).lower(),
            tenant_id=_clean_text(payload.get("tenant_id"), max_len=64),
            process_name=_clean_text(payload.get("process_name") or details.get("process_name"), max_len=128),
            command_line=_clean_text(payload.get("command_line") or details.get("command_line"), max_len=2048),
            parent_process=_clean_text(payload.get("parent_process") or details.get("parent_process"), max_len=128),
            grandparent_process=_clean_text(
                payload.get("grandparent_process") or details.get("grandparent_process"),
                max_len=128,
            ),
            username=_clean_text(payload.get("username"), max_len=128),
            pid=_clean_int(payload.get("pid") if payload.get("pid") is not None else details.get("pid")),
            ppid=_clean_int(payload.get("ppid") if payload.get("ppid") is not None else details.get("ppid")),
            process_guid=_clean_text(payload.get("process_guid") or details.get("process_guid"), max_len=128),
            parent_guid=_clean_text(payload.get("parent_guid") or details.get("parent_guid"), max_len=128),
            auth_result=_clean_text(payload.get("auth_result"), max_len=32).lower(),
            auth_source_ip=_clean_text(payload.get("auth_source_ip"), max_len=128),
            persistence_target=_clean_text(payload.get("persistence_target"), max_len=256),
            persistence_method=_clean_text(payload.get("persistence_method"), max_len=128),
            network_dst_ip=_clean_text(payload.get("network_dst_ip"), max_len=128),
            network_dst_port=_clean_int(payload.get("network_dst_port")),
            network_direction=_clean_text(payload.get("network_direction"), max_len=16).lower(),
            details=dict(details),
            tags=[_clean_text(tag, max_len=48).lower() for tag in tags if _clean_text(tag, max_len=48)],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_security_event(
        self,
        *,
        severity: str | None = None,
        rule_id: str = "",
        rule_name: str = "",
        event_type_override: str | None = None,
        mitre_tactic: str = "",
        mitre_technique: str = "",
        tags: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> Any:
        payload = self.to_dict()
        event_details = dict(payload["details"])
        event_details.update(
            {
                "process_name": self.process_name,
                "command_line": self.command_line,
                "parent_process": self.parent_process,
                "grandparent_process": self.grandparent_process,
                "username": self.username,
                "pid": self.pid,
                "ppid": self.ppid,
                "process_guid": self.process_guid,
                "parent_guid": self.parent_guid,
                "auth_result": self.auth_result,
                "auth_source_ip": self.auth_source_ip,
                "persistence_target": self.persistence_target,
                "persistence_method": self.persistence_method,
                "network_dst_ip": self.network_dst_ip,
                "network_dst_port": self.network_dst_port,
                "network_direction": self.network_direction,
                "platform": self.platform,
                "source_kind": self.source,
            }
        )
        if details:
            event_details.update(details)
        clean_tags = list(dict.fromkeys((self.tags or []) + (tags or [])))
        security_event = make_event(
            event_type=event_type_override or self.event_type,
            severity=(severity or self.severity).upper(),
            source=f"xdr.{self.source}",
            details={k: v for k, v in event_details.items() if v not in (None, "", [], {})},
            rule_id=rule_id,
            rule_name=rule_name,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            tags=clean_tags,
            raw=self.command_line or "",
        )
        security_event.host_id = self.host_id
        security_event.timestamp = self.timestamp or security_event.timestamp
        return security_event


@dataclass
class DetectionRecord:
    rule_id: str
    rule_name: str
    alert_type: str
    host_id: str
    process_name: str
    parent_process: str
    cmdline: str
    technique: str
    tactic: str
    severity: str
    summary: str
    confidence: float
    timestamp: str
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    related_events: list[dict[str, Any]] = field(default_factory=list)
    recommended_action: str = "investigate"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CorrelationRecord:
    rule_id: str
    rule_name: str
    alert_type: str
    host_id: str
    technique: str
    tactic: str
    severity: str
    summary: str
    confidence: float
    signal_count: int
    timestamp: str
    tags: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    related_events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResponseAction:
    action_type: str
    target: str
    automatic: bool
    requires_agent: bool
    reason: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineOutcome:
    event: EndpointEvent
    detections: list[DetectionRecord] = field(default_factory=list)
    correlations: list[CorrelationRecord] = field(default_factory=list)
    actions: list[ResponseAction] = field(default_factory=list)
    host_risk_score: int = 0
    behavioral_findings: list[Any] = field(default_factory=list)
    killchain_findings: list[Any] = field(default_factory=list)
    killchain_stage_summary: dict[str, Any] = field(default_factory=dict)
    attack_progression_score: int = 0
    host_defense_state: dict[str, Any] = field(default_factory=dict)

    @property
    def host_risk_level(self) -> str:
        return risk_level(self.host_risk_score)

    @property
    def highest_severity(self) -> str:
        values = [self.event.severity]
        values.extend(item.severity for item in self.detections)
        values.extend(item.severity for item in self.correlations)
        return max_severity(*values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "detections": [item.to_dict() for item in self.detections],
            "correlations": [item.to_dict() for item in self.correlations],
            "actions": [item.to_dict() for item in self.actions],
            "behavioral_findings": [_to_dict(item) for item in self.behavioral_findings],
            "killchain_findings": [_to_dict(item) for item in self.killchain_findings],
            "killchain_stage_summary": dict(self.killchain_stage_summary or {}),
            "attack_progression_score": clamp_risk(self.attack_progression_score),
            "host_defense_state": dict(self.host_defense_state or {}),
            "host_risk_score": clamp_risk(self.host_risk_score),
            "host_risk_level": self.host_risk_level,
            "highest_severity": self.highest_severity,
        }

    def to_security_events(self) -> list[Any]:
        events = [
            self.event.to_security_event(
                severity=self.highest_severity,
                rule_id="XDR-RAW",
                rule_name="Structured endpoint event",
                tags=["xdr", "endpoint", self.event.event_type],
                details={"host_risk_level": self.host_risk_level, "host_risk_score": self.host_risk_score},
            )
        ]
        for detection in self.detections:
            events.append(
                self.event.to_security_event(
                    severity=detection.severity,
                    rule_id=detection.rule_id,
                    rule_name=detection.rule_name,
                    event_type_override=detection.alert_type,
                    mitre_tactic=detection.tactic,
                    mitre_technique=detection.technique,
                    tags=["xdr", "detection"] + detection.tags,
                    details={
                        "alert_type": detection.alert_type,
                        "summary": detection.summary,
                        "confidence": detection.confidence,
                        "host_id": detection.host_id,
                        "process_name": detection.process_name,
                        "parent_process": detection.parent_process,
                        "cmdline": detection.cmdline,
                        "technique": detection.technique,
                        "tactic": detection.tactic,
                        "timestamp": detection.timestamp,
                        "recommended_action": detection.recommended_action,
                        "related_events": detection.related_events,
                        **detection.details,
                    },
                )
            )
        for correlation in self.correlations:
            events.append(
                self.event.to_security_event(
                    severity=correlation.severity,
                    rule_id=correlation.rule_id,
                    rule_name=correlation.rule_name,
                    event_type_override=correlation.alert_type,
                    mitre_tactic=correlation.tactic,
                    mitre_technique=correlation.technique,
                    tags=["xdr", "correlation"] + correlation.tags,
                    details={
                        "alert_type": correlation.alert_type,
                        "summary": correlation.summary,
                        "confidence": correlation.confidence,
                        "host_id": correlation.host_id,
                        "technique": correlation.technique,
                        "tactic": correlation.tactic,
                        "timestamp": correlation.timestamp,
                        "signal_count": correlation.signal_count,
                        "related_events": correlation.related_events,
                        **correlation.details,
                    },
                )
            )
        for behavior in self.behavioral_findings:
            behavior_dict = _to_dict(behavior)
            mapping = behavior_dict.get("mitre_mapping") or {}
            events.append(
                self.event.to_security_event(
                    severity=str(behavior_dict.get("severity") or self.highest_severity),
                    rule_id=f"XDR-BEH-{str(behavior_dict.get('behavior_type') or 'behavior').upper()}",
                    rule_name=str(behavior_dict.get("behavior_type") or "Behavioral Finding").replace("_", " ").title(),
                    event_type_override=str(behavior_dict.get("behavior_type") or "behavioral_finding"),
                    mitre_tactic=str(mapping.get("tactic") or ""),
                    mitre_technique=str(mapping.get("technique") or ""),
                    tags=["xdr", "behavioral", str(behavior_dict.get("behavior_type") or "behavior")],
                    details={
                        "behavior_type": behavior_dict.get("behavior_type"),
                        "confidence": behavior_dict.get("confidence"),
                        "evidence": behavior_dict.get("evidence"),
                        "recommended_action": behavior_dict.get("recommended_action"),
                        **dict(behavior_dict.get("details") or {}),
                    },
                )
            )
        for finding in self.killchain_findings:
            finding_dict = _to_dict(finding)
            stage = str(finding_dict.get("stage") or "killchain")
            events.append(
                self.event.to_security_event(
                    severity=self.highest_severity,
                    rule_id=f"XDR-KC-{stage.upper()}",
                    rule_name=f"Kill Chain: {stage.replace('_', ' ').title()}",
                    event_type_override=f"killchain_{stage}",
                    mitre_tactic=str(finding_dict.get("mitre_tactic") or stage),
                    mitre_technique=str(finding_dict.get("mitre_technique") or ""),
                    tags=["xdr", "killchain", stage],
                    details={
                        "stage": stage,
                        "confidence": finding_dict.get("confidence"),
                        "evidence": finding_dict.get("evidence"),
                        "recommended_response": finding_dict.get("recommended_response"),
                        "risk_modifier": finding_dict.get("risk_modifier"),
                        "attack_progression_score": self.attack_progression_score,
                        "stage_summary": self.killchain_stage_summary,
                    },
                )
            )
        for action in self.actions:
            events.append(
                self.event.to_security_event(
                    severity=self.highest_severity,
                    rule_id=f"XDR-RESP-{action.action_type.upper()}",
                    rule_name=action.action_type.replace("_", " ").title(),
                    event_type_override=action.action_type,
                    tags=["xdr", "response", action.action_type],
                    details={
                        "action_type": action.action_type,
                        "target": action.target,
                        "automatic": action.automatic,
                        "requires_agent": action.requires_agent,
                        "reason": action.reason,
                        "parameters": action.parameters,
                    },
                )
            )
        if self.host_defense_state:
            events.append(
                self.event.to_security_event(
                    severity=self.highest_severity,
                    rule_id="XDR-HOST-DEFENSE-STATE",
                    rule_name="Host Defense State",
                    event_type_override="host_defense_state",
                    tags=["xdr", "host_defense", str(self.host_defense_state.get("state") or "monitored")],
                    details=dict(self.host_defense_state or {}),
                )
            )
        return events


def _to_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return result if isinstance(result, dict) else {}
    if is_dataclass(item):
        return asdict(item)
    if hasattr(item, "__dict__"):
        return dict(getattr(item, "__dict__", {}))
    return {}


def parse_endpoint_events(payload: dict[str, Any] | list[Any]) -> list[EndpointEvent]:
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and isinstance(payload.get("events"), list):
        items = payload["events"]
    else:
        items = [payload]
    if not items:
        raise ValueError("events payload cannot be empty")
    return [EndpointEvent.from_payload(item) for item in items]
