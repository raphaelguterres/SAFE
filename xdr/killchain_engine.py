"""Kill Chain and MITRE ATT&CK mapping for NetGuard XDR outcomes."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable

from .schema import CorrelationRecord, DetectionRecord, EndpointEvent
from .severity import clamp_risk, normalize_severity, severity_weight


class KillChainStage(str, Enum):
    RECONNAISSANCE = "reconnaissance"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


STAGE_ORDER: tuple[KillChainStage, ...] = tuple(KillChainStage)
_STAGE_INDEX = {stage: index for index, stage in enumerate(STAGE_ORDER)}


TACTIC_TO_STAGE: dict[str, KillChainStage] = {
    "reconnaissance": KillChainStage.RECONNAISSANCE,
    "initial_access": KillChainStage.DELIVERY,
    "delivery": KillChainStage.DELIVERY,
    "exploitation": KillChainStage.EXPLOITATION,
    "execution": KillChainStage.EXECUTION,
    "persistence": KillChainStage.PERSISTENCE,
    "privilege_escalation": KillChainStage.PRIVILEGE_ESCALATION,
    "defense_evasion": KillChainStage.DEFENSE_EVASION,
    "credential_access": KillChainStage.CREDENTIAL_ACCESS,
    "discovery": KillChainStage.DISCOVERY,
    "lateral_movement": KillChainStage.LATERAL_MOVEMENT,
    "command_and_control": KillChainStage.COMMAND_AND_CONTROL,
    "exfiltration": KillChainStage.EXFILTRATION,
    "impact": KillChainStage.IMPACT,
}


STAGE_RESPONSE = {
    KillChainStage.RECONNAISSANCE: "review_source_scope",
    KillChainStage.DELIVERY: "validate_initial_access_path",
    KillChainStage.EXPLOITATION: "collect_diagnostics",
    KillChainStage.EXECUTION: "investigate_process_tree",
    KillChainStage.PERSISTENCE: "review_persistence_artifact",
    KillChainStage.PRIVILEGE_ESCALATION: "escalate_to_senior_analyst",
    KillChainStage.DEFENSE_EVASION: "collect_diagnostics",
    KillChainStage.CREDENTIAL_ACCESS: "review_user_session",
    KillChainStage.DISCOVERY: "inspect_host_activity",
    KillChainStage.LATERAL_MOVEMENT: "validate_lateral_movement_scope",
    KillChainStage.COMMAND_AND_CONTROL: "consider_network_containment",
    KillChainStage.EXFILTRATION: "contain_and_preserve_evidence",
    KillChainStage.IMPACT: "declare_incident_and_contain",
}


@dataclass(slots=True)
class KillChainFinding:
    stage: KillChainStage
    mitre_tactic: str
    mitre_technique: str
    confidence: float
    evidence: str
    recommended_response: str
    risk_modifier: int
    source: str = "event"
    rule_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["stage"] = self.stage.value
        payload["confidence"] = round(float(self.confidence), 2)
        return payload


class KillChainEngine:
    """Maps endpoint telemetry, detections, and correlations into attack stages."""

    def map_event_to_killchain(
        self,
        event: EndpointEvent,
        detections: list[DetectionRecord] | None = None,
        correlations: list[CorrelationRecord] | None = None,
    ) -> list[KillChainFinding]:
        findings: list[KillChainFinding] = []
        findings.extend(_event_findings(event))
        findings.extend(_record_findings(detections or [], source="detection"))
        findings.extend(_record_findings(correlations or [], source="correlation"))
        return _dedupe_findings(findings)

    def stage_summary(self, findings: list[KillChainFinding]) -> dict[str, Any]:
        return summarize_killchain(findings)

    def attack_progression_score(self, findings: list[KillChainFinding]) -> int:
        return attack_progression_score(findings)


def map_event_to_killchain(
    event: EndpointEvent,
    detections: list[DetectionRecord] | None = None,
    correlations: list[CorrelationRecord] | None = None,
) -> list[KillChainFinding]:
    return KillChainEngine().map_event_to_killchain(event, detections, correlations)


def summarize_killchain(findings: list[KillChainFinding]) -> dict[str, Any]:
    if not findings:
        return {
            "active_stages": [],
            "stage_counts": {},
            "highest_stage": "",
            "progression_score": 0,
            "recommended_responses": [],
        }

    counts = Counter(finding.stage.value for finding in findings)
    max_confidence: dict[str, float] = defaultdict(float)
    for finding in findings:
        max_confidence[finding.stage.value] = max(max_confidence[finding.stage.value], finding.confidence)

    ordered_stages = sorted(
        counts,
        key=lambda stage: _STAGE_INDEX.get(KillChainStage(stage), -1),
    )
    highest = max((finding.stage for finding in findings), key=lambda stage: _STAGE_INDEX[stage])
    responses = list(dict.fromkeys(finding.recommended_response for finding in findings if finding.recommended_response))
    return {
        "active_stages": [
            {
                "stage": stage,
                "count": counts[stage],
                "max_confidence": round(max_confidence[stage], 2),
            }
            for stage in ordered_stages
        ],
        "stage_counts": {stage: counts[stage] for stage in ordered_stages},
        "highest_stage": highest.value,
        "progression_score": attack_progression_score(findings),
        "recommended_responses": responses[:5],
    }


def attack_progression_score(findings: list[KillChainFinding]) -> int:
    if not findings:
        return 0
    highest_index = max(_STAGE_INDEX[finding.stage] for finding in findings)
    stage_component = int(((highest_index + 1) / len(STAGE_ORDER)) * 65)
    spread_component = min(20, len({finding.stage for finding in findings}) * 4)
    confidence_component = int(max(finding.confidence for finding in findings) * 10)
    risk_component = min(15, sum(max(0, finding.risk_modifier) for finding in findings) // 4)
    return clamp_risk(stage_component + spread_component + confidence_component + risk_component)


def _event_findings(event: EndpointEvent) -> list[KillChainFinding]:
    findings: list[KillChainFinding] = []
    command = (event.command_line or "").lower()
    tags = set(event.tags or [])
    details = dict(event.details or {})

    if event.event_type in {"process_execution", "script_execution"}:
        stage = KillChainStage.EXECUTION
        technique = "T1059" if event.event_type == "script_execution" else "T1204"
        if "powershell" in (event.process_name or "").lower():
            technique = "T1059.001"
        findings.append(
            _finding(
                stage=stage,
                technique=technique,
                confidence=0.55,
                evidence=f"{event.process_name or 'process'} execution observed",
                source="event",
                severity=event.severity,
            )
        )
        if any(token in command for token in ("-enc", "-encodedcommand", "frombase64string", "bypass")):
            findings.append(
                _finding(
                    stage=KillChainStage.DEFENSE_EVASION,
                    technique="T1027",
                    confidence=0.72,
                    evidence="encoded or obfuscated command-line pattern observed",
                    source="event",
                    severity=event.severity,
                )
            )

    if event.event_type == "persistence_indicator":
        findings.append(
            _finding(
                stage=KillChainStage.PERSISTENCE,
                technique=_persistence_technique(event),
                confidence=0.8,
                evidence=f"persistence indicator: {event.persistence_method or event.persistence_target or 'unknown'}",
                source="event",
                severity=event.severity,
            )
        )

    if event.event_type == "authentication":
        auth_result = (event.auth_result or "").lower()
        if auth_result == "failure" or {"bruteforce", "credential_abuse"} & tags:
            findings.append(
                _finding(
                    stage=KillChainStage.CREDENTIAL_ACCESS,
                    technique="T1110",
                    confidence=0.58 if auth_result == "failure" else 0.7,
                    evidence=f"authentication {auth_result or 'activity'} from {event.auth_source_ip or 'unknown source'}",
                    source="event",
                    severity=event.severity,
                )
            )

    if event.event_type == "network_connection":
        direction = (event.network_direction or "").lower()
        if direction == "outbound":
            confidence = 0.66 if event.network_dst_ip else 0.5
            if {"beaconing", "c2_suspected"} & tags or details.get("possible_beaconing"):
                confidence = 0.82
            findings.append(
                _finding(
                    stage=KillChainStage.COMMAND_AND_CONTROL,
                    technique="T1071",
                    confidence=confidence,
                    evidence=f"outbound connection to {event.network_dst_ip or 'unknown'}:{event.network_dst_port or ''}",
                    source="event",
                    severity=event.severity,
                )
            )

    if event.event_type == "behavioral_anomaly":
        findings.append(
            _finding(
                stage=KillChainStage.DISCOVERY,
                technique="T1082",
                confidence=0.5,
                evidence="host behavioral anomaly observed",
                source="event",
                severity=event.severity,
            )
        )
    return findings


def _record_findings(
    records: Iterable[DetectionRecord | CorrelationRecord],
    *,
    source: str,
) -> list[KillChainFinding]:
    findings: list[KillChainFinding] = []
    for record in records:
        tactic = _normalize_tactic(record.tactic)
        stage = TACTIC_TO_STAGE.get(tactic)
        if stage is None:
            stage = _stage_from_tags(record.tags, record.alert_type)
        if stage is None:
            continue
        findings.append(
            _finding(
                stage=stage,
                tactic=tactic or stage.value,
                technique=str(record.technique or ""),
                confidence=max(0.0, min(1.0, float(record.confidence or 0))),
                evidence=record.summary or record.rule_name,
                source=source,
                rule_id=record.rule_id,
                severity=record.severity,
                details={
                    "alert_type": record.alert_type,
                    "tags": list(record.tags or []),
                    "signal_count": getattr(record, "signal_count", None),
                },
            )
        )
        if _has_any(record.tags, {"encoded_command", "payload_obfuscation"}):
            findings.append(
                _finding(
                    stage=KillChainStage.DEFENSE_EVASION,
                    tactic="defense_evasion",
                    technique="T1027",
                    confidence=max(0.72, float(record.confidence or 0)),
                    evidence=record.summary or "encoded command behavior",
                    source=source,
                    rule_id=record.rule_id,
                    severity=record.severity,
                )
            )
    return findings


def _finding(
    *,
    stage: KillChainStage,
    technique: str,
    confidence: float,
    evidence: str,
    source: str,
    severity: str,
    tactic: str | None = None,
    rule_id: str = "",
    details: dict[str, Any] | None = None,
) -> KillChainFinding:
    normalized_severity = normalize_severity(severity, default="low")
    base = max(1, severity_weight(normalized_severity) // 6)
    progression_bonus = max(0, _STAGE_INDEX[stage] - 2) // 2
    return KillChainFinding(
        stage=stage,
        mitre_tactic=tactic or stage.value,
        mitre_technique=technique,
        confidence=round(max(0.0, min(1.0, float(confidence))), 2),
        evidence=(evidence or stage.value).strip()[:300],
        recommended_response=STAGE_RESPONSE[stage],
        risk_modifier=min(20, base + progression_bonus),
        source=source,
        rule_id=rule_id,
        details={k: v for k, v in (details or {}).items() if v not in (None, "", [], {})},
    )


def _normalize_tactic(value: str) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _stage_from_tags(tags: Iterable[str] | None, alert_type: str) -> KillChainStage | None:
    tagset = {str(tag or "").strip().lower() for tag in tags or []}
    alert = str(alert_type or "").strip().lower()
    if {"recon", "port_scan"} & tagset or "port_scan" in alert:
        return KillChainStage.RECONNAISSANCE
    if {"script_abuse", "process_tree", "execution_chain"} & tagset:
        return KillChainStage.EXECUTION
    if {"persistence", "persistence_chain"} & tagset:
        return KillChainStage.PERSISTENCE
    if {"auth_abuse", "bruteforce", "credential_abuse"} & tagset:
        return KillChainStage.CREDENTIAL_ACCESS
    if {"beaconing", "c2_suspected", "external_connection"} & tagset:
        return KillChainStage.COMMAND_AND_CONTROL
    if {"payload_obfuscation", "encoded_command"} & tagset:
        return KillChainStage.DEFENSE_EVASION
    if {"discovery", "network_scan"} & tagset:
        return KillChainStage.DISCOVERY
    return None


def _persistence_technique(event: EndpointEvent) -> str:
    method = (event.persistence_method or "").lower()
    if method == "registry_run_key":
        return "T1547.001"
    if method == "scheduled_task":
        return "T1053.005"
    if method == "service":
        return "T1543.003"
    return "T1547"


def _has_any(tags: Iterable[str] | None, candidates: set[str]) -> bool:
    return any(str(tag or "").strip().lower() in candidates for tag in tags or [])


def _dedupe_findings(findings: list[KillChainFinding]) -> list[KillChainFinding]:
    deduped: list[KillChainFinding] = []
    seen = set()
    for finding in findings:
        key = (finding.stage.value, finding.mitre_technique, finding.source, finding.rule_id, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped

