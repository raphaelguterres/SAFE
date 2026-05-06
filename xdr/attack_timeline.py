"""Host attack timeline builder for SOC triage."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass
from typing import Any, Iterable

from .killchain_engine import KillChainFinding, KillChainStage, attack_progression_score, summarize_killchain


def build_attack_timeline(
    *,
    host_id: str,
    events: Iterable[Any] | None = None,
    detections: Iterable[Any] | None = None,
    correlations: Iterable[Any] | None = None,
    killchain_findings: Iterable[KillChainFinding | dict[str, Any]] | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    """Build a compact attack narrative for one endpoint host."""

    normalized_findings = [_normalize_finding(item) for item in (killchain_findings or [])]
    normalized_findings = [item for item in normalized_findings if item]
    timeline = _timeline_entries(events or [], detections or [], correlations or [], normalized_findings, limit=limit)
    summary = summarize_killchain(normalized_findings)
    active_stages = [item["stage"] for item in summary.get("active_stages", [])]
    highest_stage = str(summary.get("highest_stage") or "")
    progression = attack_progression_score(normalized_findings)
    return {
        "host_id": host_id,
        "active_stages": active_stages,
        "highest_stage": highest_stage,
        "progression_score": progression,
        "timeline": timeline,
        "likely_attack_story": _attack_story(active_stages, highest_stage),
        "recommended_next_action": _recommended_next_action(highest_stage, progression),
    }


def build_host_attack_timeline(
    host_id: str,
    recent_activity: Iterable[dict[str, Any]],
    *,
    limit: int = 50,
) -> dict[str, Any]:
    """Build a timeline from `PipelineOutcome.to_dict()` history records."""

    events: list[dict[str, Any]] = []
    detections: list[dict[str, Any]] = []
    correlations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for outcome in recent_activity:
        if not isinstance(outcome, dict):
            continue
        event = outcome.get("event")
        if isinstance(event, dict):
            events.append(event)
        detections.extend(item for item in outcome.get("detections") or [] if isinstance(item, dict))
        correlations.extend(item for item in outcome.get("correlations") or [] if isinstance(item, dict))
        findings.extend(item for item in outcome.get("killchain_findings") or [] if isinstance(item, dict))
    return build_attack_timeline(
        host_id=host_id,
        events=events,
        detections=detections,
        correlations=correlations,
        killchain_findings=findings,
        limit=limit,
    )


def _timeline_entries(
    events: Iterable[Any],
    detections: Iterable[Any],
    correlations: Iterable[Any],
    findings: list[KillChainFinding],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for event in events:
        item = _to_dict(event)
        entries.append(
            {
                "timestamp": item.get("timestamp", ""),
                "type": item.get("event_type", "event"),
                "stage": "",
                "severity": item.get("severity", "low"),
                "summary": _event_summary(item),
                "evidence": _first_non_empty(item.get("command_line"), item.get("process_name"), item.get("network_dst_ip")),
            }
        )
    for detection in detections:
        item = _to_dict(detection)
        entries.append(
            {
                "timestamp": item.get("timestamp", ""),
                "type": item.get("alert_type", "detection"),
                "stage": _stage_from_tactic(item.get("tactic", "")),
                "severity": item.get("severity", "medium"),
                "summary": item.get("summary") or item.get("rule_name", "Detection"),
                "evidence": _first_non_empty(item.get("cmdline"), item.get("process_name"), item.get("rule_id")),
            }
        )
    for correlation in correlations:
        item = _to_dict(correlation)
        entries.append(
            {
                "timestamp": item.get("timestamp", ""),
                "type": item.get("alert_type", "correlation"),
                "stage": _stage_from_tactic(item.get("tactic", "")),
                "severity": item.get("severity", "high"),
                "summary": item.get("summary") or item.get("rule_name", "Correlated alert"),
                "evidence": f"{item.get('signal_count', 0)} correlated signals",
            }
        )
    for finding in findings:
        entries.append(
            {
                "timestamp": "",
                "type": "killchain_finding",
                "stage": finding.stage.value,
                "severity": _severity_from_risk_modifier(finding.risk_modifier),
                "summary": f"Kill Chain stage: {finding.stage.value.replace('_', ' ')}",
                "evidence": finding.evidence,
                "recommended_response": finding.recommended_response,
            }
        )
    entries.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return entries[: max(1, min(int(limit), 100))]


def _normalize_finding(item: KillChainFinding | dict[str, Any]) -> KillChainFinding | None:
    if isinstance(item, KillChainFinding):
        return item
    if not isinstance(item, dict):
        return None
    try:
        stage = KillChainStage(str(item.get("stage") or ""))
    except ValueError:
        return None
    return KillChainFinding(
        stage=stage,
        mitre_tactic=str(item.get("mitre_tactic") or stage.value),
        mitre_technique=str(item.get("mitre_technique") or ""),
        confidence=float(item.get("confidence") or 0),
        evidence=str(item.get("evidence") or stage.value),
        recommended_response=str(item.get("recommended_response") or ""),
        risk_modifier=int(item.get("risk_modifier") or 0),
        source=str(item.get("source") or "event"),
        rule_id=str(item.get("rule_id") or ""),
        details=dict(item.get("details") or {}),
    )


def _attack_story(active_stages: list[str], highest_stage: str) -> str:
    if not active_stages:
        return "No active attack progression is visible for this host yet."
    labels = [stage.replace("_", " ") for stage in active_stages]
    if highest_stage in {"command_and_control", "exfiltration", "impact"}:
        return "Telemetry suggests a late-stage intrusion path: " + " -> ".join(labels) + "."
    if highest_stage in {"persistence", "privilege_escalation", "defense_evasion", "credential_access"}:
        return "Telemetry suggests post-execution activity requiring triage: " + " -> ".join(labels) + "."
    return "Telemetry shows early-stage activity: " + " -> ".join(labels) + "."


def _recommended_next_action(highest_stage: str, progression_score: int) -> str:
    if not highest_stage:
        return "Continue monitoring and wait for endpoint telemetry."
    if progression_score >= 85 or highest_stage in {"exfiltration", "impact"}:
        return "Open an incident, preserve evidence, and prepare containment approval."
    if highest_stage in {"command_and_control", "lateral_movement"}:
        return "Investigate related IPs and request network containment approval if confirmed."
    if highest_stage in {"persistence", "credential_access", "defense_evasion"}:
        return "Collect diagnostics and validate persistence, credentials, and suspicious processes."
    return "Review process lineage and enrich the host timeline."


def _stage_from_tactic(tactic: str) -> str:
    return str(tactic or "").strip().lower().replace(" ", "_").replace("-", "_")


def _event_summary(item: dict[str, Any]) -> str:
    event_type = str(item.get("event_type") or "event").replace("_", " ")
    host = str(item.get("host_id") or "host")
    return f"{event_type.title()} observed on {host}"


def _severity_from_risk_modifier(value: int) -> str:
    if value >= 14:
        return "critical"
    if value >= 8:
        return "high"
    if value >= 4:
        return "medium"
    return "low"


def _to_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    if is_dataclass(item):
        return asdict(item)
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        value = to_dict()
        return value if isinstance(value, dict) else {}
    return {}


def _first_non_empty(*values: Any) -> str:
    for value in values:
        if value not in (None, "", [], {}):
            return str(value)[:300]
    return ""

