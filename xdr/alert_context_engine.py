"""Explainable alert contextualization for SAFE AI-assisted SOC workflows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterable

from .severity import normalize_severity


_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_OBJECTIVE_BY_STAGE = {
    "impact": "business_disruption",
    "exfiltration": "data_loss_or_exfiltration",
    "command_and_control": "remote_control",
    "lateral_movement": "environment_expansion",
    "credential_access": "credential_theft",
    "persistence": "foothold_persistence",
    "execution": "code_execution",
    "delivery": "initial_access",
}


@dataclass(slots=True)
class AlertContext:
    alert_summary: str
    likely_attack_stage: str
    likely_objective: str
    confidence: float
    business_impact: str
    affected_assets: list[str] = field(default_factory=list)
    recommended_investigation: list[str] = field(default_factory=list)
    recommended_response: list[str] = field(default_factory=list)
    false_positive_probability: float = 0.0
    risk_signals: list[str] = field(default_factory=list)
    severity: str = "low"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(_clamp_float(self.confidence), 2)
        payload["false_positive_probability"] = round(_clamp_float(self.false_positive_probability), 2)
        return payload


class AlertContextEngine:
    """Builds analyst-ready context without making automated response decisions."""

    def contextualize(
        self,
        *,
        detections: Iterable[Any] | None = None,
        correlations: Iterable[Any] | None = None,
        killchain_findings: Iterable[Any] | None = None,
        telemetry: Iterable[Any] | None = None,
        anomaly_findings: Iterable[Any] | None = None,
        threat_intel: Iterable[Any] | dict[str, Any] | None = None,
        process_graph: dict[str, Any] | None = None,
        persistence_indicators: Iterable[Any] | None = None,
        critical_assets: Iterable[str] | None = None,
    ) -> AlertContext:
        records = _records(detections, correlations, killchain_findings, telemetry, anomaly_findings, persistence_indicators)
        intel_records = _intel_records(threat_intel)
        severity = _max_severity(records)
        stage = _likely_stage(records)
        objective = _likely_objective(stage, records)
        assets = _affected_assets(records, critical_assets)
        signals = _risk_signals(records, intel_records, process_graph)
        confidence = _confidence(records, intel_records, signals)
        fp_probability = _false_positive_probability(records, severity, confidence, signals)
        impact = _business_impact(severity, stage, assets, critical_assets, intel_records)
        investigation = _recommended_investigation(stage, signals)
        response = _recommended_response(stage, severity, signals)

        summary = _alert_summary(severity, stage, objective, assets, signals)
        return AlertContext(
            alert_summary=summary,
            likely_attack_stage=stage,
            likely_objective=objective,
            confidence=confidence,
            business_impact=impact,
            affected_assets=assets,
            recommended_investigation=investigation,
            recommended_response=response,
            false_positive_probability=fp_probability,
            risk_signals=signals,
            severity=severity,
        )


def build_alert_context(**kwargs: Any) -> AlertContext:
    return AlertContextEngine().contextualize(**kwargs)


def _records(*groups: Iterable[Any] | None) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for group in groups:
        if not group:
            continue
        if isinstance(group, dict):
            output.append(_to_dict(group))
            continue
        for item in group:
            record = _to_dict(item)
            if record:
                output.append(record)
    return output


def _intel_records(value: Iterable[Any] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if not value:
        return []
    if isinstance(value, dict):
        if "matched" in value or "reputation" in value or "severity" in value:
            return [dict(value)]
        return [_to_dict(item) for item in value.values() if _to_dict(item)]
    return [_to_dict(item) for item in value if _to_dict(item)]


def _max_severity(records: list[dict[str, Any]]) -> str:
    current = "low"
    for record in records:
        severity = normalize_severity(record.get("severity"), default="low")
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[current]:
            current = severity
    return current


def _likely_stage(records: list[dict[str, Any]]) -> str:
    stage_order = [
        "impact",
        "exfiltration",
        "command_and_control",
        "lateral_movement",
        "credential_access",
        "privilege_escalation",
        "persistence",
        "defense_evasion",
        "execution",
        "delivery",
        "reconnaissance",
    ]
    text = _joined_text(records)
    for stage in stage_order:
        if stage in text or stage.replace("_", " ") in text:
            return stage
    if "powershell" in text or "process" in text:
        return "execution"
    if "network" in text or "beacon" in text:
        return "command_and_control"
    return "unknown"


def _likely_objective(stage: str, records: list[dict[str, Any]]) -> str:
    text = _joined_text(records)
    if "ransom" in text or "mass file" in text:
        return "business_disruption"
    if "credential" in text or "lsass" in text:
        return "credential_theft"
    return _OBJECTIVE_BY_STAGE.get(stage, "unknown")


def _affected_assets(records: list[dict[str, Any]], critical_assets: Iterable[str] | None) -> list[str]:
    critical = {str(item).strip() for item in (critical_assets or []) if str(item).strip()}
    assets: list[str] = []
    for record in records:
        candidate = str(record.get("host_id") or record.get("host") or record.get("asset") or "").strip()
        if candidate and candidate not in assets:
            assets.append(candidate)
    assets.sort(key=lambda item: (item not in critical, item))
    return assets[:20]


def _risk_signals(records: list[dict[str, Any]], intel_records: list[dict[str, Any]], process_graph: dict[str, Any] | None) -> list[str]:
    text = _joined_text(records)
    signals: list[str] = []
    checks = {
        "encoded_powershell": ("powershell" in text and ("-enc" in text or "encoded" in text)),
        "credential_access": ("credential" in text or "lsass" in text),
        "persistence": ("persistence" in text or "scheduled task" in text or "run key" in text),
        "beaconing": ("beacon" in text or "command_and_control" in text or "c2" in text),
        "lateral_movement": ("lateral" in text or "remote service" in text),
        "ransomware_or_impact": ("ransom" in text or "mass file" in text or "impact" in text),
    }
    for signal, enabled in checks.items():
        if enabled:
            signals.append(signal)
    if any(item.get("matched") or int(item.get("score") or 0) >= 50 for item in intel_records):
        signals.append("threat_intel_match")
    if process_graph and (process_graph.get("suspicious_edges") or process_graph.get("depth", 0) >= 3):
        signals.append("suspicious_process_graph")
    return list(dict.fromkeys(signals))


def _confidence(records: list[dict[str, Any]], intel_records: list[dict[str, Any]], signals: list[str]) -> float:
    candidates = []
    for record in records:
        try:
            candidates.append(float(record.get("confidence")))
        except (TypeError, ValueError):
            continue
    if candidates and max(candidates) > 1:
        candidates = [value / 100 for value in candidates]
    base = max(candidates, default=0.45 if records else 0.0)
    intel_boost = 0.12 if any(item.get("matched") or int(item.get("score") or 0) >= 50 for item in intel_records) else 0
    signal_boost = min(0.24, len(signals) * 0.06)
    return _clamp_float(base + intel_boost + signal_boost)


def _false_positive_probability(records: list[dict[str, Any]], severity: str, confidence: float, signals: list[str]) -> float:
    if severity == "critical" or {"credential_access", "ransomware_or_impact"} & set(signals):
        return min(0.25, max(0.02, 0.35 - confidence))
    weak_signal_penalty = 0.18 if not signals else 0
    low_confidence = max(0, 0.7 - confidence)
    raw = 0.15 + weak_signal_penalty + low_confidence
    if len(records) >= 3:
        raw -= 0.12
    return _clamp_float(raw)


def _business_impact(
    severity: str,
    stage: str,
    assets: list[str],
    critical_assets: Iterable[str] | None,
    intel_records: list[dict[str, Any]],
) -> str:
    critical = {str(item).strip() for item in (critical_assets or []) if str(item).strip()}
    critical_hit = any(asset in critical for asset in assets)
    intel_hit = any(item.get("matched") or int(item.get("score") or 0) >= 50 for item in intel_records)
    if severity == "critical" or stage in {"impact", "exfiltration"}:
        return "Potential business interruption or data exposure. Prioritize incident review."
    if critical_hit:
        return "A critical asset is involved. Validate scope and containment options before escalation."
    if severity == "high" or intel_hit:
        return "Elevated operational risk. Analyst triage should confirm affected assets and blast radius."
    return "Limited business impact visible. Continue investigation and monitor for progression."


def _recommended_investigation(stage: str, signals: list[str]) -> list[str]:
    steps = ["review_evidence_chain", "validate_affected_host", "compare_against_host_baseline"]
    if "suspicious_process_graph" in signals or stage == "execution":
        steps.append("inspect_process_tree")
    if "beaconing" in signals or stage == "command_and_control":
        steps.append("review_network_destinations")
    if "persistence" in signals:
        steps.append("inspect_persistence_locations")
    if "credential_access" in signals:
        steps.append("review_identity_activity")
    if "threat_intel_match" in signals:
        steps.append("pivot_on_iocs")
    return list(dict.fromkeys(steps))


def _recommended_response(stage: str, severity: str, signals: list[str]) -> list[str]:
    responses = ["collect_diagnostics"]
    if severity in {"high", "critical"}:
        responses.append("open_or_update_incident")
    if stage in {"command_and_control", "exfiltration"} or "beaconing" in signals:
        responses.append("prepare_network_containment_approval")
    if stage == "impact" or "ransomware_or_impact" in signals:
        responses.append("prepare_host_isolation_approval")
    if "credential_access" in signals:
        responses.append("recommend_credential_review")
    return list(dict.fromkeys(responses))


def _alert_summary(severity: str, stage: str, objective: str, assets: list[str], signals: list[str]) -> str:
    host_text = ", ".join(assets[:3]) if assets else "monitored assets"
    signal_text = ", ".join(signal.replace("_", " ") for signal in signals[:3]) or "security activity"
    return (
        f"{severity.title()} alert on {host_text}: {signal_text}. "
        f"Likely stage: {stage.replace('_', ' ')}; likely objective: {objective.replace('_', ' ')}."
    )


def _joined_text(records: list[dict[str, Any]]) -> str:
    pieces: list[str] = []
    for record in records:
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        for key in (
            "event_type",
            "alert_type",
            "rule_name",
            "summary",
            "description",
            "command_line",
            "cmdline",
            "tactic",
            "mitre_tactic",
            "stage",
            "killchain_stage",
            "process_name",
        ):
            pieces.append(str(record.get(key) or ""))
            pieces.append(str(details.get(key) or ""))
    return " ".join(pieces).lower()


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


def _clamp_float(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


__all__ = ["AlertContext", "AlertContextEngine", "build_alert_context"]
