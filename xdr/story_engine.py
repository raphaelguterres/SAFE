"""Investigation story engine for SAFE SOC workflows."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterable


@dataclass(slots=True)
class IncidentStory:
    summary: str
    progression: list[str] = field(default_factory=list)
    impacted_assets: list[str] = field(default_factory=list)
    likely_objective: str = "unknown"
    recommended_action: str = "continue_monitoring"
    evidence_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StoryEngine:
    """Converts technical endpoint signals into analyst-readable narrative."""

    def build_story(
        self,
        *,
        events: Iterable[Any] | None = None,
        detections: Iterable[Any] | None = None,
        correlations: Iterable[Any] | None = None,
        killchain_findings: Iterable[Any] | None = None,
        host_id: str | None = None,
    ) -> IncidentStory:
        records = [_to_dict(item) for item in (events or [])]
        records += [_to_dict(item) for item in (detections or [])]
        records += [_to_dict(item) for item in (correlations or [])]
        records += [_to_dict(item) for item in (killchain_findings or [])]
        records = [item for item in records if item]

        impacted_assets = _unique(
            str(item.get("host_id") or item.get("host") or host_id or "").strip()
            for item in records
            if str(item.get("host_id") or item.get("host") or host_id or "").strip()
        )
        stages = _ordered_stages(records)
        behaviors = _behavior_tags(records)
        primary_host = impacted_assets[0] if impacted_assets else (host_id or "the monitored host")
        likely_objective = _likely_objective(stages, behaviors)
        recommended_action = _recommended_action(stages, behaviors)
        summary = _summary(primary_host, stages, behaviors, likely_objective)

        return IncidentStory(
            summary=summary,
            progression=stages,
            impacted_assets=impacted_assets,
            likely_objective=likely_objective,
            recommended_action=recommended_action,
            evidence_tags=behaviors[:10],
        )


def build_incident_story(**kwargs: Any) -> IncidentStory:
    return StoryEngine().build_story(**kwargs)


def _summary(host: str, stages: list[str], behaviors: list[str], likely_objective: str) -> str:
    if not stages and not behaviors:
        return f"{host} has no clear attack story yet. SAFE is waiting for more endpoint telemetry."
    readable_stages = " -> ".join(stage.replace("_", " ") for stage in stages[:5])
    readable_behaviors = ", ".join(behavior.replace("_", " ") for behavior in behaviors[:4])
    if readable_stages and readable_behaviors:
        return (
            f"{host} shows {readable_behaviors}, progressing through {readable_stages}. "
            f"The likely objective is {likely_objective.replace('_', ' ')}."
        )
    if readable_stages:
        return (
            f"{host} shows attack progression through {readable_stages}. "
            f"The likely objective is {likely_objective.replace('_', ' ')}."
        )
    return (
        f"{host} shows {readable_behaviors}. "
        f"The likely objective is {likely_objective.replace('_', ' ')}."
    )


def _ordered_stages(records: list[dict[str, Any]]) -> list[str]:
    order = [
        "reconnaissance",
        "delivery",
        "exploitation",
        "execution",
        "persistence",
        "privilege_escalation",
        "defense_evasion",
        "credential_access",
        "discovery",
        "lateral_movement",
        "command_and_control",
        "exfiltration",
        "impact",
    ]
    found = set()
    for item in records:
        for key in ("stage", "killchain_stage", "mitre_tactic", "tactic"):
            value = _normalize_token(item.get(key))
            if value:
                found.add(value)
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        for key in ("stage", "killchain_stage", "mitre_tactic", "tactic"):
            value = _normalize_token(details.get(key))
            if value:
                found.add(value)
    return [stage for stage in order if stage in found] + sorted(found.difference(order))


def _behavior_tags(records: list[dict[str, Any]]) -> list[str]:
    tags: list[str] = []
    for item in records:
        details = item.get("details") if isinstance(item.get("details"), dict) else {}
        text = " ".join(
            str(value or "").lower()
            for value in (
                item.get("event_type"),
                item.get("alert_type"),
                item.get("rule_name"),
                item.get("summary"),
                item.get("command_line"),
                details.get("event_type"),
                details.get("alert_type"),
                details.get("summary"),
                details.get("command_line"),
                details.get("cmdline"),
                details.get("process_name"),
            )
        )
        if "powershell" in text and ("-enc" in text or "encoded" in text):
            tags.append("encoded_powershell")
        if "office" in text and "powershell" in text:
            tags.append("office_to_powershell")
        if "scheduled" in text or "run key" in text or "persistence" in text:
            tags.append("persistence_attempt")
        if "beacon" in text or "command_and_control" in text or "c2" in text:
            tags.append("beaconing")
        if "credential" in text or "lsass" in text:
            tags.append("credential_access")
        if "lateral" in text or "remote service" in text:
            tags.append("lateral_movement")
        if "ransom" in text or "mass file" in text or "impact" in text:
            tags.append("impact_behavior")
    return _unique(tags)


def _likely_objective(stages: list[str], behaviors: list[str]) -> str:
    if "impact" in stages or "impact_behavior" in behaviors:
        return "business_disruption"
    if "exfiltration" in stages:
        return "data_exfiltration"
    if "command_and_control" in stages or "beaconing" in behaviors:
        return "remote_control"
    if "credential_access" in stages or "credential_access" in behaviors:
        return "credential_theft"
    if "persistence" in stages or "persistence_attempt" in behaviors:
        return "foothold_persistence"
    return "early_intrusion_validation"


def _recommended_action(stages: list[str], behaviors: list[str]) -> str:
    if {"impact", "exfiltration"}.intersection(stages) or "impact_behavior" in behaviors:
        return "open_incident_and_prepare_containment"
    if "command_and_control" in stages or "beaconing" in behaviors:
        return "investigate_network_indicators_and_collect_diagnostics"
    if "credential_access" in stages or "credential_access" in behaviors:
        return "review_identity_activity_and_collect_diagnostics"
    if "persistence" in stages or "persistence_attempt" in behaviors:
        return "review_persistence_artifacts"
    if stages or behaviors:
        return "triage_host_and_validate_evidence"
    return "continue_monitoring"


def _normalize_token(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


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


def _unique(values: Iterable[str]) -> list[str]:
    output: list[str] = []
    seen = set()
    for value in values:
        if value and value not in seen:
            seen.add(value)
            output.append(value)
    return output
