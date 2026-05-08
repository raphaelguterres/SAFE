"""Human-in-the-loop investigation assistant for SAFE SOC."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .story_engine import StoryEngine


@dataclass(slots=True)
class InvestigationGuide:
    attack_summary: str
    likely_root_cause: str
    probable_attacker_behavior: list[str] = field(default_factory=list)
    suggested_next_steps: list[str] = field(default_factory=list)
    suggested_containment: list[str] = field(default_factory=list)
    evidence_checklist: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class InvestigationAssistant:
    """Generates defensive investigation guidance from existing SAFE signals."""

    def assist(
        self,
        *,
        events: Iterable[Any] | None = None,
        detections: Iterable[Any] | None = None,
        correlations: Iterable[Any] | None = None,
        killchain_findings: Iterable[Any] | None = None,
        host_id: str | None = None,
    ) -> InvestigationGuide:
        story = StoryEngine().build_story(
            events=events,
            detections=detections,
            correlations=correlations,
            killchain_findings=killchain_findings,
            host_id=host_id,
        )
        behaviors = list(story.evidence_tags or [])
        root_cause = _root_cause(behaviors, story.progression)
        return InvestigationGuide(
            attack_summary=story.summary,
            likely_root_cause=root_cause,
            probable_attacker_behavior=_attacker_behavior(behaviors, story.progression),
            suggested_next_steps=_next_steps(behaviors, story.progression),
            suggested_containment=_containment(behaviors, story.progression),
            evidence_checklist=_evidence_checklist(behaviors, story.progression),
        )


def build_investigation_guide(**kwargs: Any) -> InvestigationGuide:
    return InvestigationAssistant().assist(**kwargs)


def _root_cause(behaviors: list[str], progression: list[str]) -> str:
    if "office_to_powershell" in behaviors:
        return "user-opened document or collaboration payload leading to script execution"
    if "encoded_powershell" in behaviors:
        return "script execution with obfuscated command line"
    if "credential_access" in behaviors or "credential_access" in progression:
        return "identity or credential misuse should be validated"
    if "beaconing" in behaviors or "command_and_control" in progression:
        return "external command-and-control communication requires review"
    if "persistence_attempt" in behaviors or "persistence" in progression:
        return "persistence artifact created after initial execution"
    return "not enough evidence to determine root cause yet"


def _attacker_behavior(behaviors: list[str], progression: list[str]) -> list[str]:
    mapping = {
        "encoded_powershell": "obfuscated command execution",
        "office_to_powershell": "document-to-script execution chain",
        "persistence_attempt": "attempted foothold persistence",
        "beaconing": "periodic outbound communication",
        "credential_access": "possible credential harvesting",
        "lateral_movement": "attempted movement to additional hosts",
        "impact_behavior": "possible destructive or disruptive activity",
    }
    output = [mapping[item] for item in behaviors if item in mapping]
    output.extend(stage.replace("_", " ") for stage in progression if stage not in {"execution", "unknown"})
    return list(dict.fromkeys(output))[:8]


def _next_steps(behaviors: list[str], progression: list[str]) -> list[str]:
    steps = ["open_host_triage", "review_timeline", "validate_process_tree", "preserve_relevant_logs"]
    if "beaconing" in behaviors or "command_and_control" in progression:
        steps.append("pivot_on_network_indicators")
    if "credential_access" in behaviors or "credential_access" in progression:
        steps.append("review_user_sessions_and_identity_logs")
    if "persistence_attempt" in behaviors or "persistence" in progression:
        steps.append("review_startup_services_tasks_and_run_keys")
    if "impact_behavior" in behaviors or "impact" in progression:
        steps.append("escalate_incident_and_prepare_containment")
    return list(dict.fromkeys(steps))


def _containment(behaviors: list[str], progression: list[str]) -> list[str]:
    actions = ["collect_diagnostics"]
    if "beaconing" in behaviors or "command_and_control" in progression:
        actions.append("prepare_block_ip_approval")
    if "credential_access" in behaviors or "lateral_movement" in behaviors:
        actions.append("coordinate_credential_reset_review")
    if "impact_behavior" in behaviors or "impact" in progression:
        actions.append("prepare_host_isolation_approval")
    return list(dict.fromkeys(actions))


def _evidence_checklist(behaviors: list[str], progression: list[str]) -> list[str]:
    checklist = ["host_timeline", "raw_event_payload", "detection_rule", "analyst_notes"]
    if behaviors:
        checklist.append("behavioral_evidence")
    if progression:
        checklist.append("kill_chain_progression")
    if "beaconing" in behaviors or "command_and_control" in progression:
        checklist.append("network_connections")
    if "persistence_attempt" in behaviors or "persistence" in progression:
        checklist.append("persistence_artifacts")
    return list(dict.fromkeys(checklist))


__all__ = ["InvestigationAssistant", "InvestigationGuide", "build_investigation_guide"]
