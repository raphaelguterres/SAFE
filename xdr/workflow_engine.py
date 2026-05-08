"""SOC analyst workflow definitions for SAFE case operations."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class WorkflowDefinition:
    workflow_id: str
    name: str
    checklist: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    recommended_actions: tuple[str, ...]
    escalation_rules: tuple[str, ...]
    rollback_guidance: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        for key in ("checklist", "evidence_requirements", "recommended_actions", "escalation_rules", "rollback_guidance"):
            payload[key] = list(payload[key])
        return payload


WORKFLOWS: dict[str, WorkflowDefinition] = {
    "triage": WorkflowDefinition(
        workflow_id="triage",
        name="Triage Workflow",
        checklist=("validate_alert", "identify_asset_owner", "review_recent_timeline", "assign_case_owner"),
        evidence_requirements=("alert_payload", "host_context", "timeline_snapshot"),
        recommended_actions=("collect_diagnostics", "open_case_if_needed"),
        escalation_rules=("escalate_if_critical_asset", "escalate_if_attack_progression_above_70"),
        rollback_guidance=("no_endpoint_change_expected",),
    ),
    "ransomware": WorkflowDefinition(
        workflow_id="ransomware",
        name="Ransomware Workflow",
        checklist=("confirm_mass_file_activity", "preserve_evidence", "identify_scope", "notify_incident_lead"),
        evidence_requirements=("file_operation_burst", "process_tree", "affected_paths", "backup_status"),
        recommended_actions=("collect_diagnostics", "prepare_host_isolation_approval", "verify_rollback_plan"),
        escalation_rules=("immediate_escalation", "leadership_notification", "legal_review_if_data_impact"),
        rollback_guidance=("rollback_isolation_after_clean_recovery", "document_reimage_or_restore_steps"),
    ),
    "credential_access": WorkflowDefinition(
        workflow_id="credential_access",
        name="Credential Access Workflow",
        checklist=("validate_identity_signal", "review_auth_logs", "scope_user_sessions", "identify_privileged_accounts"),
        evidence_requirements=("identity_events", "process_evidence", "source_ips", "affected_users"),
        recommended_actions=("collect_diagnostics", "recommend_credential_reset", "hunt_peer_hosts"),
        escalation_rules=("escalate_if_privileged_account", "escalate_if_lateral_movement"),
        rollback_guidance=("document_account_actions", "verify_access_restoration"),
    ),
    "persistence": WorkflowDefinition(
        workflow_id="persistence",
        name="Persistence Workflow",
        checklist=("identify_persistence_artifact", "verify_creation_actor", "compare_baseline", "document_removal_plan"),
        evidence_requirements=("scheduled_tasks", "services", "run_keys", "file_hashes"),
        recommended_actions=("collect_diagnostics", "persistence_review", "prepare_quarantine_approval_if_needed"),
        escalation_rules=("escalate_if_signed_binary_abuse", "escalate_if_admin_context"),
        rollback_guidance=("backup_artifact_before_remediation", "restore_if_false_positive"),
    ),
    "beaconing": WorkflowDefinition(
        workflow_id="beaconing",
        name="Beaconing Workflow",
        checklist=("validate_destination", "review_frequency", "pivot_on_ioc", "scope_hosts"),
        evidence_requirements=("network_connections", "dns_records", "process_owner", "ioc_reputation"),
        recommended_actions=("ioc_hunt", "prepare_block_ip_approval", "collect_diagnostics"),
        escalation_rules=("escalate_if_c2_reputation", "escalate_if_multiple_hosts"),
        rollback_guidance=("remove_block_after_validation", "document_allowed_business_destination"),
    ),
    "insider_threat": WorkflowDefinition(
        workflow_id="insider_threat",
        name="Insider Threat Workflow",
        checklist=("validate_user_context", "preserve_audit_logs", "review_data_access", "coordinate_with_hr_legal"),
        evidence_requirements=("user_activity", "data_access_logs", "endpoint_timeline", "case_notes"),
        recommended_actions=("monitor_user_activity", "collect_diagnostics", "escalate_to_authorized_owner"),
        escalation_rules=("need_to_know_only", "legal_or_hr_review_required"),
        rollback_guidance=("avoid_endpoint_disruption_without_approval",),
    ),
}


class AnalystWorkflowEngine:
    """Provides workflow guidance for cases and detections."""

    def get_workflow(self, workflow_id: str) -> WorkflowDefinition:
        workflow = WORKFLOWS.get(str(workflow_id or "").strip().lower())
        if not workflow:
            raise KeyError("workflow_not_found")
        return workflow

    def list_workflows(self) -> list[dict[str, Any]]:
        return [workflow.to_dict() for workflow in WORKFLOWS.values()]

    def recommend_workflow(self, *, severity: str = "", stage: str = "", behaviors: list[str] | None = None) -> WorkflowDefinition:
        text = " ".join([severity, stage, *(behaviors or [])]).lower()
        if any(token in text for token in ("ransom", "impact", "mass_file")):
            return WORKFLOWS["ransomware"]
        if "credential" in text or "lsass" in text:
            return WORKFLOWS["credential_access"]
        if "persistence" in text or "scheduled" in text:
            return WORKFLOWS["persistence"]
        if "beacon" in text or "command_and_control" in text or "c2" in text:
            return WORKFLOWS["beaconing"]
        if "insider" in text or "data_access" in text:
            return WORKFLOWS["insider_threat"]
        return WORKFLOWS["triage"]


__all__ = ["AnalystWorkflowEngine", "WorkflowDefinition", "WORKFLOWS"]
