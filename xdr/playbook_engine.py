"""AI-assisted playbook recommendation for SAFE SOC.

This module recommends defensive playbooks only. It never executes response
actions and marks containment recommendations as approval-gated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Iterable


@dataclass(slots=True)
class PlaybookRecommendation:
    playbook: str
    reason: str
    recommended_actions: list[str] = field(default_factory=list)
    requires_approval: bool = False
    destructive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PlaybookRecommendationEngine:
    """Maps context to safe human-approved response playbooks."""

    def recommend(
        self,
        *,
        stage: str = "",
        objective: str = "",
        behaviors: Iterable[str] | None = None,
        severity: str = "low",
    ) -> list[PlaybookRecommendation]:
        signals = {str(item).strip().lower() for item in (behaviors or []) if str(item).strip()}
        stage = str(stage or "").lower()
        objective = str(objective or "").lower()
        severity = str(severity or "low").lower()
        recs: list[PlaybookRecommendation] = [
            PlaybookRecommendation(
                "forensic_collection",
                "Collect diagnostics first to preserve evidence before making containment decisions.",
                ["collect_diagnostics", "preserve_timeline", "export_incident_context"],
                requires_approval=False,
            )
        ]
        if stage in {"command_and_control", "exfiltration"} or "beaconing" in signals:
            recs.append(
                PlaybookRecommendation(
                    "ioc_hunt",
                    "Network indicators should be pivoted across hosts before broad containment.",
                    ["hunt_iocs", "review_dns_and_connections", "prepare_block_ip_approval"],
                    requires_approval=True,
                )
            )
        if stage == "persistence" or "persistence_attempt" in signals:
            recs.append(
                PlaybookRecommendation(
                    "persistence_review",
                    "Persistence evidence requires startup, service and scheduled task review.",
                    ["review_services", "review_scheduled_tasks", "review_run_keys"],
                    requires_approval=False,
                )
            )
        if stage == "credential_access" or "credential_access" in signals:
            recs.append(
                PlaybookRecommendation(
                    "credential_reset_review",
                    "Credential access indicators require identity validation and reset planning.",
                    ["review_identity_logs", "prepare_credential_reset", "hunt_peer_sessions"],
                    requires_approval=True,
                )
            )
        if severity == "critical" or objective in {"business_disruption", "data_loss_or_exfiltration"}:
            recs.append(
                PlaybookRecommendation(
                    "host_isolation_review",
                    "Critical progression may justify containment, but isolation must remain approval-gated.",
                    ["prepare_host_isolation_approval", "notify_incident_lead", "confirm_rollback_plan"],
                    requires_approval=True,
                )
            )
        return recs


def recommend_playbooks(**kwargs: Any) -> list[PlaybookRecommendation]:
    return PlaybookRecommendationEngine().recommend(**kwargs)


__all__ = ["PlaybookRecommendation", "PlaybookRecommendationEngine", "recommend_playbooks"]
