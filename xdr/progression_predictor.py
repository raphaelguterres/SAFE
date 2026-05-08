"""Attack progression prediction for SAFE SOC."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable


@dataclass(slots=True)
class ProgressionPrediction:
    predicted_next_stage: str
    confidence: float
    recommended_prevention: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(max(0.0, min(1.0, self.confidence)), 2)
        return payload


class AttackProgressionPredictor:
    """Predicts likely next attack stage from current defensive evidence."""

    def predict(
        self,
        *,
        active_stages: Iterable[str] | None = None,
        behaviors: Iterable[str] | None = None,
        recent_detections: Iterable[Any] | None = None,
    ) -> ProgressionPrediction:
        stages = {str(item).strip().lower() for item in (active_stages or []) if str(item).strip()}
        signals = {str(item).strip().lower() for item in (behaviors or []) if str(item).strip()}
        text = " ".join(str(item).lower() for item in signals)
        for detection in recent_detections or []:
            if isinstance(detection, dict):
                text += " " + " ".join(str(value).lower() for value in detection.values() if isinstance(value, (str, int, float)))

        if {"persistence", "command_and_control"} <= stages or ("persistence" in text and "beacon" in text):
            return ProgressionPrediction(
                "credential_access",
                0.78,
                "review_identity_activity_and_collect_diagnostics",
                "Persistence plus beaconing often precedes credential access or operator expansion.",
            )
        if "lateral_movement" in stages or "lateral" in text:
            return ProgressionPrediction(
                "privilege_escalation",
                0.72,
                "review_privileged_sessions_and_limit_admin_paths",
                "Lateral movement commonly requires elevated privileges to expand access.",
            )
        if "credential_access" in stages:
            return ProgressionPrediction(
                "lateral_movement",
                0.7,
                "reset_or_monitor_exposed_credentials_and_hunt_peer_hosts",
                "Credential access increases probability of lateral movement.",
            )
        if "execution" in stages or "encoded_powershell" in text:
            return ProgressionPrediction(
                "persistence",
                0.58,
                "inspect_startup_locations_and_scheduled_tasks",
                "Script execution may be followed by persistence attempts.",
            )
        return ProgressionPrediction(
            "monitoring",
            0.35,
            "continue_monitoring_and_validate_telemetry_coverage",
            "Not enough progression evidence to predict a specific next stage.",
        )


def predict_progression(**kwargs: Any) -> ProgressionPrediction:
    return AttackProgressionPredictor().predict(**kwargs)


__all__ = ["AttackProgressionPredictor", "ProgressionPrediction", "predict_progression"]
