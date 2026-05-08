"""False-positive reduction for SAFE alerts.

Critical and credential/ransomware-like alerts are never hidden. This engine
only adds analyst context so humans can decide what to do next.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from typing import Any

from .severity import normalize_severity


@dataclass(slots=True)
class FalsePositiveAssessment:
    classification: str
    false_positive_probability: float
    reasons: list[str]
    analyst_action: str
    suppressible: bool = False
    preserve_alert: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["false_positive_probability"] = round(max(0.0, min(1.0, self.false_positive_probability)), 2)
        return payload


class FalsePositiveReductionEngine:
    """Classifies alert reliability using baseline and trust context."""

    def assess_alert(
        self,
        alert: Any,
        *,
        baseline: dict[str, Any] | None = None,
        historical_frequency: int = 0,
        signer_trust: str = "",
        hour_of_day: int | None = None,
        user_context: dict[str, Any] | None = None,
        organization_context: dict[str, Any] | None = None,
    ) -> FalsePositiveAssessment:
        record = _to_dict(alert)
        baseline = dict(baseline or {})
        user_context = dict(user_context or {})
        organization_context = dict(organization_context or {})
        severity = normalize_severity(record.get("severity"), default="low")
        text = _alert_text(record)
        reasons: list[str] = []
        probability = 0.35

        critical_signal = severity == "critical" or any(
            token in text
            for token in ("ransom", "credential", "lsass", "mimikatz", "impact", "mass file", "exfiltration")
        )
        if critical_signal:
            reasons.append("critical_or_high_consequence_signal_preserved")
            probability = 0.08

        if baseline.get("known_good_command") or baseline.get("known_admin_tool"):
            probability += 0.22
            reasons.append("matches_known_host_baseline")
        if historical_frequency >= 25 and severity in {"low", "medium"}:
            probability += 0.18
            reasons.append("high_historical_frequency_on_host")
        if str(signer_trust or "").lower() in {"trusted", "microsoft", "enterprise_trusted"}:
            probability += 0.16
            reasons.append("trusted_signer_context")
        if hour_of_day is not None and 8 <= int(hour_of_day) <= 18 and user_context.get("expected_admin_activity"):
            probability += 0.12
            reasons.append("expected_business_hours_admin_activity")
        if organization_context.get("maintenance_window"):
            probability += 0.12
            reasons.append("inside_declared_maintenance_window")

        if "encoded" in text or "-enc" in text or "beacon" in text or "persistence" in text:
            probability -= 0.18
            reasons.append("suspicious_behavior_reduces_benign_likelihood")
        if critical_signal:
            probability = min(probability, 0.25)

        probability = max(0.01, min(0.95, probability))
        classification = _classification(probability, critical_signal)
        suppressible = classification == "likely_benign" and not critical_signal
        action = {
            "likely_true_positive": "investigate_immediately",
            "suspicious": "triage_with_context",
            "low_confidence": "validate_against_baseline",
            "likely_benign": "document_and_consider_tuning",
        }[classification]
        return FalsePositiveAssessment(
            classification=classification,
            false_positive_probability=probability,
            reasons=reasons or ["insufficient_context"],
            analyst_action=action,
            suppressible=suppressible,
            preserve_alert=True,
        )


def reduce_false_positive(alert: Any, **kwargs: Any) -> FalsePositiveAssessment:
    return FalsePositiveReductionEngine().assess_alert(alert, **kwargs)


def _classification(probability: float, critical_signal: bool) -> str:
    if critical_signal or probability <= 0.25:
        return "likely_true_positive"
    if probability <= 0.45:
        return "suspicious"
    if probability <= 0.7:
        return "low_confidence"
    return "likely_benign"


def _alert_text(record: dict[str, Any]) -> str:
    details = record.get("details") if isinstance(record.get("details"), dict) else {}
    fields = ("event_type", "alert_type", "summary", "description", "command_line", "cmdline", "rule_name", "tactic")
    return " ".join(str(record.get(key) or details.get(key) or "") for key in fields).lower()


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


__all__ = ["FalsePositiveAssessment", "FalsePositiveReductionEngine", "reduce_false_positive"]
