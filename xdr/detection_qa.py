"""Detection content QA for SAFE rule catalogs."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class DetectionQualityFinding:
    rule_id: str
    finding_type: str
    severity: str
    message: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class DetectionQualityReport:
    total_rules: int
    score: int
    findings: list[DetectionQualityFinding] = field(default_factory=list)
    noisy_rules: list[str] = field(default_factory=list)
    duplicate_rules: list[str] = field(default_factory=list)
    missing_mitre: list[str] = field(default_factory=list)
    invalid_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "score": self.score,
            "findings": [finding.to_dict() for finding in self.findings],
            "noisy_rules": list(self.noisy_rules),
            "duplicate_rules": list(self.duplicate_rules),
            "missing_mitre": list(self.missing_mitre),
            "invalid_rules": list(self.invalid_rules),
        }


class DetectionQAEngine:
    """Validate noisy, duplicate, invalid and low-confidence detection content."""

    def evaluate(self, rules: list[Mapping[str, Any]], *, telemetry_counts: Mapping[str, int] | None = None) -> DetectionQualityReport:
        telemetry_counts = telemetry_counts or {}
        findings: list[DetectionQualityFinding] = []
        rule_ids = Counter(str(rule.get("rule_id") or "") for rule in rules)
        signatures: dict[tuple[str, str, str], list[str]] = defaultdict(list)

        for rule in rules:
            rule_id = str(rule.get("rule_id") or "").strip()
            if not rule_id:
                findings.append(self._finding("", "invalid_rule", "high", "Rule is missing rule_id.", "Add a stable rule_id."))
                continue
            if rule_ids[rule_id] > 1:
                findings.append(self._finding(rule_id, "duplicate_rule_id", "high", "Duplicate rule_id detected.", "Keep rule identifiers globally unique."))

            mitre = rule.get("mitre") if isinstance(rule.get("mitre"), Mapping) else {}
            tactic = str(mitre.get("tactic") or "").strip()
            technique = str(mitre.get("technique") or "").strip()
            if not tactic or not technique:
                findings.append(self._finding(rule_id, "missing_mitre", "medium", "Rule is missing MITRE tactic or technique.", "Add ATT&CK metadata."))

            severity = str(rule.get("severity") or "").lower()
            if severity not in {"low", "medium", "high", "critical", "dynamic"}:
                findings.append(self._finding(rule_id, "invalid_severity", "medium", "Rule severity is invalid.", "Use low, medium, high, critical or dynamic."))

            event_types = tuple(sorted(str(item) for item in (rule.get("event_types") or [])))
            signature = (str(rule.get("alert_type") or ""), tactic, ",".join(event_types))
            signatures[signature].append(rule_id)

            if int(telemetry_counts.get(rule_id, 0)) >= 500 and severity in {"low", "medium", "dynamic"}:
                findings.append(self._finding(rule_id, "noisy_detection", "medium", "Rule has high event volume.", "Review tuning guidance and suppression logic."))

            confidence = rule.get("confidence_score") or rule.get("confidence")
            if confidence is not None:
                try:
                    confidence_value = float(confidence)
                    if confidence_value < 0.35:
                        findings.append(self._finding(rule_id, "low_confidence", "low", "Rule confidence is low.", "Add stronger match constraints or tuning guidance."))
                except (TypeError, ValueError):
                    findings.append(self._finding(rule_id, "invalid_confidence", "low", "Rule confidence is not numeric.", "Use a 0-1 confidence score."))

        for signature, ids in signatures.items():
            if len(ids) > 1 and signature[0]:
                for rule_id in ids:
                    findings.append(self._finding(rule_id, "overlapping_detection", "low", "Rule overlaps with another detection signature.", "Document dependency or consolidate."))

        invalid = sorted({item.rule_id for item in findings if item.finding_type.startswith("invalid")})
        missing = sorted({item.rule_id for item in findings if item.finding_type == "missing_mitre"})
        noisy = sorted({item.rule_id for item in findings if item.finding_type == "noisy_detection"})
        duplicates = sorted({item.rule_id for item in findings if "duplicate" in item.finding_type})
        penalty = sum({"high": 12, "medium": 7, "low": 3}.get(item.severity, 2) for item in findings)
        score = max(0, min(100, 100 - penalty))
        return DetectionQualityReport(
            total_rules=len(rules),
            score=score,
            findings=findings,
            noisy_rules=noisy,
            duplicate_rules=duplicates,
            missing_mitre=missing,
            invalid_rules=invalid,
        )

    def _finding(self, rule_id: str, finding_type: str, severity: str, message: str, recommendation: str) -> DetectionQualityFinding:
        return DetectionQualityFinding(rule_id, finding_type, severity, message, recommendation)
