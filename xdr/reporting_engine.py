"""Executive reporting structures for SAFE SOC operations."""

from __future__ import annotations

import csv
import io
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ExecutiveReport:
    title: str
    generated_at: str
    executive_summary: str
    incident_trends: dict[str, Any]
    top_attack_types: list[dict[str, Any]] = field(default_factory=list)
    posture_evolution: list[dict[str, Any]] = field(default_factory=list)
    critical_incidents: list[dict[str, Any]] = field(default_factory=list)
    response_effectiveness: dict[str, Any] = field(default_factory=dict)
    pdf_ready: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_csv(self) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=["section", "metric", "value"])
        writer.writeheader()
        writer.writerow({"section": "summary", "metric": "title", "value": self.title})
        writer.writerow({"section": "summary", "metric": "executive_summary", "value": self.executive_summary})
        for key, value in self.incident_trends.items():
            writer.writerow({"section": "incident_trends", "metric": key, "value": value})
        for key, value in self.response_effectiveness.items():
            writer.writerow({"section": "response_effectiveness", "metric": key, "value": value})
        return buffer.getvalue()


class ReportingEngine:
    def generate(
        self,
        *,
        generated_at: str,
        cases: list[dict[str, Any]] | None = None,
        metrics: dict[str, Any] | None = None,
        posture_history: list[dict[str, Any]] | None = None,
    ) -> ExecutiveReport:
        cases = list(cases or [])
        metrics = dict(metrics or {})
        critical = [case for case in cases if str(case.get("severity") or "").lower() == "critical"]
        attack_counts: dict[str, int] = {}
        for case in cases:
            for tactic in case.get("mitre_tactics") or ["unknown"]:
                attack_counts[str(tactic)] = attack_counts.get(str(tactic), 0) + 1
        top_attacks = [
            {"attack_type": key, "count": value}
            for key, value in sorted(attack_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        ]
        summary = (
            f"SAFE reviewed {len(cases)} cases with {len(critical)} critical case(s). "
            f"Unresolved criticals: {metrics.get('unresolved_criticals', 0)}."
        )
        return ExecutiveReport(
            title="SAFE SOC Executive Report",
            generated_at=generated_at,
            executive_summary=summary,
            incident_trends={
                "case_volume": len(cases),
                "open_cases": metrics.get("open_cases", 0),
                "false_positive_ratio": metrics.get("false_positive_ratio", 0),
            },
            top_attack_types=top_attacks,
            posture_evolution=list(posture_history or []),
            critical_incidents=critical[:20],
            response_effectiveness={
                "containment_success": metrics.get("containment_success", 0),
                "mttr_minutes": metrics.get("mttr_minutes", 0),
                "mttd_minutes": metrics.get("mttd_minutes", 0),
            },
            pdf_ready={
                "sections": ["summary", "trends", "critical_incidents", "response_effectiveness"],
                "layout": "executive",
            },
        )


__all__ = ["ExecutiveReport", "ReportingEngine"]
