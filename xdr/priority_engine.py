"""Telemetry priority classification for the scalable XDR ingest path.

The priority engine is intentionally deterministic and dependency-free.  It
does not replace detections; it decides which telemetry deserves scarce queue
capacity first when the platform is under pressure.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class TelemetryPriority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"

    @property
    def rank(self) -> int:
        return {"P0": 0, "P1": 1, "P2": 2, "P3": 3}[self.value]


@dataclass(frozen=True, slots=True)
class PriorityDecision:
    priority: TelemetryPriority
    category: str
    reason: str
    score: int

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["priority"] = self.priority.value
        return payload


class TelemetryPriorityEngine:
    """Classify endpoint telemetry into P0..P3 processing lanes."""

    P0_KEYWORDS = {
        "credential_access",
        "credential_dumping",
        "privilege_escalation",
        "ransomware",
        "impact",
        "lsass",
        "procdump",
        "comsvcs.dll",
        "ntds.dit",
        "vssadmin delete shadows",
        "bcdedit /set",
        "wevtutil cl",
    }
    P1_KEYWORDS = {
        "persistence",
        "encoded_command",
        "powershell -enc",
        "powershell.exe -enc",
        "beaconing",
        "command_and_control",
        "c2",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "schtasks",
        "run key",
    }
    P2_KEYWORDS = {
        "anomaly",
        "behavioral_anomaly",
        "rare_process",
        "unusual",
        "suspicious",
        "burst",
    }

    def classify(self, event: Any) -> PriorityDecision:
        severity = _value(event, "severity").lower()
        event_type = _value(event, "event_type").lower()
        command = _value(event, "command_line").lower()
        process = _value(event, "process_name").lower()
        tactic = _value(event, "mitre_tactic").lower()
        technique = _value(event, "mitre_technique").lower()
        tags = " ".join(_list_value(event, "tags")).lower()
        details = _details_text(event)
        haystack = " ".join([severity, event_type, command, process, tactic, technique, tags, details])

        if severity == "critical" or _contains_any(haystack, self.P0_KEYWORDS):
            return PriorityDecision(
                priority=TelemetryPriority.P0,
                category="critical",
                reason="Credential access, privilege escalation, ransomware/impact, or critical severity.",
                score=100,
            )

        if severity == "high" or _contains_any(haystack, self.P1_KEYWORDS):
            return PriorityDecision(
                priority=TelemetryPriority.P1,
                category="security",
                reason="High-risk execution, persistence, beaconing, or LOLBIN activity.",
                score=75,
            )

        if severity == "medium" or event_type == "behavioral_anomaly" or _contains_any(haystack, self.P2_KEYWORDS):
            return PriorityDecision(
                priority=TelemetryPriority.P2,
                category="telemetry",
                reason="Behavioral anomaly or medium-priority security telemetry.",
                score=45,
            )

        return PriorityDecision(
            priority=TelemetryPriority.P3,
            category="debug",
            reason="Low-risk operational telemetry.",
            score=10,
        )


def _value(event: Any, name: str) -> str:
    if isinstance(event, dict):
        value = event.get(name)
        if value is None and isinstance(event.get("details"), dict):
            value = event["details"].get(name)
    else:
        value = getattr(event, name, None)
        details = getattr(event, "details", None)
        if value is None and isinstance(details, dict):
            value = details.get(name)
    return "" if value is None else str(value)


def _list_value(event: Any, name: str) -> list[str]:
    if isinstance(event, dict):
        value = event.get(name) or []
    else:
        value = getattr(event, name, None) or []
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if item not in (None, "")]


def _details_text(event: Any) -> str:
    details = event.get("details") if isinstance(event, dict) else getattr(event, "details", None)
    if not isinstance(details, dict):
        return ""
    return " ".join(str(value) for value in details.values() if value not in (None, "", [], {})).lower()


def _contains_any(value: str, keywords: set[str]) -> bool:
    return any(keyword in value for keyword in keywords)
