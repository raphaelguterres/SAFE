"""Enterprise behavioral detections for NetGuard XDR.

The engine only produces defensive findings. It does not execute response
actions and it avoids offensive memory/process behavior.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .schema import EndpointEvent
from .severity import normalize_severity


@dataclass(slots=True)
class BehavioralFinding:
    behavior_type: str
    severity: str
    confidence: float
    mitre_mapping: dict[str, str]
    evidence: str
    host_id: str
    recommended_action: str = "investigate"
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(max(0.0, min(1.0, float(self.confidence))), 2)
        return payload


class EnterpriseBehaviorEngine:
    """Small stateful detector for endpoint behavior patterns."""

    def __init__(self, *, burst_window_size: int = 40):
        self._recent_processes: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=burst_window_size))
        self._recent_network: dict[str, deque[dict[str, Any]]] = defaultdict(lambda: deque(maxlen=burst_window_size))

    def analyze(self, event: EndpointEvent) -> list[BehavioralFinding]:
        self._observe(event)
        findings: list[BehavioralFinding] = []
        findings.extend(self._script_and_lolbin_findings(event))
        findings.extend(self._process_relationship_findings(event))
        findings.extend(self._credential_access_findings(event))
        findings.extend(self._file_operation_findings(event))
        findings.extend(self._network_findings(event))
        findings.extend(self._persistence_findings(event))
        findings.extend(self._burst_findings(event))
        return _dedupe_findings(findings)

    def _observe(self, event: EndpointEvent) -> None:
        if event.event_type in {"process_execution", "script_execution"}:
            self._recent_processes[event.host_id].appendleft(
                {
                    "timestamp": event.timestamp,
                    "process_name": event.process_name,
                    "parent_process": event.parent_process,
                    "pid": event.pid,
                }
            )
        if event.event_type == "network_connection":
            self._recent_network[event.host_id].appendleft(
                {
                    "timestamp": event.timestamp,
                    "dst_ip": event.network_dst_ip,
                    "dst_port": event.network_dst_port,
                    "process_name": event.process_name,
                }
            )

    def _script_and_lolbin_findings(self, event: EndpointEvent) -> list[BehavioralFinding]:
        findings: list[BehavioralFinding] = []
        command = _lower(event.command_line)
        process = _lower(event.process_name)
        if "powershell" in process and any(token in command for token in ("-enc", "-encodedcommand", "frombase64string")):
            findings.append(
                _finding(
                    event,
                    "powershell_encoded_command",
                    "high",
                    0.9,
                    "execution",
                    "T1059.001",
                    "PowerShell encoded command-line pattern observed.",
                    "collect_diagnostics",
                )
            )

        lolbins = {
            "certutil": ("defense_evasion", "T1140"),
            "mshta": ("execution", "T1218.005"),
            "rundll32": ("defense_evasion", "T1218.011"),
            "regsvr32": ("defense_evasion", "T1218.010"),
            "bitsadmin": ("command_and_control", "T1197"),
            "wmic": ("execution", "T1047"),
        }
        for name, mapping in lolbins.items():
            if name in process or name in command:
                suspicious = any(token in command for token in ("http://", "https://", "javascript:", "scrobj", "/i:", "urlcache"))
                if suspicious:
                    findings.append(
                        _finding(
                            event,
                            "lolbin_abuse",
                            "high",
                            0.86,
                            mapping[0],
                            mapping[1],
                            f"Potential LOLBIN abuse observed via {name}.",
                            "investigate_process_tree",
                            {"lolbin": name},
                        )
                    )
        return findings

    def _process_relationship_findings(self, event: EndpointEvent) -> list[BehavioralFinding]:
        parent = _lower(event.parent_process)
        process = _lower(event.process_name)
        risky_children = {"powershell", "cmd", "wscript", "cscript", "mshta", "rundll32", "regsvr32"}
        risky_parents = {"winword", "excel", "powerpnt", "outlook", "chrome", "edge", "firefox", "teams"}
        findings: list[BehavioralFinding] = []
        if any(item in parent for item in risky_parents) and any(item in process for item in risky_children):
            findings.append(
                _finding(
                    event,
                    "suspicious_parent_child_process",
                    "high",
                    0.84,
                    "execution",
                    "T1204",
                    f"Suspicious parent/child chain: {event.parent_process or 'unknown'} -> {event.process_name or 'unknown'}.",
                    "investigate_process_tree",
                )
            )
        spawn_count = _int(event.details.get("spawn_count") or event.details.get("child_process_count"))
        if spawn_count >= 20 or "process_loop" in set(event.tags or []):
            findings.append(
                _finding(
                    event,
                    "process_spawning_loop",
                    "medium",
                    0.78,
                    "execution",
                    "T1059",
                    f"Process spawning loop indicator observed ({spawn_count} children).",
                    "collect_diagnostics",
                    {"spawn_count": spawn_count},
                )
            )
        return findings

    def _credential_access_findings(self, event: EndpointEvent) -> list[BehavioralFinding]:
        command = _lower(event.command_line)
        process = _lower(event.process_name)
        indicators = ("lsass", "sekurlsa", "procdump", "comsvcs.dll", "minidump", "nanodump")
        if any(token in command or token in process for token in indicators):
            return [
                _finding(
                    event,
                    "credential_dumping_indicator",
                    "critical",
                    0.92,
                    "credential_access",
                    "T1003",
                    "Credential dumping indicator observed in process telemetry.",
                    "open_incident_and_collect_diagnostics",
                )
            ]
        return []

    def _file_operation_findings(self, event: EndpointEvent) -> list[BehavioralFinding]:
        details = event.details or {}
        file_ops = max(
            _int(details.get("renamed_files")),
            _int(details.get("deleted_files")),
            _int(details.get("file_operation_count")),
        )
        if event.event_type == "behavioral_anomaly" and (file_ops >= 100 or "mass_file_change" in set(event.tags or [])):
            return [
                _finding(
                    event,
                    "mass_file_rename_delete_burst",
                    "critical" if file_ops >= 500 else "high",
                    0.88,
                    "impact",
                    "T1486",
                    f"Mass file rename/delete burst observed ({file_ops} operations).",
                    "prepare_containment_approval",
                    {"file_operation_count": file_ops},
                )
            ]
        return []

    def _network_findings(self, event: EndpointEvent) -> list[BehavioralFinding]:
        findings: list[BehavioralFinding] = []
        details = event.details or {}
        if event.event_type != "network_connection":
            return findings
        repeated_dst = sum(1 for item in self._recent_network[event.host_id] if item.get("dst_ip") == event.network_dst_ip)
        possible_beacon = bool(details.get("possible_beaconing") or "beaconing" in set(event.tags or []))
        low_variance = _float(details.get("interval_variance")) <= 5.0 if details.get("interval_variance") is not None else False
        if possible_beacon or (repeated_dst >= 5 and low_variance):
            findings.append(
                _finding(
                    event,
                    "unusual_outbound_beaconing",
                    "high",
                    0.86,
                    "command_and_control",
                    "T1071",
                    f"Repeated outbound network pattern to {event.network_dst_ip or 'unknown destination'}.",
                    "investigate_related_ips",
                    {"repeated_destination_count": repeated_dst},
                )
            )
        return findings

    def _persistence_findings(self, event: EndpointEvent) -> list[BehavioralFinding]:
        command = _lower(event.command_line)
        if event.event_type == "persistence_indicator" or "schtasks /create" in command or "\\run" in command:
            method = event.persistence_method or ("scheduled_task" if "schtasks" in command else "registry_run_key")
            technique = "T1053.005" if method == "scheduled_task" else "T1547.001"
            return [
                _finding(
                    event,
                    "persistence_indicator",
                    "high",
                    0.82,
                    "persistence",
                    technique,
                    f"Persistence indicator observed: {method}.",
                    "review_persistence_artifact",
                    {"persistence_method": method},
                )
            ]
        return []

    def _burst_findings(self, event: EndpointEvent) -> list[BehavioralFinding]:
        if event.event_type not in {"process_execution", "script_execution"}:
            return []
        recent = self._recent_processes[event.host_id]
        if len(recent) >= 10:
            return [
                _finding(
                    event,
                    "execution_burst",
                    "medium",
                    0.7,
                    "execution",
                    "T1059",
                    f"Execution burst observed on host ({len(recent)} recent process events).",
                    "review_process_burst",
                    {"recent_process_events": len(recent)},
                )
            ]
        return []


def evaluate_behavior(event: EndpointEvent) -> list[BehavioralFinding]:
    return EnterpriseBehaviorEngine().analyze(event)


def _finding(
    event: EndpointEvent,
    behavior_type: str,
    severity: str,
    confidence: float,
    tactic: str,
    technique: str,
    evidence: str,
    recommended_action: str,
    details: dict[str, Any] | None = None,
) -> BehavioralFinding:
    return BehavioralFinding(
        behavior_type=behavior_type,
        severity=normalize_severity(severity, default="medium"),
        confidence=confidence,
        mitre_mapping={"tactic": tactic, "technique": technique},
        evidence=evidence[:400],
        host_id=event.host_id,
        recommended_action=recommended_action,
        details={k: v for k, v in (details or {}).items() if v not in (None, "", [], {})},
        timestamp=event.timestamp or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def _dedupe_findings(findings: list[BehavioralFinding]) -> list[BehavioralFinding]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[BehavioralFinding] = []
    for finding in findings:
        key = (finding.behavior_type, finding.host_id, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)
    return deduped


def _lower(value: Any) -> str:
    return str(value or "").lower()


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
