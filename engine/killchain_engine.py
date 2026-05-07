"""Cyber Kill Chain engine for SAFE EDR.

This module gives the product a first-class Lockheed-style kill chain API
without replacing the existing MITRE ATT&CK detection layer. It accepts raw
events, normalizes them into the canonical EDR event shape, infers one of the
six Lockheed phases, and emits higher-level correlation findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

from engine.kill_chain_lockheed import (
    PHASES,
    PHASE_INDEX,
    PHASE_LABELS,
    derive_host_state,
    map_tactic,
)


STAGE_ALIASES = {
    "recon": "reconnaissance",
    "reconnaissance": "reconnaissance",
    "delivery": "delivery",
    "initial_access": "delivery",
    "exploit": "exploitation",
    "exploitation": "exploitation",
    "execution": "exploitation",
    "installation": "installation",
    "install": "installation",
    "persistence": "installation",
    "c2": "command_and_control",
    "command_and_control": "command_and_control",
    "command and control": "command_and_control",
    "actions": "actions_on_objectives",
    "actions_on_objectives": "actions_on_objectives",
    "impact": "actions_on_objectives",
    "exfiltration": "actions_on_objectives",
}


EVENT_TYPE_TO_STAGE = {
    "port_scan": "reconnaissance",
    "network_scan": "reconnaissance",
    "host_discovery": "reconnaissance",
    "dns_lookup": "reconnaissance",
    "suspicious_dns": "delivery",
    "failed_login": "delivery",
    "auth_failure": "delivery",
    "payload_delivery": "delivery",
    "phishing": "delivery",
    "process_execution": "exploitation",
    "powershell_encoded": "exploitation",
    "exploit_attempt": "exploitation",
    "web_exploit": "exploitation",
    "persistence_attempt": "installation",
    "scheduled_task": "installation",
    "registry_run_key": "installation",
    "service_install": "installation",
    "c2_beacon": "command_and_control",
    "suspicious_connection": "command_and_control",
    "dns_tunnel": "command_and_control",
    "network_connection": "command_and_control",
    "lateral_movement": "actions_on_objectives",
    "data_collection": "actions_on_objectives",
    "exfiltration": "actions_on_objectives",
    "ransomware": "actions_on_objectives",
    "impact": "actions_on_objectives",
}

STAGE_TO_REPRESENTATIVE_MITRE = {
    "reconnaissance": "reconnaissance",
    "delivery": "initial_access",
    "exploitation": "execution",
    "installation": "persistence",
    "command_and_control": "command_and_control",
    "actions_on_objectives": "impact",
}


SEVERITY_CONFIDENCE_BONUS = {
    "critical": 25,
    "high": 18,
    "medium": 10,
    "low": 3,
    "info": 0,
}


@dataclass
class KillChainEvent:
    event_type: str
    source_ip: str = ""
    process: str = ""
    killchain_stage: Optional[str] = None
    confidence: int = 0
    host_id: str = "unknown"
    timestamp: str = ""
    evidence: str = ""
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "process": self.process,
            "killchain_stage": self.killchain_stage,
            "confidence": self.confidence,
            "host_id": self.host_id,
            "timestamp": self.timestamp,
            "evidence": self.evidence,
            "raw": self.raw,
        }


@dataclass
class KillChainCorrelation:
    rule_id: str
    title: str
    stage: str
    confidence: int
    severity: str
    signals: list[str]
    evidence: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "stage": self.stage,
            "stage_label": PHASE_LABELS[self.stage]["en"],
            "confidence": self.confidence,
            "severity": self.severity,
            "signals": self.signals,
            "evidence": self.evidence,
        }


@dataclass
class KillChainAnalysis:
    host_id: str
    events: list[KillChainEvent]
    correlations: list[KillChainCorrelation]
    lockheed_state: dict

    def to_dict(self) -> dict:
        # Keep the same top-level keys expected by the current Host Triage UI.
        out = dict(self.lockheed_state)
        out.update(
            {
                "host_id": self.host_id,
                "normalized_events": [event.to_dict() for event in self.events],
                "correlations": [item.to_dict() for item in self.correlations],
            }
        )
        return out


def normalize_stage(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    key = str(value).strip().lower().replace("-", "_")
    return STAGE_ALIASES.get(key)


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class KillChainEngine:
    """Normalize endpoint events and correlate them across kill chain stages."""

    def normalize_event(self, item: dict) -> KillChainEvent:
        if not isinstance(item, dict):
            item = {}
        event_type = str(item.get("event_type") or item.get("type") or "unknown").strip().lower()
        stage = self.infer_stage(item)
        confidence = self.estimate_confidence(item, stage)
        process = (
            item.get("process")
            or item.get("process_name")
            or item.get("image")
            or ""
        )
        source_ip = (
            item.get("source_ip")
            or item.get("src_ip")
            or item.get("auth_source_ip")
            or item.get("remote_ip")
            or ""
        )
        return KillChainEvent(
            event_type=event_type,
            source_ip=str(source_ip or ""),
            process=str(process or ""),
            killchain_stage=stage,
            confidence=confidence,
            host_id=str(item.get("host_id") or item.get("host") or "unknown"),
            timestamp=str(item.get("timestamp") or item.get("ts") or item.get("created_at") or _now_iso()),
            evidence=str(item.get("evidence") or item.get("summary") or item.get("rule_name") or ""),
            raw=dict(item),
        )

    def infer_stage(self, item: dict) -> Optional[str]:
        explicit = normalize_stage(item.get("killchain_stage") or item.get("stage"))
        if explicit:
            return explicit

        tactic = (
            item.get("mitre_tactic")
            or item.get("tactic")
            or (item.get("mitre") or {}).get("tactic")
        )
        mapped = map_tactic(tactic)
        if mapped:
            return mapped

        event_type = str(item.get("event_type") or item.get("type") or "").strip().lower()
        if event_type in EVENT_TYPE_TO_STAGE:
            return EVENT_TYPE_TO_STAGE[event_type]

        command = str(item.get("command_line") or item.get("cmdline") or "").lower()
        process = str(item.get("process_name") or item.get("process") or "").lower()
        text = f"{process} {command}"
        if "powershell" in text and (" -enc" in text or "encodedcommand" in text):
            return "exploitation"
        if any(token in text for token in ("certutil", "mshta", "rundll32", "regsvr32")):
            return "exploitation"
        if any(token in text for token in ("runonce", "schtasks", "startup", "new-service")):
            return "installation"
        if item.get("dst_ip") or item.get("network_dst_ip") or item.get("dst_port"):
            return "command_and_control"
        return None

    def estimate_confidence(self, item: dict, stage: Optional[str]) -> int:
        raw_conf = item.get("confidence")
        if raw_conf is not None:
            try:
                return max(0, min(100, int(raw_conf)))
            except (TypeError, ValueError):
                pass

        confidence = 35 if stage else 10
        severity = str(item.get("severity") or "low").strip().lower()
        confidence += SEVERITY_CONFIDENCE_BONUS.get(severity, 0)
        if item.get("mitre_tactic") or item.get("tactic") or item.get("mitre"):
            confidence += 15
        if item.get("evidence") or item.get("rule_name"):
            confidence += 8
        if item.get("source_ip") or item.get("src_ip") or item.get("dst_ip"):
            confidence += 5
        return max(0, min(100, confidence))

    def correlate(self, events: Iterable[KillChainEvent]) -> list[KillChainCorrelation]:
        normalized = list(events)
        signals = self._signals(normalized)
        findings: list[KillChainCorrelation] = []

        if {"port_scan", "suspicious_dns", "failed_login"}.issubset(signals):
            findings.append(
                KillChainCorrelation(
                    rule_id="KC-001",
                    title="Reconnaissance progressed toward delivery",
                    stage="delivery",
                    confidence=88,
                    severity="high",
                    signals=["port_scan", "suspicious_dns", "failed_login"],
                    evidence="Port scan, suspicious DNS, and failed logins occurred in the same analysis window.",
                )
            )

        if self._has_stage(normalized, "exploitation") and self._has_stage(normalized, "command_and_control"):
            findings.append(
                KillChainCorrelation(
                    rule_id="KC-002",
                    title="Execution followed by external communication",
                    stage="command_and_control",
                    confidence=84,
                    severity="high",
                    signals=["exploitation", "command_and_control"],
                    evidence="Execution-stage activity was followed by network communication.",
                )
            )

        if self._has_stage(normalized, "installation") and self._has_stage(normalized, "exploitation"):
            findings.append(
                KillChainCorrelation(
                    rule_id="KC-003",
                    title="Execution plus persistence indicates installation",
                    stage="installation",
                    confidence=82,
                    severity="high",
                    signals=["exploitation", "installation"],
                    evidence="Suspicious execution and persistence signals were both observed.",
                )
            )

        if self._has_stage(normalized, "command_and_control") and self._has_stage(normalized, "actions_on_objectives"):
            findings.append(
                KillChainCorrelation(
                    rule_id="KC-004",
                    title="C2 followed by objective-stage activity",
                    stage="actions_on_objectives",
                    confidence=92,
                    severity="critical",
                    signals=["command_and_control", "actions_on_objectives"],
                    evidence="Command-and-control activity co-occurred with lateral movement, collection, exfiltration, or impact.",
                )
            )

        return findings

    def analyze(self, items: Iterable[dict], *, host_id: str = "unknown") -> KillChainAnalysis:
        events = [self.normalize_event(item) for item in items if isinstance(item, dict)]
        for event in events:
            if event.host_id == "unknown" and host_id:
                event.host_id = host_id

        derived_inputs = []
        for event in events:
            raw = dict(event.raw)
            if event.killchain_stage:
                raw["killchain_stage"] = event.killchain_stage
            # Convert back to a representative MITRE tactic shape when possible
            # so the existing Lockheed serializer remains the single UI contract.
            if event.killchain_stage:
                raw.setdefault(
                    "tactic",
                    STAGE_TO_REPRESENTATIVE_MITRE.get(event.killchain_stage, event.killchain_stage),
                )
            raw.setdefault("timestamp", event.timestamp)
            raw.setdefault("id", raw.get("event_id") or raw.get("id"))
            derived_inputs.append(raw)

        correlations = self.correlate(events)
        for finding in correlations:
            derived_inputs.append(
                {
                    "tactic": finding.stage,
                    "timestamp": _now_iso(),
                    "id": finding.rule_id,
                    "event_type": "killchain_correlation",
                    "severity": finding.severity,
                    "tactic": STAGE_TO_REPRESENTATIVE_MITRE.get(finding.stage, finding.stage),
                }
            )

        state = derive_host_state(host_id, derived_inputs).to_dict()
        return KillChainAnalysis(
            host_id=host_id,
            events=events,
            correlations=correlations,
            lockheed_state=state,
        )

    @staticmethod
    def _signals(events: Iterable[KillChainEvent]) -> set[str]:
        signals: set[str] = set()
        for event in events:
            signals.add(event.event_type)
            if event.killchain_stage:
                signals.add(event.killchain_stage)
            raw = event.raw
            rule = str(raw.get("rule_id") or raw.get("rule_name") or "").lower()
            if "dns" in rule:
                signals.add("suspicious_dns")
            if "brute" in rule or "failed" in rule:
                signals.add("failed_login")
            if "scan" in rule:
                signals.add("port_scan")
        return signals

    @staticmethod
    def _has_stage(events: Iterable[KillChainEvent], stage: str) -> bool:
        return any(event.killchain_stage == stage for event in events)


__all__ = [
    "PHASES",
    "PHASE_INDEX",
    "KillChainAnalysis",
    "KillChainCorrelation",
    "KillChainEngine",
    "KillChainEvent",
    "normalize_stage",
]
