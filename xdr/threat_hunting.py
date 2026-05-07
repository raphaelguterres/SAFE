"""Defensive threat hunting routines for NetGuard XDR."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterable


@dataclass(slots=True)
class HuntResult:
    hunt_name: str
    confidence: float
    affected_hosts: list[str]
    evidence: list[str] = field(default_factory=list)
    recommended_investigation: str = "review_timeline"

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(max(0.0, min(1.0, float(self.confidence))), 2)
        return payload


class ThreatHuntingEngine:
    """Runs lightweight hunts over recent XDR outcomes or raw events."""

    def run_hunts(self, records: Iterable[Any]) -> list[HuntResult]:
        events = [_event_from_record(item) for item in records]
        events = [item for item in events if item]
        results: list[HuntResult] = []
        results.extend(self._hunt_lateral_movement(events))
        results.extend(self._hunt_beaconing(events))
        results.extend(self._hunt_rare_processes(events))
        results.extend(self._hunt_uncommon_admin(events))
        results.extend(self._hunt_rare_domains(events))
        results.extend(self._hunt_auth_chains(events))
        return _dedupe_results(results)

    def _hunt_lateral_movement(self, events: list[dict[str, Any]]) -> list[HuntResult]:
        by_host: dict[str, list[str]] = defaultdict(list)
        lateral_ports = {22, 135, 139, 445, 3389, 5985, 5986}
        for event in events:
            if event.get("event_type") == "network_connection" and int(event.get("network_dst_port") or 0) in lateral_ports:
                by_host[str(event.get("host_id") or "")].append(str(event.get("network_dst_ip") or "unknown"))
        return [
            HuntResult(
                hunt_name="repeated_lateral_movement_indicators",
                confidence=0.82,
                affected_hosts=[host],
                evidence=[f"{len(set(targets))} lateral destinations: {', '.join(sorted(set(targets))[:5])}"],
                recommended_investigation="validate_admin intent and inspect destination hosts",
            )
            for host, targets in by_host.items()
            if host and len(set(targets)) >= 3
        ]

    def _hunt_beaconing(self, events: list[dict[str, Any]]) -> list[HuntResult]:
        counts: Counter[tuple[str, str]] = Counter()
        for event in events:
            if event.get("event_type") != "network_connection":
                continue
            details = event.get("details") or {}
            if details.get("possible_beaconing") or "beaconing" in set(event.get("tags") or []):
                counts[(str(event.get("host_id") or ""), str(event.get("network_dst_ip") or ""))] += 1
        results = []
        for (host, dst_ip), count in counts.items():
            if host and dst_ip and count >= 2:
                results.append(
                    HuntResult(
                        hunt_name="beaconing_patterns",
                        confidence=0.86,
                        affected_hosts=[host],
                        evidence=[f"{count} beacon-like events to {dst_ip}"],
                        recommended_investigation="enrich destination IP and inspect process lineage",
                    )
                )
        return results

    def _hunt_rare_processes(self, events: list[dict[str, Any]]) -> list[HuntResult]:
        counts = Counter(str(event.get("process_name") or "").lower() for event in events if event.get("process_name"))
        suspicious = {"adfind.exe", "rclone.exe", "psexec.exe", "procdump.exe", "nltest.exe", "quser.exe"}
        results = []
        for event in events:
            process = str(event.get("process_name") or "").lower()
            if not process:
                continue
            rare = counts[process] == 1 and (process in suspicious or bool((event.get("details") or {}).get("rare_process")))
            if rare:
                results.append(
                    HuntResult(
                        hunt_name="rare_process_execution",
                        confidence=0.74,
                        affected_hosts=[str(event.get("host_id") or "")],
                        evidence=[f"Rare process observed: {process}"],
                        recommended_investigation="review signer, hash, parent process and user context",
                    )
                )
        return results

    def _hunt_uncommon_admin(self, events: list[dict[str, Any]]) -> list[HuntResult]:
        results = []
        for event in events:
            username = str(event.get("username") or "").lower()
            details = event.get("details") or {}
            if event.get("event_type") == "authentication" and ("admin" in username or details.get("admin_activity")):
                if details.get("uncommon_admin_activity") or details.get("outside_business_hours"):
                    results.append(
                        HuntResult(
                            hunt_name="uncommon_admin_activity",
                            confidence=0.78,
                            affected_hosts=[str(event.get("host_id") or "")],
                            evidence=[f"Uncommon admin authentication: {username or 'unknown user'}"],
                            recommended_investigation="confirm change window and source IP legitimacy",
                        )
                    )
        return results

    def _hunt_rare_domains(self, events: list[dict[str, Any]]) -> list[HuntResult]:
        domains: dict[str, list[str]] = defaultdict(list)
        for event in events:
            details = event.get("details") or {}
            domain = str(details.get("domain") or details.get("dst_domain") or "").lower()
            if domain and (details.get("rare_domain") or details.get("new_domain")):
                domains[domain].append(str(event.get("host_id") or ""))
        return [
            HuntResult(
                hunt_name="rare_outbound_domains",
                confidence=0.72,
                affected_hosts=sorted(set(hosts)),
                evidence=[f"Rare outbound domain: {domain}"],
                recommended_investigation="enrich domain reputation and review process owner",
            )
            for domain, hosts in domains.items()
            if hosts
        ]

    def _hunt_auth_chains(self, events: list[dict[str, Any]]) -> list[HuntResult]:
        failures: dict[tuple[str, str], int] = defaultdict(int)
        success: set[tuple[str, str]] = set()
        for event in events:
            if event.get("event_type") != "authentication":
                continue
            key = (str(event.get("auth_source_ip") or ""), str(event.get("username") or ""))
            if event.get("auth_result") == "failure":
                failures[key] += 1
            if event.get("auth_result") == "success":
                success.add(key)
        results = []
        for key, count in failures.items():
            if count >= 3 and key in success:
                results.append(
                    HuntResult(
                        hunt_name="suspicious_authentication_chain",
                        confidence=0.84,
                        affected_hosts=sorted({str(event.get("host_id") or "") for event in events if (str(event.get("auth_source_ip") or ""), str(event.get("username") or "")) == key}),
                        evidence=[f"{count} failures followed by success from {key[0] or 'unknown source'}"],
                        recommended_investigation="review account activity and reset credentials if unauthorized",
                    )
                )
        return results


def run_default_hunts(records: Iterable[Any]) -> list[HuntResult]:
    return ThreatHuntingEngine().run_hunts(records)


def _event_from_record(record: Any) -> dict[str, Any]:
    item = _to_dict(record)
    if not item:
        return {}
    event = item.get("event")
    if isinstance(event, dict):
        return event
    return item


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


def _dedupe_results(results: list[HuntResult]) -> list[HuntResult]:
    seen = set()
    deduped: list[HuntResult] = []
    for result in results:
        key = (result.hunt_name, tuple(sorted(result.affected_hosts)), tuple(result.evidence))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(result)
    return deduped
