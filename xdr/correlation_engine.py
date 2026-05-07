"""Incident correlation V2 for campaign-style XDR analysis."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class CampaignCorrelation:
    campaign_id: str
    correlation_type: str
    severity: str
    confidence: float
    affected_hosts: list[str]
    attacker_infrastructure: list[str]
    related_incidents: list[str]
    evidence: list[dict[str, Any]] = field(default_factory=list)
    recommended_action: str = "investigate_campaign"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IncidentCorrelationV2:
    """Correlates events across hosts and incidents without cross-tenant mixing."""

    def __init__(self, *, window_seconds: int = 3600):
        self.window_seconds = max(60, int(window_seconds))

    def correlate_events(self, events: list[dict[str, Any]], *, tenant_id: str | None = None) -> list[CampaignCorrelation]:
        scoped = [_normalize_event(event) for event in events]
        if tenant_id:
            scoped = [event for event in scoped if event.get("tenant_id") == tenant_id]

        campaigns: list[CampaignCorrelation] = []
        campaigns.extend(self._infra_campaigns(scoped))
        campaigns.extend(self._temporal_host_campaigns(scoped))
        return _dedupe_campaigns(campaigns)

    def correlate_incidents(self, incidents: list[dict[str, Any]], *, tenant_id: str | None = None) -> list[CampaignCorrelation]:
        events = []
        for incident in incidents:
            if tenant_id and str(incident.get("tenant_id") or "") != tenant_id:
                continue
            payload = dict(incident)
            payload.setdefault("event_type", "incident")
            payload.setdefault("incident_id", incident.get("id") or incident.get("incident_id"))
            events.append(payload)
        return self.correlate_events(events, tenant_id=tenant_id)

    def _infra_campaigns(self, events: list[dict[str, Any]]) -> list[CampaignCorrelation]:
        buckets: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            tenant = str(event.get("tenant_id") or "default")
            for infra in _infrastructure(event):
                buckets[(tenant, infra)].append(event)

        campaigns: list[CampaignCorrelation] = []
        for (tenant, infra), items in buckets.items():
            hosts = sorted({str(item.get("host_id") or "") for item in items if item.get("host_id")})
            if len(hosts) < 2 and len(items) < 4:
                continue
            related = sorted({str(item.get("incident_id") or "") for item in items if item.get("incident_id")})
            severity = "critical" if len(hosts) >= 3 else "high"
            confidence = min(0.98, 0.55 + (len(hosts) * 0.14) + (len(items) * 0.03))
            campaigns.append(
                CampaignCorrelation(
                    campaign_id=f"camp_{tenant}_{_safe_id(infra)}",
                    correlation_type="repeated_attacker_infrastructure",
                    severity=severity,
                    confidence=round(confidence, 3),
                    affected_hosts=hosts,
                    attacker_infrastructure=[infra],
                    related_incidents=related,
                    evidence=_trim_evidence(items),
                    recommended_action="investigate_shared_infrastructure_and_scope_hosts",
                )
            )
        return campaigns

    def _temporal_host_campaigns(self, events: list[dict[str, Any]]) -> list[CampaignCorrelation]:
        by_host: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for event in events:
            tenant = str(event.get("tenant_id") or "default")
            host = str(event.get("host_id") or "")
            if host:
                by_host[(tenant, host)].append(event)

        campaigns: list[CampaignCorrelation] = []
        for (tenant, host), items in by_host.items():
            ordered = sorted(items, key=lambda item: _epoch(item.get("timestamp")))
            if len(ordered) < 3:
                continue
            first = _epoch(ordered[0].get("timestamp"))
            last = _epoch(ordered[-1].get("timestamp"))
            if last - first > self.window_seconds:
                continue
            tactics = {
                str(item.get("mitre_tactic") or item.get("tactic") or item.get("killchain_stage") or "").lower()
                for item in ordered
            }
            tactics.discard("")
            if len(tactics) < 2:
                continue
            campaigns.append(
                CampaignCorrelation(
                    campaign_id=f"camp_{tenant}_{_safe_id(host)}_temporal",
                    correlation_type="temporal_attack_progression",
                    severity="high" if len(tactics) < 4 else "critical",
                    confidence=min(0.95, 0.5 + (len(tactics) * 0.1) + (len(ordered) * 0.02)),
                    affected_hosts=[host],
                    attacker_infrastructure=sorted({infra for item in ordered for infra in _infrastructure(item)}),
                    related_incidents=sorted({str(item.get("incident_id") or "") for item in ordered if item.get("incident_id")}),
                    evidence=_trim_evidence(ordered),
                    recommended_action="open_host_triage_and_link_related_incidents",
                )
            )
        return campaigns


def _normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    payload = dict(event or {})
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    for key in ("src_ip", "source_ip", "auth_source_ip", "dst_ip", "network_dst_ip", "domain", "dst_domain"):
        if key not in payload and key in details:
            payload[key] = details[key]
    payload["tenant_id"] = str(payload.get("tenant_id") or payload.get("tenant") or "default")
    return payload


def _infrastructure(event: dict[str, Any]) -> list[str]:
    values = [
        event.get("src_ip"),
        event.get("source_ip"),
        event.get("auth_source_ip"),
        event.get("dst_ip"),
        event.get("network_dst_ip"),
        event.get("domain"),
        event.get("dst_domain"),
    ]
    return sorted({str(value).strip().lower() for value in values if str(value or "").strip()})


def _trim_evidence(items: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    evidence = []
    for item in items[:limit]:
        evidence.append({
            "event_id": item.get("event_id") or item.get("record_id") or "",
            "incident_id": item.get("incident_id") or item.get("id") or "",
            "host_id": item.get("host_id") or "",
            "timestamp": item.get("timestamp") or "",
            "event_type": item.get("event_type") or item.get("alert_type") or "",
            "severity": item.get("severity") or "",
        })
    return evidence


def _epoch(value: Any) -> float:
    if not value:
        return 0.0
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        try:
            return float(value)
        except (TypeError, ValueError):
            return datetime.now(timezone.utc).timestamp()


def _safe_id(value: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in value.lower()).strip("_")[:80] or "unknown"


def _dedupe_campaigns(campaigns: list[CampaignCorrelation]) -> list[CampaignCorrelation]:
    output: list[CampaignCorrelation] = []
    seen = set()
    for campaign in campaigns:
        key = (campaign.campaign_id, campaign.correlation_type)
        if key in seen:
            continue
        seen.add(key)
        output.append(campaign)
    return output
