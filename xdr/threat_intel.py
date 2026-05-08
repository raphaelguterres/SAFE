"""Threat intelligence enrichment for SAFE AI-assisted SOC.

The enrichment is offline-safe and deterministic. It can wrap the existing
``engine.threat_intel`` facade when available, but does not require external
network access.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(slots=True)
class EnrichedIOC:
    value: str
    ioc_type: str
    matched: bool
    ioc_confidence: int
    ioc_aging: str
    reputation: str
    asn_context: str = ""
    domain_age: str = "unknown"
    geo_context: str = "unknown"
    source: str = "local"
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ThreatIntelEnrichmentEngine:
    """Adds analyst context to IOC reputation without depending on live APIs."""

    def __init__(self, reputation_client: Any | None = None):
        self.reputation_client = reputation_client

    def enrich_ioc(
        self,
        value: str,
        *,
        ioc_type: str = "",
        first_seen: str = "",
        last_seen: str = "",
        tenant_id: str = "global",
    ) -> EnrichedIOC:
        normalized = str(value or "").strip().lower()
        detected_type = ioc_type or _classify(normalized)
        reputation = _lookup_reputation(self.reputation_client, normalized, detected_type, tenant_id)
        confidence = int(reputation.get("confidence") or reputation.get("score") or 0)
        matched = bool(reputation.get("matched") or confidence >= 50)
        severity = str(reputation.get("severity") or "none").lower()
        return EnrichedIOC(
            value=normalized,
            ioc_type=detected_type,
            matched=matched,
            ioc_confidence=max(0, min(100, confidence)),
            ioc_aging=_aging(first_seen, last_seen),
            reputation=_reputation_label(severity, confidence, matched),
            asn_context=_asn_context(normalized, detected_type),
            domain_age=_domain_age(normalized, detected_type),
            geo_context=_geo_context(normalized, detected_type),
            source=str(reputation.get("source") or "local"),
            tags=[str(item) for item in (reputation.get("tags") or [])[:8]],
        )

    def enrich_event(self, event: dict[str, Any], *, tenant_id: str = "global") -> list[EnrichedIOC]:
        values = []
        details = event.get("details") if isinstance(event.get("details"), dict) else {}
        for key in ("source_ip", "src_ip", "dst_ip", "network_dst_ip", "remote_ip", "domain", "file_hash", "sha256", "md5"):
            value = event.get(key) or details.get(key)
            if value:
                values.append(self.enrich_ioc(str(value), tenant_id=tenant_id))
        deduped: dict[str, EnrichedIOC] = {}
        for item in values:
            deduped[item.value] = item
        return list(deduped.values())


def enrich_ioc(value: str, **kwargs: Any) -> EnrichedIOC:
    return ThreatIntelEnrichmentEngine().enrich_ioc(value, **kwargs)


def _lookup_reputation(client: Any, value: str, ioc_type: str, tenant_id: str) -> dict[str, Any]:
    if client and hasattr(client, "reputation"):
        try:
            verdict = client.reputation(value, ioc_type=ioc_type, tenant_id=tenant_id)
            if hasattr(verdict, "to_dict"):
                return verdict.to_dict()
            if isinstance(verdict, dict):
                return dict(verdict)
        except Exception:
            return {}
    try:
        from engine.threat_intel import ThreatIntelClient

        verdict = ThreatIntelClient().reputation(value, ioc_type=ioc_type, tenant_id=tenant_id)
        return verdict.to_dict()
    except Exception:
        return {}


def _classify(value: str) -> str:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass
    if len(value) in {32, 40, 64} and all(ch in "0123456789abcdef" for ch in value):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
    if "." in value:
        return "domain"
    return "unknown"


def _aging(first_seen: str, last_seen: str) -> str:
    ref = last_seen or first_seen
    if not ref:
        return "unknown"
    try:
        dt = datetime.fromisoformat(str(ref).replace("Z", "+00:00"))
    except ValueError:
        return "unknown"
    days = max(0, (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).days)
    if days <= 7:
        return "fresh"
    if days <= 30:
        return "recent"
    if days <= 180:
        return "aging"
    return "stale"


def _reputation_label(severity: str, confidence: int, matched: bool) -> str:
    if not matched:
        return "unknown"
    if severity in {"critical", "high"} or confidence >= 80:
        return "malicious"
    if severity == "medium" or confidence >= 50:
        return "suspicious"
    return "low_confidence"


def _asn_context(value: str, ioc_type: str) -> str:
    if ioc_type != "ip":
        return ""
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:4]
    return f"asn-context-{digest}"


def _domain_age(value: str, ioc_type: str) -> str:
    if ioc_type != "domain":
        return "not_applicable"
    if value.endswith(".test") or value.endswith(".local"):
        return "lab_or_reserved"
    return "unknown_without_external_lookup"


def _geo_context(value: str, ioc_type: str) -> str:
    if ioc_type != "ip":
        return "not_applicable"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if ip.is_private:
        return "private_network"
    if ip.is_loopback:
        return "loopback"
    if ip.is_reserved:
        return "reserved_or_documentation_range"
    return "public_internet"


__all__ = ["EnrichedIOC", "ThreatIntelEnrichmentEngine", "enrich_ioc"]
