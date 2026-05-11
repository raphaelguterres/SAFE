"""SAFE enrichment pipeline for canonical security events."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from typing import Any, Mapping

from schema.canonical_event import CanonicalEvent


PRIVATE_ASN = {"asn": "private", "organization": "internal/private network", "confidence": 0.9}


@dataclass(frozen=True)
class EnrichmentResult:
    event: CanonicalEvent
    applied_enrichments: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event.to_dict(),
            "applied_enrichments": list(self.applied_enrichments),
            "issues": list(self.issues),
        }


class EnrichmentPipeline:
    """Add deterministic, offline-safe context to canonical telemetry."""

    def __init__(
        self,
        *,
        asset_inventory: Mapping[str, Mapping[str, Any]] | None = None,
        identity_inventory: Mapping[str, Mapping[str, Any]] | None = None,
        threat_intel: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> None:
        self.asset_inventory = {str(key): dict(value) for key, value in (asset_inventory or {}).items()}
        self.identity_inventory = {str(key): dict(value) for key, value in (identity_inventory or {}).items()}
        self.threat_intel = {str(key).lower(): dict(value) for key, value in (threat_intel or {}).items()}

    def enrich(
        self,
        event: CanonicalEvent,
        *,
        detections: list[Any] | None = None,
        correlations: list[Any] | None = None,
    ) -> EnrichmentResult:
        enrichment: dict[str, Any] = {}
        applied: list[str] = []
        issues: list[str] = []

        network_context = self._network_context(event)
        if network_context:
            enrichment["network_context"] = network_context
            applied.append("network_context")

        mitre = self._mitre_context(event, detections or [], correlations or [])
        if mitre:
            enrichment["mitre"] = mitre
            applied.append("mitre_mapping")

        asset = self.asset_inventory.get(event.host_id)
        if asset:
            enrichment["asset"] = redact_inventory(asset)
            applied.append("asset_context")

        identity = self.identity_inventory.get(event.user_id) if event.user_id else None
        if identity:
            enrichment["identity"] = redact_inventory(identity)
            applied.append("identity_context")

        threat = self._threat_context(event)
        if threat:
            enrichment["threat_intel"] = threat
            applied.append("threat_intel")

        process = self._process_context(event)
        if process:
            enrichment["process"] = process
            applied.append("process_signer")

        campaign = self._campaign_linkage(event, mitre)
        if campaign:
            enrichment["campaign"] = campaign
            applied.append("campaign_linkage")

        anomaly = self._anomaly_metadata(event)
        if anomaly:
            enrichment["anomaly"] = anomaly
            applied.append("anomaly_metadata")

        if not applied:
            issues.append("no_enrichment_applied")
        return EnrichmentResult(event.with_enrichment(enrichment), applied, issues)

    def _network_context(self, event: CanonicalEvent) -> dict[str, Any]:
        ip_value = event.network.dst_ip or event.network.src_ip
        domain = event.network.domain
        context: dict[str, Any] = {}
        if ip_value:
            try:
                parsed = ipaddress.ip_address(ip_value)
                context["ip"] = ip_value
                context["scope"] = "private" if parsed.is_private else "public"
                context["geo"] = {"country": "internal" if parsed.is_private else "unknown", "source": "offline"}
                context["asn"] = PRIVATE_ASN if parsed.is_private else {"asn": "unknown", "organization": "unknown", "confidence": 0.1}
            except ValueError:
                context["ip_parse_error"] = True
        if domain:
            context["domain"] = {"name": domain, "reputation": self.threat_intel.get(domain, {}).get("reputation", "unknown"), "age_days": None}
        return context

    def _mitre_context(self, event: CanonicalEvent, detections: list[Any], correlations: list[Any]) -> dict[str, Any]:
        tactics: list[str] = []
        techniques: list[str] = []
        for item in [*detections, *correlations]:
            data = to_mapping(item)
            tactic = str(data.get("tactic") or data.get("mitre_tactic") or "").strip()
            technique = str(data.get("technique") or data.get("mitre_technique") or "").strip()
            if tactic:
                tactics.append(tactic)
            if technique:
                techniques.append(technique)
        if not tactics and event.category == "auth":
            tactics.append("credential_access")
        if not tactics and event.category == "persistence":
            tactics.append("persistence")
        if not tactics and event.category == "process":
            tactics.append("execution")
        return {
            "tactics": sorted(set(tactics)),
            "techniques": sorted(set(techniques)),
        }

    def _threat_context(self, event: CanonicalEvent) -> dict[str, Any]:
        keys = [event.network.dst_ip, event.network.src_ip, event.network.domain, event.process.sha256]
        matches = []
        for key in keys:
            if not key:
                continue
            record = self.threat_intel.get(str(key).lower())
            if record:
                matches.append(redact_inventory({"ioc": key, **record}))
        return {"matches": matches, "matched": bool(matches)} if matches else {}

    def _process_context(self, event: CanonicalEvent) -> dict[str, Any]:
        if not (event.process.signer or event.process.sha256):
            return {}
        signer = event.process.signer or "unknown"
        trusted = any(token in signer.lower() for token in ("microsoft", "google", "apple", "signed"))
        return {"signer": signer, "sha256": event.process.sha256, "signer_trust": "trusted" if trusted else "unknown"}

    def _campaign_linkage(self, event: CanonicalEvent, mitre: Mapping[str, Any]) -> dict[str, Any]:
        pivots = [value for value in (event.network.dst_ip, event.network.domain, event.process.sha256) if value]
        if not pivots and not mitre.get("tactics"):
            return {}
        seed = "|".join(sorted([*pivots, *list(mitre.get("tactics") or [])])) or event.event_type
        return {"campaign_key": f"camp_{abs(hash(seed)) % 10_000_000:07d}", "pivots": pivots}

    def _anomaly_metadata(self, event: CanonicalEvent) -> dict[str, Any]:
        hints = []
        if event.confidence < 0.4:
            hints.append("low_confidence")
        if event.severity in {"high", "critical"} and event.category == "process":
            hints.append("high_risk_process_activity")
        if event.network.dst_port in {4444, 6667, 8080, 8443}:
            hints.append("interesting_destination_port")
        return {"hints": hints} if hints else {}


def to_mapping(item: Any) -> dict[str, Any]:
    if isinstance(item, Mapping):
        return dict(item)
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return dict(result) if isinstance(result, Mapping) else {}
    if hasattr(item, "__dict__"):
        return dict(getattr(item, "__dict__", {}))
    return {}


def redact_inventory(payload: Mapping[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in payload.items():
        lower = str(key).lower()
        if any(secret in lower for secret in ("secret", "token", "password", "api_key", "host_key")):
            redacted[str(key)] = "[redacted]"
        elif isinstance(value, Mapping):
            redacted[str(key)] = redact_inventory(value)
        else:
            redacted[str(key)] = value
    return redacted
