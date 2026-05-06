"""Threat intelligence facade for NetGuard EDR.

The production feed engine already lives in ``engine.threat_intel_feed``. This
module provides the stable EDR-facing reputation API requested by the active
defense layer: IP, domain and hash lookup, deterministic scoring, and an
offline-safe mock mode for demos/tests.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional


HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


SEVERITY_SCORES = {
    "none": 0,
    "low": 10,
    "medium": 30,
    "high": 55,
    "critical": 80,
}


DEFAULT_MOCK_IOCS = {
    "198.51.100.66": {
        "ioc_type": "ip",
        "source": "mock-c2",
        "threat_type": "c2",
        "confidence": 90,
        "severity": "critical",
        "tags": ["c2", "beacon"],
    },
    "malware.example.test": {
        "ioc_type": "domain",
        "source": "mock-domain",
        "threat_type": "malware",
        "confidence": 82,
        "severity": "high",
        "tags": ["malware", "delivery"],
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "ioc_type": "md5",
        "source": "mock-eicar",
        "threat_type": "test-malware",
        "confidence": 95,
        "severity": "critical",
        "tags": ["malware", "test"],
    },
}


@dataclass
class ThreatIntelVerdict:
    value: str
    ioc_type: str
    matched: bool = False
    source: str = ""
    threat_type: str = ""
    confidence: int = 0
    severity: str = "none"
    score: int = 0
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type,
            "matched": self.matched,
            "source": self.source,
            "threat_type": self.threat_type,
            "confidence": self.confidence,
            "severity": self.severity,
            "score": self.score,
            "tags": self.tags,
        }


def classify_ioc(value: str, explicit_type: str = "") -> str:
    candidate = (value or "").strip()
    if explicit_type:
        return explicit_type.strip().lower()
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass
    if HASH_RE.match(candidate):
        return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(candidate), "hash")
    if DOMAIN_RE.match(candidate):
        return "domain"
    return "unknown"


def score_from_match(confidence: int, severity: str) -> int:
    base = SEVERITY_SCORES.get((severity or "none").lower(), 0)
    try:
        conf = max(0, min(100, int(confidence)))
    except (TypeError, ValueError):
        conf = 0
    return max(0, min(100, round(base * (conf / 100))))


class ThreatIntelClient:
    """Lookup IOC reputation from mock indicators and optional feed storage."""

    def __init__(self, feed=None, mock_indicators: Optional[dict[str, dict]] = None):
        self.feed = feed
        self.mock_indicators = {
            key.lower(): dict(value)
            for key, value in (mock_indicators or DEFAULT_MOCK_IOCS).items()
        }

    def reputation(
        self,
        value: str,
        *,
        ioc_type: str = "",
        tenant_id: str = "global",
    ) -> ThreatIntelVerdict:
        normalized = (value or "").strip().lower()
        detected_type = classify_ioc(normalized, ioc_type)
        if not normalized:
            return ThreatIntelVerdict(value="", ioc_type="unknown")

        feed_match = self._lookup_feed(normalized, tenant_id)
        if feed_match:
            severity = str(feed_match.get("severity") or "medium").lower()
            confidence = int(feed_match.get("confidence") or 50)
            return ThreatIntelVerdict(
                value=normalized,
                ioc_type=str(feed_match.get("ioc_type") or detected_type),
                matched=True,
                source=str(feed_match.get("source") or "feed"),
                threat_type=str(feed_match.get("threat_type") or ""),
                confidence=confidence,
                severity=severity,
                score=score_from_match(confidence, severity),
                tags=self._tags(feed_match),
            )

        mock = self.mock_indicators.get(normalized)
        if mock:
            severity = str(mock.get("severity") or "medium").lower()
            confidence = int(mock.get("confidence") or 50)
            return ThreatIntelVerdict(
                value=normalized,
                ioc_type=str(mock.get("ioc_type") or detected_type),
                matched=True,
                source=str(mock.get("source") or "mock"),
                threat_type=str(mock.get("threat_type") or ""),
                confidence=confidence,
                severity=severity,
                score=score_from_match(confidence, severity),
                tags=list(mock.get("tags") or []),
            )

        return ThreatIntelVerdict(
            value=normalized,
            ioc_type=detected_type,
            matched=False,
            severity="none",
            confidence=0,
            score=0,
        )

    def event_reputation(self, event: dict, *, tenant_id: str = "global") -> dict[str, ThreatIntelVerdict]:
        values = {}
        for key in ("source_ip", "src_ip", "dst_ip", "remote_ip", "domain", "file_hash", "sha256", "md5"):
            value = event.get(key)
            if value:
                verdict = self.reputation(str(value), tenant_id=tenant_id)
                values[str(value)] = verdict
        return values

    def event_score(self, event: dict, *, tenant_id: str = "global") -> int:
        verdicts = self.event_reputation(event, tenant_id=tenant_id).values()
        return max((verdict.score for verdict in verdicts), default=0)

    def _lookup_feed(self, value: str, tenant_id: str) -> Optional[dict]:
        if not self.feed or not hasattr(self.feed, "lookup"):
            return None
        try:
            match = self.feed.lookup(value, tenant_id=tenant_id)
        except Exception:
            return None
        return dict(match) if match else None

    @staticmethod
    def _tags(match: dict) -> list[str]:
        tags = match.get("tags") or []
        if isinstance(tags, str):
            digest = hashlib.sha1(tags.encode("utf-8")).hexdigest()[:8]
            return [tags[:64], f"tags-sha1:{digest}"] if tags else []
        return [str(tag) for tag in tags if str(tag)]


__all__ = [
    "ThreatIntelClient",
    "ThreatIntelVerdict",
    "classify_ioc",
    "score_from_match",
]
