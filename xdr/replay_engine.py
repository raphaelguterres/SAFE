"""Defensive attack replay engine for rule QA and tuning."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .enrichment_pipeline import EnrichmentPipeline
from .normalization_engine import TelemetryNormalizationEngine


DetectionCallable = Callable[[Any], list[Any]]


@dataclass(frozen=True)
class ReplayEventResult:
    event_id: str
    tenant_id: str
    normalized: bool
    detections: list[dict[str, Any]] = field(default_factory=list)
    enrichments: list[str] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "tenant_id": self.tenant_id,
            "normalized": self.normalized,
            "detections": list(self.detections),
            "enrichments": list(self.enrichments),
            "issues": list(self.issues),
        }


@dataclass(frozen=True)
class ReplayResult:
    replay_id: str
    tenant_id: str
    event_count: int
    detection_count: int
    false_positive_estimate: float
    results: list[ReplayEventResult]
    safe_mode: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "replay_id": self.replay_id,
            "tenant_id": self.tenant_id,
            "event_count": self.event_count,
            "detection_count": self.detection_count,
            "false_positive_estimate": self.false_positive_estimate,
            "safe_mode": self.safe_mode,
            "results": [item.to_dict() for item in self.results],
        }


class AttackReplayEngine:
    """Reprocess historical events without executing payloads."""

    def __init__(
        self,
        *,
        normalizer: TelemetryNormalizationEngine | None = None,
        enrichment_pipeline: EnrichmentPipeline | None = None,
    ) -> None:
        self.normalizer = normalizer or TelemetryNormalizationEngine()
        self.enrichment_pipeline = enrichment_pipeline or EnrichmentPipeline()

    def replay(
        self,
        *,
        tenant_id: str,
        events: list[Mapping[str, Any]],
        detection_callable: DetectionCallable | None = None,
        replay_id: str = "replay",
    ) -> ReplayResult:
        tenant = str(tenant_id or "").strip()
        if not tenant:
            raise ValueError("tenant_id is required")

        results: list[ReplayEventResult] = []
        total_detections = 0
        low_confidence = 0
        for raw in events:
            if str(raw.get("tenant_id") or tenant) != tenant:
                continue
            normalized = self.normalizer.normalize(raw, tenant_id=tenant)
            if not normalized.canonical_event:
                results.append(ReplayEventResult("", tenant, False, issues=[issue.reason for issue in normalized.issues]))
                continue
            enriched = self.enrichment_pipeline.enrich(normalized.canonical_event)
            detections = []
            if detection_callable:
                detections = [to_mapping(item) for item in detection_callable(enriched.event)]
            total_detections += len(detections)
            low_confidence += sum(1 for item in detections if float(item.get("confidence") or 1) < 0.45)
            results.append(
                ReplayEventResult(
                    event_id=enriched.event.event_id,
                    tenant_id=tenant,
                    normalized=True,
                    detections=detections,
                    enrichments=enriched.applied_enrichments,
                    issues=[issue.reason for issue in normalized.issues] + enriched.issues,
                )
            )
        false_positive_estimate = round(low_confidence / total_detections, 4) if total_detections else 0.0
        return ReplayResult(
            replay_id=replay_id,
            tenant_id=tenant,
            event_count=len(results),
            detection_count=total_detections,
            false_positive_estimate=false_positive_estimate,
            results=results,
        )


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
