"""SAFE EDR/XDR pipeline orchestration."""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Any

from .behavior_engine import EnterpriseBehaviorEngine
from .correlation import WeakSignalCorrelationEngine
from .detection import BehaviorDetectionEngine
from .enrichment_pipeline import EnrichmentPipeline
from .event_lineage import EventLineageEngine
from .host_defense_engine import HostDefenseEngine
from .killchain_engine import KillChainEngine
from .normalization_engine import TelemetryNormalizationEngine
from .response import ResponseEngine
from .schema import PipelineOutcome, parse_endpoint_events
from .severity import clamp_risk, risk_level, severity_weight


class XDRPipeline:
    def __init__(
        self,
        detection_engine: BehaviorDetectionEngine | None = None,
        correlation_engine: WeakSignalCorrelationEngine | None = None,
        response_engine: ResponseEngine | None = None,
        killchain_engine: KillChainEngine | None = None,
        behavior_engine: EnterpriseBehaviorEngine | None = None,
        host_defense_engine: HostDefenseEngine | None = None,
        normalization_engine: TelemetryNormalizationEngine | None = None,
        enrichment_pipeline: EnrichmentPipeline | None = None,
        lineage_engine: EventLineageEngine | None = None,
    ):
        self.detection_engine = detection_engine or BehaviorDetectionEngine()
        self.correlation_engine = correlation_engine or WeakSignalCorrelationEngine()
        self.response_engine = response_engine or ResponseEngine()
        self.killchain_engine = killchain_engine or KillChainEngine()
        self.behavior_engine = behavior_engine or EnterpriseBehaviorEngine()
        self.host_defense_engine = host_defense_engine or HostDefenseEngine()
        self.normalization_engine = normalization_engine or TelemetryNormalizationEngine()
        self.enrichment_pipeline = enrichment_pipeline or EnrichmentPipeline()
        self.lineage_engine = lineage_engine or EventLineageEngine()
        self._risk_lock = threading.RLock()
        self._history_lock = threading.RLock()
        self._host_risk_scores: dict[str, int] = defaultdict(int)
        self._host_recent_activity: dict[str, deque] = defaultdict(lambda: deque(maxlen=80))

    def process_payload(self, payload: dict[str, Any] | list[Any]) -> list[PipelineOutcome]:
        events = parse_endpoint_events(payload)
        return [self.process_event(event) for event in events]

    def process_event(self, event) -> PipelineOutcome:
        normalization = self.normalization_engine.normalize(event, tenant_id=getattr(event, "tenant_id", "") or None)
        canonical_event = normalization.canonical_event
        detections = self.detection_engine.process(event)
        correlations = self.correlation_engine.process(event, detections)
        enrichment = self.enrichment_pipeline.enrich(canonical_event, detections=detections, correlations=correlations) if canonical_event else None
        enriched_event = enrichment.event if enrichment else canonical_event
        if enriched_event:
            self.lineage_engine.start(enriched_event)
            for name in (enrichment.applied_enrichments if enrichment else []):
                self.lineage_engine.add_enrichment(enriched_event, name)
            for detection in detections:
                self.lineage_engine.add_detection(enriched_event, detection)
            for correlation in correlations:
                self.lineage_engine.add_correlation(enriched_event, correlation)
        behavioral_findings = self.behavior_engine.analyze(event)
        killchain_findings = self.killchain_engine.map_event_to_killchain(event, detections, correlations)
        killchain_stage_summary = self.killchain_engine.stage_summary(killchain_findings)
        attack_score = self.killchain_engine.attack_progression_score(killchain_findings)
        actions = self.response_engine.plan(event, detections, correlations)
        risk_delta = max(1, severity_weight(event.severity) // 3)
        risk_delta += sum(max(1, int(severity_weight(item.severity) * max(item.confidence, 0.5))) for item in detections)
        risk_delta += sum(max(1, int(severity_weight(item.severity) * max(item.confidence, 0.5))) for item in correlations)
        risk_delta += sum(max(1, int(severity_weight(item.severity) * max(item.confidence, 0.5))) for item in behavioral_findings)
        risk_delta += sum(max(0, int(getattr(item, "risk_modifier", 0))) for item in killchain_findings)
        if attack_score >= 80:
            risk_delta += 10
        if any("execution_chain" in (item.tags or []) for item in correlations):
            risk_delta += 12
        host_risk = self._update_host_risk(event.host_id, risk_delta)
        host_defense_state = self.host_defense_engine.evaluate_host_security_state(
            host_id=event.host_id,
            base_risk_score=host_risk,
            detections=detections,
            correlations=correlations,
            killchain_findings=killchain_findings,
            response_actions=actions,
            behavioral_anomalies=behavioral_findings,
            active_incidents=sum(1 for action in actions if action.action_type == "generate_incident_ticket"),
        ).to_dict()
        outcome = PipelineOutcome(
            event=event,
            canonical_event=canonical_event,
            enriched_event=enriched_event,
            event_lineage=self.lineage_engine.trace(
                tenant_id=enriched_event.tenant_id,
                event_id=enriched_event.event_id,
            ) if enriched_event else {"issues": [item.to_dict() for item in normalization.issues]},
            detections=detections,
            correlations=correlations,
            actions=actions,
            host_risk_score=host_risk,
            behavioral_findings=behavioral_findings,
            killchain_findings=killchain_findings,
            killchain_stage_summary=killchain_stage_summary,
            attack_progression_score=attack_score,
            host_defense_state=host_defense_state,
        )
        self._record_outcome(outcome)
        return outcome

    def current_host_risk(self, host_id: str) -> dict[str, Any]:
        with self._risk_lock:
            score = clamp_risk(self._host_risk_scores.get(host_id, 0))
        return {"host_id": host_id, "risk_score": score, "risk_level": risk_level(score)}

    def _update_host_risk(self, host_id: str, delta: int) -> int:
        with self._risk_lock:
            baseline = max(0, self._host_risk_scores.get(host_id, 0) - 2)
            self._host_risk_scores[host_id] = clamp_risk(baseline + delta)
            return self._host_risk_scores[host_id]

    def _record_outcome(self, outcome: PipelineOutcome) -> None:
        with self._history_lock:
            self._host_recent_activity[outcome.event.host_id].appendleft(outcome.to_dict())

    def recent_host_activity(self, host_id: str, *, limit: int = 25) -> list[dict[str, Any]]:
        with self._history_lock:
            return list(self._host_recent_activity.get(host_id, ()))[:limit]
