"""SAFE XDR foundation package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .alert_context_engine import AlertContextEngine
    from .behavior_engine import EnterpriseBehaviorEngine
    from .case_management import CaseRepository
    from .detection import BehaviorDetectionEngine
    from .evidence_store import EvidenceStore
    from .explainability_engine import ExplainabilityEngine
    from .fp_reduction_engine import FalsePositiveReductionEngine
    from .host_defense_engine import HostDefenseEngine
    from .health_engine import HealthEngine
    from .investigation_assistant import InvestigationAssistant
    from .ioc_manager import IOCManager
    from .event_bus import LiveSOCEventBus
    from .enrichment_pipeline import EnrichmentPipeline
    from .event_lineage import EventLineageEngine
    from .queue_manager import ResilientQueueManager
    from .realtime_stream import RealtimeStreamHub
    from .normalization_engine import TelemetryNormalizationEngine
    from .pipeline import XDRPipeline
    from .playbook_executor import DefensivePlaybookExecutor
    from .prioritization_engine import IncidentPrioritizationEngine
    from .progression_predictor import AttackProgressionPredictor
    from .schema import EndpointEvent, PipelineOutcome
    from .threat_hunting import ThreatHuntingEngine

__all__ = [
    "AlertContextEngine",
    "AttackProgressionPredictor",
    "BehaviorDetectionEngine",
    "CaseRepository",
    "DefensivePlaybookExecutor",
    "EndpointEvent",
    "EnterpriseBehaviorEngine",
    "EvidenceStore",
    "ExplainabilityEngine",
    "FalsePositiveReductionEngine",
    "HealthEngine",
    "HostDefenseEngine",
    "IOCManager",
    "IncidentPrioritizationEngine",
    "InvestigationAssistant",
    "EnrichmentPipeline",
    "EventLineageEngine",
    "LiveSOCEventBus",
    "TelemetryNormalizationEngine",
    "PipelineOutcome",
    "RealtimeStreamHub",
    "ResilientQueueManager",
    "ThreatHuntingEngine",
    "XDRPipeline",
]


def __getattr__(name: str):
    if name == "AlertContextEngine":
        from .alert_context_engine import AlertContextEngine as _AlertContextEngine

        return _AlertContextEngine
    if name == "AttackProgressionPredictor":
        from .progression_predictor import AttackProgressionPredictor as _AttackProgressionPredictor

        return _AttackProgressionPredictor
    if name == "BehaviorDetectionEngine":
        from .detection import BehaviorDetectionEngine as _BehaviorDetectionEngine

        return _BehaviorDetectionEngine
    if name == "CaseRepository":
        from .case_management import CaseRepository as _CaseRepository

        return _CaseRepository
    if name == "DefensivePlaybookExecutor":
        from .playbook_executor import DefensivePlaybookExecutor as _DefensivePlaybookExecutor

        return _DefensivePlaybookExecutor
    if name == "EnterpriseBehaviorEngine":
        from .behavior_engine import EnterpriseBehaviorEngine as _EnterpriseBehaviorEngine

        return _EnterpriseBehaviorEngine
    if name == "EvidenceStore":
        from .evidence_store import EvidenceStore as _EvidenceStore

        return _EvidenceStore
    if name == "ExplainabilityEngine":
        from .explainability_engine import ExplainabilityEngine as _ExplainabilityEngine

        return _ExplainabilityEngine
    if name == "FalsePositiveReductionEngine":
        from .fp_reduction_engine import FalsePositiveReductionEngine as _FalsePositiveReductionEngine

        return _FalsePositiveReductionEngine
    if name == "HealthEngine":
        from .health_engine import HealthEngine as _HealthEngine

        return _HealthEngine
    if name == "HostDefenseEngine":
        from .host_defense_engine import HostDefenseEngine as _HostDefenseEngine

        return _HostDefenseEngine
    if name == "IOCManager":
        from .ioc_manager import IOCManager as _IOCManager

        return _IOCManager
    if name == "IncidentPrioritizationEngine":
        from .prioritization_engine import IncidentPrioritizationEngine as _IncidentPrioritizationEngine

        return _IncidentPrioritizationEngine
    if name == "InvestigationAssistant":
        from .investigation_assistant import InvestigationAssistant as _InvestigationAssistant

        return _InvestigationAssistant
    if name == "EnrichmentPipeline":
        from .enrichment_pipeline import EnrichmentPipeline as _EnrichmentPipeline

        return _EnrichmentPipeline
    if name == "EventLineageEngine":
        from .event_lineage import EventLineageEngine as _EventLineageEngine

        return _EventLineageEngine
    if name == "LiveSOCEventBus":
        from .event_bus import LiveSOCEventBus as _LiveSOCEventBus

        return _LiveSOCEventBus
    if name == "TelemetryNormalizationEngine":
        from .normalization_engine import TelemetryNormalizationEngine as _TelemetryNormalizationEngine

        return _TelemetryNormalizationEngine
    if name == "RealtimeStreamHub":
        from .realtime_stream import RealtimeStreamHub as _RealtimeStreamHub

        return _RealtimeStreamHub
    if name == "ResilientQueueManager":
        from .queue_manager import ResilientQueueManager as _ResilientQueueManager

        return _ResilientQueueManager
    if name == "ThreatHuntingEngine":
        from .threat_hunting import ThreatHuntingEngine as _ThreatHuntingEngine

        return _ThreatHuntingEngine
    if name == "XDRPipeline":
        from .pipeline import XDRPipeline as _XDRPipeline

        return _XDRPipeline
    if name == "EndpointEvent":
        from .schema import EndpointEvent as _EndpointEvent

        return _EndpointEvent
    if name == "PipelineOutcome":
        from .schema import PipelineOutcome as _PipelineOutcome

        return _PipelineOutcome
    raise AttributeError(name)
