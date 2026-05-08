"""SAFE XDR foundation package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .alert_context_engine import AlertContextEngine
    from .behavior_engine import EnterpriseBehaviorEngine
    from .detection import BehaviorDetectionEngine
    from .explainability_engine import ExplainabilityEngine
    from .fp_reduction_engine import FalsePositiveReductionEngine
    from .host_defense_engine import HostDefenseEngine
    from .investigation_assistant import InvestigationAssistant
    from .pipeline import XDRPipeline
    from .prioritization_engine import IncidentPrioritizationEngine
    from .progression_predictor import AttackProgressionPredictor
    from .schema import EndpointEvent, PipelineOutcome
    from .threat_hunting import ThreatHuntingEngine

__all__ = [
    "AlertContextEngine",
    "AttackProgressionPredictor",
    "BehaviorDetectionEngine",
    "EndpointEvent",
    "EnterpriseBehaviorEngine",
    "ExplainabilityEngine",
    "FalsePositiveReductionEngine",
    "HostDefenseEngine",
    "IncidentPrioritizationEngine",
    "InvestigationAssistant",
    "PipelineOutcome",
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
    if name == "EnterpriseBehaviorEngine":
        from .behavior_engine import EnterpriseBehaviorEngine as _EnterpriseBehaviorEngine

        return _EnterpriseBehaviorEngine
    if name == "ExplainabilityEngine":
        from .explainability_engine import ExplainabilityEngine as _ExplainabilityEngine

        return _ExplainabilityEngine
    if name == "FalsePositiveReductionEngine":
        from .fp_reduction_engine import FalsePositiveReductionEngine as _FalsePositiveReductionEngine

        return _FalsePositiveReductionEngine
    if name == "HostDefenseEngine":
        from .host_defense_engine import HostDefenseEngine as _HostDefenseEngine

        return _HostDefenseEngine
    if name == "IncidentPrioritizationEngine":
        from .prioritization_engine import IncidentPrioritizationEngine as _IncidentPrioritizationEngine

        return _IncidentPrioritizationEngine
    if name == "InvestigationAssistant":
        from .investigation_assistant import InvestigationAssistant as _InvestigationAssistant

        return _InvestigationAssistant
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
