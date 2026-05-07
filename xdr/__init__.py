"""NetGuard XDR foundation package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .behavior_engine import EnterpriseBehaviorEngine
    from .detection import BehaviorDetectionEngine
    from .host_defense_engine import HostDefenseEngine
    from .pipeline import XDRPipeline
    from .schema import EndpointEvent, PipelineOutcome
    from .threat_hunting import ThreatHuntingEngine

__all__ = [
    "BehaviorDetectionEngine",
    "EndpointEvent",
    "EnterpriseBehaviorEngine",
    "HostDefenseEngine",
    "PipelineOutcome",
    "ThreatHuntingEngine",
    "XDRPipeline",
]


def __getattr__(name: str):
    if name == "BehaviorDetectionEngine":
        from .detection import BehaviorDetectionEngine as _BehaviorDetectionEngine

        return _BehaviorDetectionEngine
    if name == "EnterpriseBehaviorEngine":
        from .behavior_engine import EnterpriseBehaviorEngine as _EnterpriseBehaviorEngine

        return _EnterpriseBehaviorEngine
    if name == "HostDefenseEngine":
        from .host_defense_engine import HostDefenseEngine as _HostDefenseEngine

        return _HostDefenseEngine
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
