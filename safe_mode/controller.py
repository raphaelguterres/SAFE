"""SAFE Mode controller for degraded operational states."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping


class SafeModeState(str, Enum):
    normal = "normal"
    active = "safe_mode"


@dataclass(frozen=True)
class SafeModeDecision:
    accepted: bool
    priority: str
    reason: str
    reduced: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "accepted": self.accepted,
            "priority": self.priority,
            "reason": self.reason,
            "reduced": self.reduced,
        }


@dataclass
class SafeModeController:
    state: SafeModeState = SafeModeState.normal
    reason: str = ""
    entered_at: str | None = None
    reduced_features: set[str] = field(default_factory=set)

    def evaluate(
        self,
        *,
        health_status: str,
        queue_pressure: float = 0.0,
        memory_pressure: float = 0.0,
        worker_failures: int = 0,
    ) -> SafeModeState:
        should_enter = (
            str(health_status).lower() in {"critical", "unstable"}
            or queue_pressure >= 0.85
            or memory_pressure >= 0.90
            or worker_failures >= 2
        )
        if should_enter:
            return self.enter(
                reason=f"health={health_status};queue={queue_pressure:.2f};memory={memory_pressure:.2f};workers={worker_failures}"
            )
        if self.state == SafeModeState.active and queue_pressure < 0.55 and worker_failures == 0:
            return self.exit()
        return self.state

    def enter(self, reason: str = "degraded_operations") -> SafeModeState:
        self.state = SafeModeState.active
        self.reason = reason
        self.entered_at = datetime.now(timezone.utc).isoformat()
        self.reduced_features = {"debug_telemetry", "heavy_hunts", "secondary_analytics", "low_priority_exports"}
        return self.state

    def exit(self) -> SafeModeState:
        self.state = SafeModeState.normal
        self.reason = ""
        self.entered_at = None
        self.reduced_features.clear()
        return self.state

    def prioritize_event(self, event: Mapping[str, Any]) -> SafeModeDecision:
        priority = normalize_priority(str(event.get("priority") or event.get("severity") or "P2"))
        event_type = str(event.get("event_type") or "").lower()
        if self.state == SafeModeState.normal:
            return SafeModeDecision(True, priority, "normal_operations")
        if priority in {"P0", "P1"}:
            return SafeModeDecision(True, priority, "safe_mode_priority_accept")
        if "critical" in event_type or "incident" in event_type:
            return SafeModeDecision(True, "P1", "safe_mode_critical_signal")
        if priority == "P2":
            return SafeModeDecision(True, priority, "safe_mode_reduced_processing", reduced=True)
        return SafeModeDecision(False, priority, "safe_mode_low_priority_suppressed", reduced=True)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "state": self.state.value,
            "reason": self.reason,
            "entered_at": self.entered_at,
            "reduced_features": sorted(self.reduced_features),
        }


def normalize_priority(value: str) -> str:
    raw = str(value or "P2").upper()
    if raw in {"CRITICAL", "P0"}:
        return "P0"
    if raw in {"HIGH", "P1"}:
        return "P1"
    if raw in {"MEDIUM", "P2"}:
        return "P2"
    return "P3"
