"""Explainable detection records for SAFE XDR."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Iterable


@dataclass(slots=True)
class DetectionExplanation:
    why_generated: str
    contributing_events: list[dict[str, Any]] = field(default_factory=list)
    contributing_engines: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence_chain: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(max(0.0, min(1.0, self.confidence)), 2)
        return payload


class ExplainabilityEngine:
    """Creates transparent explanations for detections and correlations."""

    def explain_detection(
        self,
        detection: Any,
        *,
        event: Any | None = None,
        correlations: Iterable[Any] | None = None,
        killchain_findings: Iterable[Any] | None = None,
        contributing_engines: Iterable[str] | None = None,
    ) -> DetectionExplanation:
        record = _to_dict(detection)
        event_record = _to_dict(event) if event else {}
        correlation_records = [_to_dict(item) for item in (correlations or []) if _to_dict(item)]
        killchain_records = [_to_dict(item) for item in (killchain_findings or []) if _to_dict(item)]
        engines = list(dict.fromkeys(["detection_engine"] + list(contributing_engines or [])))
        if correlation_records:
            engines.append("correlation_engine")
        if killchain_records:
            engines.append("killchain_engine")
        confidence = _confidence(record, correlation_records, killchain_records)
        why = _why(record, event_record, killchain_records)
        evidence_chain = _evidence_chain(record, event_record, correlation_records, killchain_records)
        contributing_events = []
        if event_record:
            contributing_events.append(_safe_event_ref(event_record))
        for related in record.get("related_events") or []:
            if isinstance(related, dict):
                contributing_events.append(_safe_event_ref(related))

        return DetectionExplanation(
            why_generated=why,
            contributing_events=contributing_events[:10],
            contributing_engines=list(dict.fromkeys(engines)),
            confidence=confidence,
            evidence_chain=evidence_chain,
        )


def explain_detection(detection: Any, **kwargs: Any) -> DetectionExplanation:
    return ExplainabilityEngine().explain_detection(detection, **kwargs)


def _why(record: dict[str, Any], event: dict[str, Any], killchain: list[dict[str, Any]]) -> str:
    rule = str(record.get("rule_name") or record.get("alert_type") or "detection").strip()
    summary = str(record.get("summary") or record.get("description") or "").strip()
    process = str(record.get("process_name") or event.get("process_name") or "").strip()
    stage = next((str(item.get("stage") or "") for item in killchain if item.get("stage")), "")
    pieces = [f"{rule} was generated"]
    if process:
        pieces.append(f"because process context included {process}")
    if summary:
        pieces.append(f"and matched evidence: {summary}")
    if stage:
        pieces.append(f"mapped to Kill Chain stage {stage.replace('_', ' ')}")
    return " ".join(pieces) + "."


def _confidence(record: dict[str, Any], correlations: list[dict[str, Any]], killchain: list[dict[str, Any]]) -> float:
    try:
        base = float(record.get("confidence") or 0.5)
    except (TypeError, ValueError):
        base = 0.5
    if base > 1:
        base = base / 100
    base += min(0.18, len(correlations) * 0.06)
    base += min(0.12, len(killchain) * 0.04)
    return max(0.0, min(1.0, base))


def _evidence_chain(
    record: dict[str, Any],
    event: dict[str, Any],
    correlations: list[dict[str, Any]],
    killchain: list[dict[str, Any]],
) -> list[str]:
    chain = []
    if event:
        chain.append(f"event:{event.get('event_type') or event.get('event_id') or 'endpoint_telemetry'}")
    if record:
        chain.append(f"detection:{record.get('rule_id') or record.get('alert_type') or 'rule'}")
    chain.extend(f"correlation:{item.get('rule_id') or item.get('alert_type') or 'rule'}" for item in correlations[:5])
    chain.extend(f"killchain:{item.get('stage')}" for item in killchain[:5] if item.get("stage"))
    return list(dict.fromkeys(chain))


def _safe_event_ref(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": record.get("event_id") or "",
        "event_type": record.get("event_type") or "",
        "timestamp": record.get("timestamp") or "",
        "host_id": record.get("host_id") or "",
    }


def _to_dict(item: Any) -> dict[str, Any]:
    if isinstance(item, dict):
        return dict(item)
    to_dict = getattr(item, "to_dict", None)
    if callable(to_dict):
        result = to_dict()
        return result if isinstance(result, dict) else {}
    if is_dataclass(item):
        return asdict(item)
    return {}


__all__ = ["DetectionExplanation", "ExplainabilityEngine", "explain_detection"]
