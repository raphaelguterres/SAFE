"""Memory-safe defensive indicators for SAFE endpoint telemetry."""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

try:  # pragma: no cover - depends on endpoint package availability
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None  # type: ignore


@dataclass(slots=True)
class MemoryIndicator:
    indicator_type: str
    severity: str
    confidence: float
    process_name: str
    pid: int
    evidence: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["confidence"] = round(max(0.0, min(1.0, float(self.confidence))), 2)
        return payload


def collect_memory_indicators(
    *,
    processes: Iterable[Any] | None = None,
    rss_threshold_mb: int = 1024,
    handle_threshold: int = 2500,
) -> list[dict[str, Any]]:
    """Collect coarse defensive indicators without dumping or reading memory."""

    indicators: list[MemoryIndicator] = []
    source = list(processes) if processes is not None else _iter_processes()
    for proc in source:
        info = _process_info(proc)
        rss_mb = int(info.get("rss_mb") or 0)
        handles = int(info.get("num_handles") or info.get("num_fds") or 0)
        pid = int(info.get("pid") or 0)
        name = str(info.get("name") or "unknown")
        if rss_mb >= rss_threshold_mb:
            indicators.append(
                MemoryIndicator(
                    indicator_type="suspicious_memory_usage_spike",
                    severity="medium",
                    confidence=0.68,
                    process_name=name,
                    pid=pid,
                    evidence=f"Process memory usage above threshold: {rss_mb} MB.",
                    details={"rss_mb": rss_mb, "threshold_mb": rss_threshold_mb},
                    timestamp=_utc_now(),
                )
            )
        if handles >= handle_threshold:
            indicators.append(
                MemoryIndicator(
                    indicator_type="process_handle_anomaly",
                    severity="medium",
                    confidence=0.65,
                    process_name=name,
                    pid=pid,
                    evidence=f"Process handle count above threshold: {handles}.",
                    details={"handle_count": handles, "threshold": handle_threshold},
                    timestamp=_utc_now(),
                )
            )
        if bool(info.get("unsigned_memory_indicator")):
            indicators.append(
                MemoryIndicator(
                    indicator_type="unsigned_memory_injection_indicator",
                    severity="high",
                    confidence=0.72,
                    process_name=name,
                    pid=pid,
                    evidence="Endpoint reported a defensive unsigned memory indicator.",
                    details={"source": "endpoint_indicator"},
                    timestamp=_utc_now(),
                )
            )
    return [item.to_dict() for item in indicators]


def _iter_processes() -> list[Any]:
    if psutil is None:
        return []
    try:
        return list(psutil.process_iter(["pid", "name", "memory_info", "num_handles", "num_fds"]))
    except Exception:
        return []


def _process_info(proc: Any) -> dict[str, Any]:
    if isinstance(proc, dict):
        return dict(proc)
    info = getattr(proc, "info", None) or {}
    memory_info = info.get("memory_info")
    rss = getattr(memory_info, "rss", 0) if memory_info is not None else 0
    payload = {
        "pid": info.get("pid", getattr(proc, "pid", 0)),
        "name": info.get("name", ""),
        "rss_mb": int(rss / (1024 * 1024)) if rss else 0,
    }
    for attr in ("num_handles", "num_fds"):
        value = info.get(attr)
        if value is None and hasattr(proc, attr):
            method = getattr(proc, attr)
            if callable(method):
                try:
                    value = method()
                except Exception:
                    value = 0
        if value:
            payload[attr] = value
    return payload


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
