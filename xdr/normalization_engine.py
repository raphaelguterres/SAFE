"""Telemetry normalization engine for SAFE security data platform."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from schema.canonical_event import (
    AuthContext,
    CanonicalEvent,
    EventLineageRef,
    NetworkContext,
    ProcessContext,
    canonical_event_id,
    canonical_hash,
    make_raw_ref,
    utc_now_iso,
)


EVENT_CATEGORY_MAP = {
    "process_execution": "process",
    "script_execution": "process",
    "powershell": "process",
    "authentication": "auth",
    "login": "auth",
    "network_connection": "network",
    "dns_query": "network",
    "registry": "registry",
    "registry_set": "registry",
    "persistence_indicator": "persistence",
    "scheduled_task": "persistence",
    "behavioral_anomaly": "behavior",
}


@dataclass(frozen=True)
class NormalizationIssue:
    field: str
    reason: str
    severity: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field, "reason": self.reason, "severity": self.severity}


@dataclass(frozen=True)
class NormalizationResult:
    canonical_event: CanonicalEvent | None
    issues: list[NormalizationIssue] = field(default_factory=list)
    malformed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "canonical_event": self.canonical_event.to_dict() if self.canonical_event else None,
            "issues": [issue.to_dict() for issue in self.issues],
            "malformed": self.malformed,
        }


class TelemetryNormalizationEngine:
    """Normalize endpoint, auth, network and persistence telemetry."""

    def normalize(self, event: Any, *, tenant_id: str | None = None) -> NormalizationResult:
        raw = self._to_raw_mapping(event)
        issues: list[NormalizationIssue] = []
        if not raw:
            return NormalizationResult(None, [NormalizationIssue("event", "empty_or_unsupported", "medium")], True)

        event_type = normalize_key(_pick(raw, "event_type", "type", "alert_type") or "telemetry")
        category = normalize_category(event_type, raw)
        normalized_tenant = clean_text(tenant_id or _pick(raw, "tenant_id", "tenant") or "default", max_len=96)
        host_id = clean_text(_pick(raw, "host_id", "host", "hostname") or "", max_len=128)
        if not host_id:
            issues.append(NormalizationIssue("host_id", "missing_host_id", "medium"))
            host_id = "unknown"

        timestamp, timestamp_issue = normalize_timestamp(_pick(raw, "timestamp", "time", "created_at"))
        if timestamp_issue:
            issues.append(timestamp_issue)

        process = self._normalize_process(raw)
        network = self._normalize_network(raw)
        auth = self._normalize_auth(raw)
        confidence = clamp_float(_pick(raw, "confidence") or 0.65, 0.0, 1.0)
        user_id = clean_text(_pick(raw, "user_id", "username", "user") or auth.username, max_len=128)
        severity = normalize_severity(_pick(raw, "severity", "level"))
        raw_hash = canonical_hash(raw)
        canonical = CanonicalEvent(
            event_id=clean_text(_pick(raw, "event_id", "id"), max_len=96) or canonical_event_id(raw),
            tenant_id=normalized_tenant,
            host_id=host_id,
            user_id=user_id,
            event_type=event_type,
            category=category,
            timestamp=timestamp,
            process=process,
            network=network,
            auth=auth,
            telemetry_source=clean_text(_pick(raw, "source", "telemetry_source") or "safe", max_len=64),
            severity=severity,
            raw_event_ref=make_raw_ref(raw),
            normalized_fields={
                "original_event_type": _pick(raw, "event_type", "type", "alert_type") or "",
                "raw_hash": raw_hash,
                "normalization_issues": [issue.to_dict() for issue in issues],
            },
            enrichment={},
            lineage=EventLineageRef(
                source=clean_text(_pick(raw, "source", "telemetry_source") or "safe", max_len=64),
                source_event_id=clean_text(_pick(raw, "event_id", "id"), max_len=96),
                ingest_id=clean_text(_pick(raw, "ingest_id", "batch_id"), max_len=96),
                raw_hash=raw_hash,
                parent_event_id=clean_text(_pick(raw, "parent_event_id"), max_len=96),
            ),
            confidence=confidence,
        )
        return NormalizationResult(canonical, issues, malformed=False)

    def _to_raw_mapping(self, event: Any) -> dict[str, Any]:
        if isinstance(event, Mapping):
            return dict(event)
        to_dict = getattr(event, "to_dict", None)
        if callable(to_dict):
            result = to_dict()
            return dict(result) if isinstance(result, Mapping) else {}
        if hasattr(event, "__dict__"):
            return dict(getattr(event, "__dict__", {}))
        return {}

    def _normalize_process(self, raw: Mapping[str, Any]) -> ProcessContext:
        details = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
        return ProcessContext(
            name=clean_text(_pick(raw, "process_name", "process") or details.get("process_name"), max_len=128),
            pid=clean_int(_pick(raw, "pid") if _pick(raw, "pid") is not None else details.get("pid")),
            ppid=clean_int(_pick(raw, "ppid") if _pick(raw, "ppid") is not None else details.get("ppid")),
            command_line=clean_text(_pick(raw, "command_line", "cmdline") or details.get("command_line"), max_len=4096),
            parent_name=clean_text(_pick(raw, "parent_process") or details.get("parent_process"), max_len=128),
            executable_path=clean_text(_pick(raw, "process_path", "image_path", "path") or details.get("process_path"), max_len=512),
            sha256=clean_text(_pick(raw, "sha256", "process_hash") or details.get("sha256"), max_len=96).lower(),
            signer=clean_text(_pick(raw, "signer", "process_signer") or details.get("signer"), max_len=160),
        )

    def _normalize_network(self, raw: Mapping[str, Any]) -> NetworkContext:
        details = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
        return NetworkContext(
            src_ip=clean_text(_pick(raw, "src_ip", "source_ip") or details.get("src_ip"), max_len=128),
            src_port=clean_int(_pick(raw, "src_port") if _pick(raw, "src_port") is not None else details.get("src_port")),
            dst_ip=clean_text(
                _pick(raw, "dst_ip", "destination_ip", "network_dst_ip", "remote_ip") or details.get("network_dst_ip"),
                max_len=128,
            ),
            dst_port=clean_int(
                _pick(raw, "dst_port", "destination_port", "network_dst_port", "remote_port")
                if _pick(raw, "dst_port", "destination_port", "network_dst_port", "remote_port") is not None
                else details.get("network_dst_port")
            ),
            protocol=clean_text(_pick(raw, "protocol") or details.get("protocol"), max_len=16).lower(),
            direction=clean_text(_pick(raw, "direction", "network_direction") or details.get("network_direction"), max_len=16).lower(),
            domain=clean_text(_pick(raw, "domain", "dns_query", "hostname") or details.get("domain"), max_len=253).lower(),
        )

    def _normalize_auth(self, raw: Mapping[str, Any]) -> AuthContext:
        details = raw.get("details") if isinstance(raw.get("details"), Mapping) else {}
        return AuthContext(
            username=clean_text(_pick(raw, "username", "user", "user_id") or details.get("username"), max_len=128),
            result=clean_text(_pick(raw, "auth_result", "result", "status") or details.get("auth_result"), max_len=32).lower(),
            source_ip=clean_text(_pick(raw, "auth_source_ip", "source_ip", "src_ip") or details.get("auth_source_ip"), max_len=128),
            logon_type=clean_text(_pick(raw, "logon_type") or details.get("logon_type"), max_len=64),
            identity_provider=clean_text(_pick(raw, "identity_provider", "idp") or details.get("identity_provider"), max_len=96),
        )


def normalize_timestamp(value: Any) -> tuple[str, NormalizationIssue | None]:
    if value in (None, ""):
        return utc_now_iso(), NormalizationIssue("timestamp", "missing_timestamp_defaulted")
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"), None
    except Exception:
        return utc_now_iso(), NormalizationIssue("timestamp", "invalid_timestamp_defaulted", "medium")


def normalize_key(value: Any) -> str:
    return clean_text(value, max_len=80).lower().replace("-", "_").replace(" ", "_") or "telemetry"


def normalize_category(event_type: str, raw: Mapping[str, Any]) -> str:
    explicit = clean_text(raw.get("category"), max_len=64).lower().replace("-", "_").replace(" ", "_")
    if explicit:
        return explicit
    if event_type in EVENT_CATEGORY_MAP:
        return EVENT_CATEGORY_MAP[event_type]
    if "powershell" in event_type:
        return "process"
    if "auth" in event_type or "login" in event_type:
        return "auth"
    if "network" in event_type or "dns" in event_type:
        return "network"
    return "telemetry"


def normalize_severity(value: Any) -> str:
    severity = clean_text(value, max_len=24).lower()
    return severity if severity in {"low", "medium", "high", "critical"} else "low"


def clean_text(value: Any, *, max_len: int = 512) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()[:max_len]


def clean_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def clamp_float(value: Any, low: float, high: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = low
    if number > 1.0 and high <= 1.0:
        number = number / 100.0
    return max(low, min(high, number))


def _pick(raw: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None
