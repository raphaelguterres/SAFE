"""Security data retention planning for SAFE."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping


@dataclass(frozen=True)
class RetentionPolicy:
    data_class: str
    hot_days: int
    warm_days: int
    archive_days: int
    legal_hold_supported: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_class": self.data_class,
            "hot_days": self.hot_days,
            "warm_days": self.warm_days,
            "archive_days": self.archive_days,
            "legal_hold_supported": self.legal_hold_supported,
        }


DEFAULT_POLICIES = {
    "telemetry": RetentionPolicy("telemetry", 14, 90, 365),
    "audit": RetentionPolicy("audit", 30, 180, 730),
    "evidence": RetentionPolicy("evidence", 90, 365, 1095),
    "incident": RetentionPolicy("incident", 180, 730, 1825),
}


class RetentionEngine:
    def __init__(self, policies: Mapping[str, RetentionPolicy] | None = None) -> None:
        self.policies = dict(policies or DEFAULT_POLICIES)

    def classify_record(self, record: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        current = now or datetime.now(timezone.utc)
        data_class = str(record.get("data_class") or record.get("category") or "telemetry").lower()
        policy = self.policies.get(data_class, self.policies["telemetry"])
        timestamp = parse_time(record.get("timestamp") or record.get("created_at")) or current
        age_days = max(0, (current - timestamp).days)
        if bool(record.get("legal_hold")) and policy.legal_hold_supported:
            tier = "legal_hold"
            action = "retain"
        elif age_days <= policy.hot_days:
            tier = "hot"
            action = "retain_hot"
        elif age_days <= policy.warm_days:
            tier = "warm"
            action = "move_to_warm"
        elif age_days <= policy.archive_days:
            tier = "archive"
            action = "archive"
        else:
            tier = "expired"
            action = "eligible_for_purge"
        return {
            "data_class": policy.data_class,
            "age_days": age_days,
            "tier": tier,
            "action": action,
            "policy": policy.to_dict(),
        }

    def build_plan(self, records: list[Mapping[str, Any]], *, tenant_id: str, now: datetime | None = None) -> dict[str, Any]:
        scoped = [record for record in records if str(record.get("tenant_id") or tenant_id) == tenant_id]
        decisions = [self.classify_record(record, now=now) | {"record_id": str(record.get("event_id") or record.get("id") or "")} for record in scoped]
        return {
            "tenant_id": tenant_id,
            "record_count": len(scoped),
            "decisions": decisions,
            "summary": {
                "hot": sum(1 for item in decisions if item["tier"] == "hot"),
                "warm": sum(1 for item in decisions if item["tier"] == "warm"),
                "archive": sum(1 for item in decisions if item["tier"] == "archive"),
                "expired": sum(1 for item in decisions if item["tier"] == "expired"),
                "legal_hold": sum(1 for item in decisions if item["tier"] == "legal_hold"),
            },
        }


def parse_time(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
