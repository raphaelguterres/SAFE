"""Tenant-scoped security data search helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class SearchResult:
    result_type: str
    title: str
    tenant_id: str
    score: int
    record: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_type": self.result_type,
            "title": self.title,
            "tenant_id": self.tenant_id,
            "score": self.score,
            "record": dict(self.record),
        }


class SecurityDataSearchEngine:
    """Simple enterprise-safe search over tenant-scoped security data."""

    def search(
        self,
        *,
        tenant_id: str,
        query: str,
        datasets: Mapping[str, list[Mapping[str, Any]]],
        filters: Mapping[str, Any] | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        tenant = str(tenant_id or "").strip()
        if not tenant:
            raise ValueError("tenant_id is required")
        terms = [term.lower() for term in str(query or "").split() if term.strip()]
        filters = filters or {}
        results: list[SearchResult] = []
        for dataset_name, records in datasets.items():
            for record in records:
                if str(record.get("tenant_id") or tenant) != tenant:
                    continue
                if not filter_match(record, filters):
                    continue
                score = score_record(record, terms)
                if terms and score == 0:
                    continue
                results.append(
                    SearchResult(
                        result_type=dataset_name,
                        title=title_for(dataset_name, record),
                        tenant_id=tenant,
                        score=score,
                        record=redact(record),
                    )
                )
        results.sort(key=lambda item: (item.score, item.result_type, item.title), reverse=True)
        limited = results[: max(1, int(limit))]
        return {
            "tenant_id": tenant,
            "query": query,
            "total": len(results),
            "results": [item.to_dict() for item in limited],
            "pivots": build_pivots(limited),
        }


def filter_match(record: Mapping[str, Any], filters: Mapping[str, Any]) -> bool:
    for key, expected in filters.items():
        if expected in (None, "", "all"):
            continue
        if str(record.get(key) or "").lower() != str(expected).lower():
            return False
    return True


def score_record(record: Mapping[str, Any], terms: list[str]) -> int:
    if not terms:
        return 1
    text = " ".join(flatten_values(record)).lower()
    return sum(10 for term in terms if term in text)


def flatten_values(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        values: list[str] = []
        for item in value.values():
            values.extend(flatten_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(flatten_values(item))
        return values
    return [str(value)]


def title_for(dataset_name: str, record: Mapping[str, Any]) -> str:
    for key in ("title", "hostname", "host_id", "user_id", "ioc", "rule_id", "incident_id", "event_type", "campaign_key"):
        if record.get(key):
            return f"{dataset_name}: {record[key]}"
    return dataset_name


def build_pivots(results: list[SearchResult]) -> dict[str, list[str]]:
    pivots: dict[str, set[str]] = {"hosts": set(), "users": set(), "iocs": set(), "incidents": set(), "campaigns": set()}
    for result in results:
        record = result.record
        for key in ("host_id", "host", "hostname"):
            if record.get(key):
                pivots["hosts"].add(str(record[key]))
        for key in ("user_id", "username", "user"):
            if record.get(key):
                pivots["users"].add(str(record[key]))
        for key in ("ioc", "dst_ip", "domain", "sha256"):
            if record.get(key):
                pivots["iocs"].add(str(record[key]))
        if record.get("incident_id"):
            pivots["incidents"].add(str(record["incident_id"]))
        if record.get("campaign_key"):
            pivots["campaigns"].add(str(record["campaign_key"]))
    return {key: sorted(value) for key, value in pivots.items()}


def redact(record: Mapping[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in record.items():
        lower = str(key).lower()
        if any(secret in lower for secret in ("secret", "token", "password", "api_key", "host_key")):
            redacted[str(key)] = "[redacted]"
        elif isinstance(value, Mapping):
            redacted[str(key)] = redact(value)
        else:
            redacted[str(key)] = value
    return redacted
