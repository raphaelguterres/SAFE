"""Hash-chain helpers for SAFE audit logs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditIntegrityResult:
    valid: bool
    checked_records: int
    first_broken_record: int | None
    last_hash: str
    mode: str = "virtual_chain"
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def canonicalize_event(event: dict[str, Any]) -> str:
    clean = {
        str(key): value
        for key, value in dict(event or {}).items()
        if key not in {"previous_hash", "current_hash"}
    }
    return json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def event_hash(event: dict[str, Any], previous_hash: str) -> str:
    digest = hashlib.sha256()
    digest.update(str(previous_hash or GENESIS_HASH).encode("ascii"))
    digest.update(b"\n")
    digest.update(canonicalize_event(event).encode("utf-8"))
    return digest.hexdigest()


def chain_events(events: list[dict[str, Any]], *, previous_hash: str = GENESIS_HASH) -> list[dict[str, Any]]:
    chained: list[dict[str, Any]] = []
    prev = previous_hash
    for event in events:
        item = dict(event)
        item["previous_hash"] = prev
        item["current_hash"] = event_hash(item, prev)
        prev = item["current_hash"]
        chained.append(item)
    return chained


def verify_events(events: list[dict[str, Any]]) -> AuditIntegrityResult:
    previous = GENESIS_HASH
    checked = 0
    has_stored_chain = any("current_hash" in item or "previous_hash" in item for item in events)
    for index, event in enumerate(events, start=1):
        if has_stored_chain:
            if str(event.get("previous_hash") or "") != previous:
                return AuditIntegrityResult(False, checked, index, previous, mode="stored_chain", reason="previous_hash_mismatch")
            expected = event_hash(event, previous)
            if str(event.get("current_hash") or "") != expected:
                return AuditIntegrityResult(False, checked, index, previous, mode="stored_chain", reason="current_hash_mismatch")
            previous = str(event.get("current_hash"))
        else:
            previous = event_hash(event, previous)
        checked += 1
    return AuditIntegrityResult(True, checked, None, previous, mode="stored_chain" if has_stored_chain else "virtual_chain")


def verify_audit_log(path: str | Path, *, limit: int = 5000) -> AuditIntegrityResult:
    log_path = Path(path)
    if not log_path.exists():
        return AuditIntegrityResult(True, 0, None, GENESIS_HASH, reason="log_not_found")
    events: list[dict[str, Any]] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            if line_no > max(1, int(limit)):
                break
            text = line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                return AuditIntegrityResult(False, len(events), line_no, GENESIS_HASH, reason="invalid_json")
            if isinstance(parsed, dict):
                events.append(parsed)
    return verify_events(events)
