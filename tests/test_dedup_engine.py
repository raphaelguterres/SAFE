from __future__ import annotations

from xdr.dedup_engine import EventDeduplicationEngine


def _event(**overrides):
    payload = {
        "tenant_id": "tenant-a",
        "host_id": "host-1",
        "event_type": "process_execution",
        "severity": "low",
        "process_name": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": "powershell.exe -NoP",
        "username": "alice",
        "timestamp": "2026-05-06T12:00:00Z",
    }
    payload.update(overrides)
    return payload


def test_dedup_suppresses_repeated_process_events_within_ttl():
    engine = EventDeduplicationEngine(ttl_seconds=30)

    first = engine.check(_event(), now=1000)
    second = engine.check(_event(event_id="different-id"), now=1001)

    assert first.is_duplicate is False
    assert second.is_duplicate is True
    assert second.deduplicated_count == 1
    assert second.suppression_reason == "repeated_process_event"


def test_dedup_allows_same_event_after_ttl_expires():
    engine = EventDeduplicationEngine(ttl_seconds=5)

    first = engine.check(_event(), now=1000)
    second = engine.check(_event(), now=1007)

    assert first.is_duplicate is False
    assert second.is_duplicate is False


def test_dedup_fingerprint_is_tenant_scoped():
    engine = EventDeduplicationEngine(ttl_seconds=60)

    tenant_a = engine.check(_event(tenant_id="tenant-a"), now=1000)
    tenant_b = engine.check(_event(tenant_id="tenant-b"), now=1001)

    assert tenant_a.is_duplicate is False
    assert tenant_b.is_duplicate is False
    assert tenant_a.fingerprint != tenant_b.fingerprint


def test_deduplicate_batch_reports_duplicates():
    engine = EventDeduplicationEngine(ttl_seconds=60)
    batch = engine.deduplicate_batch([_event(), _event(), _event(command_line="whoami")], now=1000)

    assert batch.accepted_count == 2
    assert batch.duplicate_count == 1
    assert batch.duplicates[0].suppression_reason == "repeated_process_event"
