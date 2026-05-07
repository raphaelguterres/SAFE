from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from storage.storage_adapter import RetentionPolicy, SQLiteStorageAdapter


def _event(host_id: str, event_id: str):
    return {
        "event_id": event_id,
        "host_id": host_id,
        "event_type": "process_execution",
        "severity": "low",
        "timestamp": "2026-05-06T12:00:00Z",
        "process_name": "cmd.exe",
    }


def test_sqlite_storage_adapter_isolates_hot_events_by_tenant(tmp_path):
    adapter = SQLiteStorageAdapter(tmp_path / "xdr_storage.db")

    adapter.write_hot_event("tenant-a", _event("host-a", "evt-a"))
    adapter.write_hot_event("tenant-b", _event("host-b", "evt-b"))

    tenant_a = adapter.query_hot_events(tenant_id="tenant-a")
    tenant_b = adapter.query_hot_events(tenant_id="tenant-b")

    assert [item.record_id for item in tenant_a] == ["evt-a"]
    assert [item.record_id for item in tenant_b] == ["evt-b"]
    assert tenant_a[0].payload["host_id"] == "host-a"


def test_storage_adapter_requires_tenant_scope(tmp_path):
    adapter = SQLiteStorageAdapter(tmp_path / "xdr_storage.db")

    with pytest.raises(ValueError, match="tenant_id_required"):
        adapter.query_hot_events(tenant_id="")


def test_storage_adapter_retention_cleanup(tmp_path):
    adapter = SQLiteStorageAdapter(
        tmp_path / "xdr_storage.db",
        retention=RetentionPolicy(hot_events_days=1),
    )
    adapter.write_hot_event("tenant-a", _event("host-a", "evt-a"))

    deleted = adapter.cleanup_retention(now=datetime.now(timezone.utc) + timedelta(days=2))

    assert deleted["hot_events"] == 1
    assert adapter.query_hot_events(tenant_id="tenant-a") == []


def test_storage_adapter_reports_safe_migration_status(tmp_path):
    adapter = SQLiteStorageAdapter(tmp_path / "xdr_storage.db")

    status = adapter.migration_status()

    assert status["backend"] == "sqlite"
    assert status["schema_version"] == 1
    assert status["pending"] == 0
    assert adapter.stats()["tables"]["hot_events"] == 0
