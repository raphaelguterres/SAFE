from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _tenant_scope_module():
    root = Path(__file__).resolve().parents[1]
    path = root / "security" / "tenant_scope.py"
    spec = importlib.util.spec_from_file_location("tenant_scope_helpers", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_tenant_scope_helpers_fail_closed():
    helpers = _tenant_scope_module()

    assert helpers.require_tenant_scope("tenant-a") == "tenant-a"
    assert helpers.assert_same_tenant("tenant-a", "tenant-a") == "tenant-a"
    assert helpers.safe_tenant_filter("tenant-a", {"host_id": "h"}) == {"host_id": "h", "tenant_id": "tenant-a"}
    with pytest.raises(ValueError, match="tenant_id_required"):
        helpers.require_tenant_scope("")
    with pytest.raises(ValueError, match="wildcard"):
        helpers.require_tenant_scope("*")
    with pytest.raises(PermissionError, match="tenant_scope_mismatch"):
        helpers.assert_same_tenant("tenant-a", "tenant-b")


def test_storage_dedup_and_heartbeat_are_tenant_scoped(tmp_path):
    from storage.storage_adapter import SQLiteStorageAdapter
    from xdr.dedup_engine import EventDeduplicationEngine
    from xdr.heartbeat_engine import HostHeartbeatEngine

    storage = SQLiteStorageAdapter(tmp_path / "tenant.db")
    storage.write_hot_event("tenant-a", {"event_id": "same", "host_id": "host", "event_type": "process_execution"})
    storage.write_hot_event("tenant-b", {"event_id": "same", "host_id": "host", "event_type": "process_execution"})
    assert len(storage.query_hot_events(tenant_id="tenant-a")) == 1
    assert len(storage.query_hot_events(tenant_id="tenant-b")) == 1
    with pytest.raises(ValueError, match="tenant_id_required"):
        storage.query_hot_events(tenant_id="")

    dedup = EventDeduplicationEngine(ttl_seconds=60)
    base_event = {"event_type": "process_execution", "host_id": "host", "process_name": "cmd.exe"}
    assert dedup.check({**base_event, "tenant_id": "tenant-a"}).is_duplicate is False
    assert dedup.check({**base_event, "tenant_id": "tenant-b"}).is_duplicate is False
    assert dedup.check({**base_event, "tenant_id": "tenant-a"}).is_duplicate is True

    heartbeat = HostHeartbeatEngine()
    heartbeat.record_heartbeat(tenant_id="tenant-a", host_id="host")
    heartbeat.record_heartbeat(tenant_id="tenant-b", host_id="host", isolated=True)
    assert heartbeat.snapshot(tenant_id="tenant-a")[0]["state"] != heartbeat.snapshot(tenant_id="tenant-b")[0]["state"]
