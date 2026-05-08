from xdr.disaster_recovery import DisasterRecoveryManager


def test_disaster_recovery_snapshot_redacts_and_verifies_integrity():
    manager = DisasterRecoveryManager()
    snapshot = manager.export_snapshot(
        tenant_id="tenant-a",
        incidents=[{"tenant_id": "tenant-a", "id": "I1", "api_key": "secret"}, {"tenant_id": "tenant-b", "id": "I2"}],
        audit_logs=[{"tenant_id": "tenant-a", "event": "x", "token": "abc"}],
        queue_state={"depth": 1, "host_key": "hidden"},
    )

    assert snapshot["incidents"] == [{"tenant_id": "tenant-a", "id": "I1", "api_key": "[redacted]"}]
    assert snapshot["queue_state"]["host_key"] == "[redacted]"
    assert manager.verify_snapshot(snapshot)["valid"] is True


def test_disaster_recovery_restore_plan_blocks_cross_tenant_restore():
    manager = DisasterRecoveryManager()
    snapshot = manager.export_snapshot(tenant_id="tenant-a", incidents=[], audit_logs=[])

    plan = manager.tenant_safe_restore_plan(snapshot=snapshot, target_tenant_id="tenant-b")

    assert plan["allowed"] is False
    assert plan["reason"] == "tenant_mismatch"
