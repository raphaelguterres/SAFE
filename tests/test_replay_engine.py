from xdr.replay_engine import AttackReplayEngine


def test_replay_engine_reprocesses_events_deterministically_and_scopes_tenant():
    events = [
        {"tenant_id": "tenant-a", "host_id": "h1", "event_type": "process_execution", "process_name": "powershell.exe"},
        {"tenant_id": "tenant-b", "host_id": "h2", "event_type": "process_execution", "process_name": "cmd.exe"},
    ]

    def detector(event):
        return [{"rule_id": "R-PS", "confidence": 0.8}] if event.process.name == "powershell.exe" else []

    result = AttackReplayEngine().replay(tenant_id="tenant-a", events=events, detection_callable=detector, replay_id="test")

    assert result.event_count == 1
    assert result.detection_count == 1
    assert result.results[0].tenant_id == "tenant-a"
    assert result.safe_mode is True


def test_replay_engine_rejects_missing_tenant():
    try:
        AttackReplayEngine().replay(tenant_id="", events=[])
    except ValueError as exc:
        assert "tenant_id" in str(exc)
    else:
        raise AssertionError("expected ValueError")
