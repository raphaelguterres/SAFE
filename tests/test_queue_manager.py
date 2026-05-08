from xdr.queue_manager import ResilientQueueManager


def test_queue_manager_prioritizes_p0_and_sheds_low_priority():
    queue = ResilientQueueManager(max_size=2, dead_letter_size=5, per_tenant_limit=10)
    assert queue.submit(tenant_id="t1", event_type="debug", payload={"n": 1}, priority="P3").accepted
    assert queue.submit(tenant_id="t1", event_type="debug", payload={"n": 2}, priority="P3").accepted

    result = queue.submit(tenant_id="t1", event_type="critical", payload={"n": 3}, priority="P0")

    assert result.accepted is True
    snapshot = queue.snapshot()
    assert snapshot["total_depth"] == 2
    assert snapshot["dead_letter_depth"] == 1
    batch = queue.next_batch(limit=1)
    assert batch[0].priority == "P0"


def test_queue_manager_dead_letters_after_retry_budget():
    queue = ResilientQueueManager(max_size=5, dead_letter_size=5)
    result = queue.submit(tenant_id="tenant-a", event_type="telemetry", payload={"ok": True}, max_attempts=1)
    message = queue.next_batch()[0]

    assert message.message_id == result.message_id
    assert queue.fail(message.message_id, "boom") is True
    assert queue.snapshot()["dead_letter_depth"] == 1


def test_queue_manager_rejects_missing_tenant_fail_closed():
    queue = ResilientQueueManager()
    result = queue.submit(tenant_id="", event_type="telemetry", payload={})

    assert result.accepted is False
    assert result.reason == "missing_tenant_or_event"
