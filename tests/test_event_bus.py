from xdr.event_bus import LiveSOCEventBus


def test_event_bus_is_tenant_scoped():
    bus = LiveSOCEventBus(default_consumer_queue_size=10)
    sub_a = bus.subscribe(tenant_id="tenant-a", channel="detections", consumer_id="a")
    sub_b = bus.subscribe(tenant_id="tenant-b", channel="detections", consumer_id="b")

    bus.publish(tenant_id="tenant-a", channel="detections", event_type="alert", payload={"risk": 90}, priority="P0")

    assert len(bus.poll(sub_a.subscription_id)) == 1
    assert bus.poll(sub_b.subscription_id) == []


def test_event_bus_backpressure_moves_oldest_to_dead_letter():
    bus = LiveSOCEventBus(default_consumer_queue_size=1, dead_letter_size=5)
    sub = bus.subscribe(tenant_id="tenant-a", channel="*", consumer_id="ui", max_queue_size=1)

    bus.publish(tenant_id="tenant-a", channel="incidents", event_type="incident.created", payload={"n": 1})
    bus.publish(tenant_id="tenant-a", channel="incidents", event_type="incident.updated", payload={"n": 2})

    events = bus.poll(sub.subscription_id)
    assert events[0]["payload"]["n"] == 2
    assert bus.snapshot()["dead_letter_depth"] == 1
