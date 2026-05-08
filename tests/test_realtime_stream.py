import pytest

from xdr.event_bus import LiveSOCEventBus
from xdr.realtime_stream import RealtimeStreamHub


def test_realtime_stream_requires_authenticated_tenant_context():
    hub = RealtimeStreamHub(event_bus=LiveSOCEventBus())

    with pytest.raises(PermissionError):
        hub.connect(
            tenant_id="tenant-a",
            user_id="analyst",
            channels=["incidents"],
            auth_context={"authenticated": False, "tenant_id": "tenant-a"},
        )


def test_realtime_stream_delivers_incremental_tenant_events():
    hub = RealtimeStreamHub(event_bus=LiveSOCEventBus())
    client = hub.connect(
        tenant_id="tenant-a",
        user_id="analyst",
        channels=["incidents"],
        auth_context={"authenticated": True, "tenant_id": "tenant-a", "role": "analyst"},
    )

    hub.publish(tenant_id="tenant-a", channel="incidents", event_type="incident.live", payload={"case": "C1"})
    hub.publish(tenant_id="tenant-b", channel="incidents", event_type="incident.live", payload={"case": "C2"})

    events = hub.poll(client.client_id)
    assert [event["payload"]["case"] for event in events] == ["C1"]
    assert hub.heartbeat(client.client_id)["ok"] is True
