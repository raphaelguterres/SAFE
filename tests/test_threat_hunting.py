from __future__ import annotations

from xdr.threat_hunting import ThreatHuntingEngine


def test_threat_hunting_detects_lateral_movement_indicators():
    records = [
        {"host_id": "host-hunt", "event_type": "network_connection", "network_dst_port": 445, "network_dst_ip": f"10.0.0.{idx}"}
        for idx in range(3)
    ]

    hunts = ThreatHuntingEngine().run_hunts(records)

    assert any(item.hunt_name == "repeated_lateral_movement_indicators" for item in hunts)


def test_threat_hunting_detects_auth_chain():
    records = [
        {"host_id": "host-auth", "event_type": "authentication", "auth_source_ip": "10.0.0.5", "username": "admin", "auth_result": "failure"},
        {"host_id": "host-auth", "event_type": "authentication", "auth_source_ip": "10.0.0.5", "username": "admin", "auth_result": "failure"},
        {"host_id": "host-auth", "event_type": "authentication", "auth_source_ip": "10.0.0.5", "username": "admin", "auth_result": "failure"},
        {"host_id": "host-auth", "event_type": "authentication", "auth_source_ip": "10.0.0.5", "username": "admin", "auth_result": "success"},
    ]

    hunts = ThreatHuntingEngine().run_hunts(records)

    assert any(item.hunt_name == "suspicious_authentication_chain" for item in hunts)
