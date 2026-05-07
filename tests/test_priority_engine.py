from __future__ import annotations

from xdr.priority_engine import TelemetryPriority, TelemetryPriorityEngine


def test_priority_engine_classifies_credential_access_as_p0():
    decision = TelemetryPriorityEngine().classify(
        {
            "tenant_id": "tenant-a",
            "host_id": "h1",
            "event_type": "process_execution",
            "severity": "high",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe comsvcs.dll, MiniDump lsass.exe",
            "tags": ["credential_access"],
        }
    )

    assert decision.priority == TelemetryPriority.P0
    assert decision.category == "critical"
    assert decision.score == 100


def test_priority_engine_classifies_powershell_encoded_as_p1():
    decision = TelemetryPriorityEngine().classify(
        {
            "tenant_id": "tenant-a",
            "host_id": "h1",
            "event_type": "script_execution",
            "severity": "medium",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
        }
    )

    assert decision.priority == TelemetryPriority.P1
    assert decision.category == "security"


def test_priority_engine_low_risk_telemetry_is_p3():
    decision = TelemetryPriorityEngine().classify(
        {
            "tenant_id": "tenant-a",
            "host_id": "h1",
            "event_type": "network_connection",
            "severity": "low",
            "process_name": "chrome.exe",
            "network_dst_ip": "198.51.100.10",
        }
    )

    assert decision.priority == TelemetryPriority.P3
    assert decision.category == "debug"
