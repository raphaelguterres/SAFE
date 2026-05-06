from __future__ import annotations

from xdr.killchain_engine import KillChainEngine, KillChainStage
from xdr.pipeline import XDRPipeline
from xdr.schema import EndpointEvent


def _event(**overrides):
    payload = {
        "host_id": "host-kc-01",
        "event_type": "process_execution",
        "severity": "high",
        "timestamp": "2026-05-06T12:00:00Z",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -nop -enc AAAA",
        "parent_process": "winword.exe",
        "source": "agent",
        "platform": "windows",
        "details": {},
    }
    payload.update(overrides)
    return EndpointEvent.from_payload(payload)


def test_killchain_maps_suspicious_powershell_to_execution_and_evasion():
    engine = KillChainEngine()
    findings = engine.map_event_to_killchain(_event())
    stages = {item.stage for item in findings}

    assert KillChainStage.EXECUTION in stages
    assert KillChainStage.DEFENSE_EVASION in stages
    assert all(item.recommended_response for item in findings)
    assert all(item.risk_modifier > 0 for item in findings)


def test_killchain_maps_persistence_and_c2_events():
    engine = KillChainEngine()
    persistence = engine.map_event_to_killchain(
        _event(
            event_type="persistence_indicator",
            process_name="powershell.exe",
            command_line="",
            persistence_method="registry_run_key",
            persistence_target=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        )
    )
    network = engine.map_event_to_killchain(
        _event(
            event_type="network_connection",
            process_name="powershell.exe",
            command_line="",
            network_direction="outbound",
            network_dst_ip="8.8.8.8",
            network_dst_port=8443,
            tags=["beaconing"],
        )
    )

    assert any(item.stage == KillChainStage.PERSISTENCE for item in persistence)
    assert any(item.stage == KillChainStage.COMMAND_AND_CONTROL for item in network)


def test_xdr_pipeline_exposes_killchain_outcome_fields():
    outcome = XDRPipeline().process_event(_event())

    assert outcome.killchain_findings
    assert outcome.killchain_stage_summary["highest_stage"]
    assert outcome.attack_progression_score > 0
    payload = outcome.to_dict()
    assert payload["killchain_findings"]
    assert payload["attack_progression_score"] == outcome.attack_progression_score
    security_events = outcome.to_security_events()
    assert any(item.event_type.startswith("killchain_") for item in security_events)
