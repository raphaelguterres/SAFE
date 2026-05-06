from __future__ import annotations

from engine.attack_timeline import AttackTimelineEngine
from xdr.attack_timeline import build_attack_timeline, build_host_attack_timeline
from xdr.killchain_engine import KillChainFinding, KillChainStage


def test_legacy_engine_build_timeline():
    engine = AttackTimelineEngine()

    events = [
        {
            "timestamp": "2026-03-31T19:10:02Z",
            "host_id": "workstation-01",
            "event_type": "port_scan_suspected",
            "severity": "low",
            "message": "Port scan suspected from external source",
            "source": "netguard",
            "metadata": {},
        },
        {
            "timestamp": "2026-03-31T19:10:15Z",
            "host_id": "workstation-01",
            "event_type": "multiple_failed_logins",
            "severity": "high",
            "message": "Multiple failed logins detected",
            "source": "netguard",
            "metadata": {},
        },
        {
            "timestamp": "2026-03-31T19:10:45Z",
            "host_id": "workstation-01",
            "event_type": "suspicious_process_execution",
            "severity": "high",
            "message": "Encoded PowerShell execution detected",
            "source": "netguard",
            "metadata": {},
        },
    ]

    timelines = engine.build_timelines(events)

    assert len(timelines) == 1
    assert timelines[0].host_id == "workstation-01"
    assert timelines[0].risk_score > 0
    assert len(timelines[0].steps) == 3
    assert timelines[0].steps[0].phase == "Reconnaissance"


def _finding(stage: KillChainStage, technique: str, risk: int = 8) -> KillChainFinding:
    return KillChainFinding(
        stage=stage,
        mitre_tactic=stage.value,
        mitre_technique=technique,
        confidence=0.9,
        evidence=f"{stage.value} evidence",
        recommended_response="collect_diagnostics",
        risk_modifier=risk,
    )


def test_attack_timeline_builds_host_story_and_next_action():
    timeline = build_attack_timeline(
        host_id="host-story-01",
        events=[
            {
                "host_id": "host-story-01",
                "event_type": "process_execution",
                "severity": "high",
                "timestamp": "2026-05-06T12:00:00Z",
                "process_name": "powershell.exe",
            }
        ],
        killchain_findings=[
            _finding(KillChainStage.EXECUTION, "T1059.001"),
            _finding(KillChainStage.PERSISTENCE, "T1547.001"),
            _finding(KillChainStage.CREDENTIAL_ACCESS, "T1110"),
            _finding(KillChainStage.COMMAND_AND_CONTROL, "T1071"),
        ],
    )

    assert timeline["host_id"] == "host-story-01"
    assert "execution" in timeline["active_stages"]
    assert timeline["highest_stage"] == "command_and_control"
    assert timeline["progression_score"] > 50
    assert "late-stage intrusion" in timeline["likely_attack_story"]
    assert "containment approval" in timeline["recommended_next_action"]


def test_host_attack_timeline_accepts_pipeline_outcome_dicts():
    timeline = build_host_attack_timeline(
        "host-dict-01",
        [
            {
                "event": {
                    "host_id": "host-dict-01",
                    "event_type": "network_connection",
                    "severity": "high",
                    "timestamp": "2026-05-06T12:01:00Z",
                    "network_dst_ip": "8.8.8.8",
                },
                "killchain_findings": [
                    {
                        "stage": "command_and_control",
                        "mitre_tactic": "command_and_control",
                        "mitre_technique": "T1071",
                        "confidence": 0.86,
                        "evidence": "beacon-like egress",
                        "recommended_response": "consider_network_containment",
                        "risk_modifier": 12,
                    }
                ],
            }
        ],
    )

    assert timeline["active_stages"] == ["command_and_control"]
    assert timeline["timeline"]
    assert timeline["recommended_next_action"]
