from __future__ import annotations

from xdr.behavior_engine import BehavioralFinding
from xdr.host_defense_engine import HostDefenseEngine, HostProtectionState
from xdr.killchain_engine import KillChainFinding, KillChainStage


def test_host_defense_engine_elevates_state_from_killchain_and_behavior():
    state = HostDefenseEngine().evaluate_host_security_state(
        host_id="host-defense",
        base_risk_score=45,
        killchain_findings=[
            KillChainFinding(
                stage=KillChainStage.COMMAND_AND_CONTROL,
                mitre_tactic="command_and_control",
                mitre_technique="T1071",
                confidence=0.9,
                evidence="Beaconing pattern",
                recommended_response="consider_network_containment",
                risk_modifier=18,
            )
        ],
        behavioral_anomalies=[
            BehavioralFinding(
                behavior_type="unusual_outbound_beaconing",
                severity="high",
                confidence=0.86,
                mitre_mapping={"tactic": "command_and_control", "technique": "T1071"},
                evidence="Repeated outbound beaconing",
                host_id="host-defense",
            )
        ],
    )

    assert state.state == HostProtectionState.ELEVATED_RISK
    assert state.containment_recommended is True
    assert "command_and_control" in state.active_attack_stages


def test_host_defense_engine_marks_isolated_from_response_action():
    state = HostDefenseEngine().evaluate_host_security_state(
        host_id="host-contained",
        base_risk_score=80,
        response_actions=[
            {"action_type": "safe_host_isolation", "status": "succeeded"},
        ],
    )

    assert state.state == HostProtectionState.ISOLATED
    assert "prepare_rollback_plan" in state.recommended_actions
