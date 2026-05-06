"""Tests for the EDR active-defense facade modules."""

from engine.killchain_engine import KillChainEngine
from engine.response_engine import ActiveDefenseEngine, ActiveDefensePolicy
from engine.risk_engine import risk_level_for_score, score_event
from engine.threat_intel import ThreatIntelClient, classify_ioc


def test_killchain_engine_normalizes_required_event_schema():
    event = {
        "event_type": "powershell_encoded",
        "source_ip": "203.0.113.10",
        "process_name": "powershell.exe",
        "severity": "high",
    }

    normalized = KillChainEngine().normalize_event(event).to_dict()

    assert normalized["event_type"] == "powershell_encoded"
    assert normalized["source_ip"] == "203.0.113.10"
    assert normalized["process"] == "powershell.exe"
    assert normalized["killchain_stage"] == "exploitation"
    assert 0 <= normalized["confidence"] <= 100


def test_killchain_engine_correlates_recon_to_delivery():
    engine = KillChainEngine()
    analysis = engine.analyze(
        [
            {"event_type": "port_scan", "host_id": "h1"},
            {"event_type": "suspicious_dns", "host_id": "h1"},
            {"event_type": "failed_login", "host_id": "h1"},
        ],
        host_id="h1",
    ).to_dict()

    rule_ids = {item["rule_id"] for item in analysis["correlations"]}
    assert "KC-001" in rule_ids
    assert analysis["current_phase"] in {"delivery", "initial_access"}
    assert analysis["progression_pct"] > 0


def test_threat_intel_mock_reputation_and_type_classification():
    client = ThreatIntelClient()

    verdict = client.reputation("198.51.100.66").to_dict()

    assert classify_ioc("198.51.100.66") == "ip"
    assert classify_ioc("44d88612fea8a8f36de82e1278abb02f") == "md5"
    assert verdict["matched"] is True
    assert verdict["severity"] == "critical"
    assert verdict["score"] > 0


def test_response_engine_plans_safe_dry_run_actions_for_high_risk_event():
    policy = ActiveDefensePolicy(auto_response_threshold=80, destructive_enabled=False)
    engine = ActiveDefenseEngine(policy=policy, dry_run=True)

    result = engine.handle_event(
        {
            "event_type": "c2_beacon",
            "host_id": "host-a",
            "source_ip": "198.51.100.66",
            "process_name": "powershell.exe",
            "pid": 4242,
        },
        risk_score=91,
        killchain_stage="command_and_control",
        threat_intel_score=72,
        execute=True,
    )

    action_types = {item["action_type"] for item in result["actions"]}
    statuses = {item["status"] for item in result["results"]}
    assert {"block_ip", "kill_process", "quarantine_host"}.issubset(action_types)
    assert result["dry_run"] is True
    assert statuses == {"simulated"}


def test_risk_engine_enterprise_score_formula_and_levels():
    assert score_event(
        {"severity": "high", "correlation_bonus": 20},
        threat_intel_score=15,
    ) == 65
    assert risk_level_for_score(30) == "LOW"
    assert risk_level_for_score(31) == "MEDIUM"
    assert risk_level_for_score(61) == "HIGH"
    assert risk_level_for_score(86) == "CRITICAL"
