from __future__ import annotations

from xdr.pipeline import XDRPipeline
from xdr.policy_engine import ResponseMode, ResponsePolicyEngine, decide_response_action


def test_monitor_only_allows_safe_actions_and_blocks_containment():
    engine = ResponsePolicyEngine(ResponseMode.MONITOR_ONLY)

    safe = engine.decide("collect_diagnostics")
    guarded = engine.decide("isolate_host", confidence=0.99)

    assert safe.allowed is True
    assert safe.required_approval is False
    assert guarded.allowed is False
    assert guarded.required_approval is True


def test_block_ip_requires_high_confidence_and_policy_mode():
    engine = ResponsePolicyEngine(ResponseMode.SEMI_AUTO)

    low = engine.decide("block_ip", confidence=0.7, evidence={"ip": "8.8.8.8"})
    high = engine.decide("block_ip", confidence=0.9, evidence={"ip": "8.8.8.8"})

    assert low.allowed is False
    assert "confidence_min_0_85" in low.safety_checks
    assert high.allowed is True
    assert high.required_approval is False


def test_process_kill_is_never_automatic_by_default():
    decision = decide_response_action(
        "kill_process",
        mode="manual_approval",
        confidence=0.95,
        evidence={"process_name": "powershell.exe", "pid": 1234, "process_hash": "abc"},
    )

    assert decision.allowed is False
    assert decision.required_approval is True
    assert "protected_process_denylist" in decision.safety_checks


def test_quarantine_requires_hash_path_and_signature_check():
    engine = ResponsePolicyEngine(ResponseMode.FULL_AUTO_CONTAINMENT)

    missing = engine.decide("quarantine_file", confidence=0.95, evidence={"path": r"C:\tmp\a.exe"})
    complete = engine.decide(
        "quarantine_file",
        confidence=0.95,
        evidence={"path": r"C:\tmp\a.exe", "sha256": "a" * 64, "signature_checked": True},
    )

    assert missing.allowed is False
    assert "missing_file_safety_evidence" in missing.safety_checks
    assert complete.allowed is True


def test_delete_file_remains_disabled():
    decision = ResponsePolicyEngine(ResponseMode.FULL_AUTO_CONTAINMENT).decide("delete_file", confidence=1.0)

    assert decision.allowed is False
    assert decision.required_approval is True
    assert "destructive_delete_disabled" in decision.safety_checks


def test_response_engine_marks_dangerous_plans_as_requires_approval():
    outcome = XDRPipeline().process_payload(
        {
            "host_id": "host-policy-plan",
            "event_type": "process_execution",
            "severity": "high",
            "timestamp": "2026-05-06T12:00:00Z",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc AAAA",
            "pid": 4444,
            "source": "agent",
            "details": {},
        }
    )[0]

    kill = next(action for action in outcome.actions if action.action_type == "kill_process")
    decision = kill.parameters["policy_decision"]

    assert kill.automatic is False
    assert kill.parameters["response_queue_status"] == "requires_approval"
    assert decision["allowed"] is False
    assert decision["required_approval"] is True
