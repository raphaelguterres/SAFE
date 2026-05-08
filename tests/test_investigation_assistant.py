from xdr.investigation_assistant import InvestigationAssistant


def test_investigation_assistant_builds_next_steps_and_evidence_checklist():
    guide = InvestigationAssistant().assist(
        host_id="SAFE-WS-14",
        events=[
            {
                "host_id": "SAFE-WS-14",
                "command_line": "powershell.exe -enc abc",
                "mitre_tactic": "execution",
            },
            {
                "host_id": "SAFE-WS-14",
                "summary": "external beaconing observed",
                "mitre_tactic": "command_and_control",
            },
        ],
    ).to_dict()

    assert "SAFE-WS-14" in guide["attack_summary"]
    assert "validate_process_tree" in guide["suggested_next_steps"]
    assert "pivot_on_network_indicators" in guide["suggested_next_steps"]
    assert "network_connections" in guide["evidence_checklist"]
