from __future__ import annotations

from xdr.policy_engine import can_approve_response_action


def test_response_approval_matrix_matches_enterprise_roles():
    assert can_approve_response_action("viewer", "collect_diagnostics") is False
    assert can_approve_response_action("analyst", "create_investigation") is True
    assert can_approve_response_action("analyst", "block_ip") is False
    assert can_approve_response_action("responder", "collect_diagnostics") is True
    assert can_approve_response_action("responder", "block_ip") is True
    assert can_approve_response_action("responder", "isolate_host") is False
    assert can_approve_response_action("admin", "isolate_host") is True
    assert can_approve_response_action("owner", "delete_file") is True


def test_only_owner_can_change_policy_mode():
    assert can_approve_response_action("admin", "full_auto_containment", policy_mode_change=True) is False
    assert can_approve_response_action("owner", "full_auto_containment", policy_mode_change=True) is True
