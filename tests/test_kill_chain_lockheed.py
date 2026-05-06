"""Tests for engine.kill_chain_lockheed."""

import pytest

from engine.kill_chain_lockheed import (
    PHASES,
    PHASE_INDEX,
    MITRE_TO_LOCKHEED,
    HostKillChainState,
    map_tactic,
    derive_host_state,
)


class TestMappingTable:
    def test_all_14_mitre_tactics_mapped(self):
        expected = {
            "reconnaissance", "resource_development", "initial_access",
            "execution", "persistence", "privilege_escalation", "defense_evasion",
            "credential_access", "discovery", "lateral_movement", "collection",
            "command_and_control", "exfiltration", "impact",
        }
        assert set(MITRE_TO_LOCKHEED.keys()) == expected

    def test_all_phases_are_canonical_lockheed(self):
        valid = set(PHASES)
        for tactic, phase in MITRE_TO_LOCKHEED.items():
            assert phase in valid, f"{tactic} mapped to unknown phase {phase}"

    def test_six_canonical_phases_in_order(self):
        assert PHASES == (
            "reconnaissance", "delivery", "exploitation",
            "installation", "command_and_control", "actions_on_objectives",
        )

    def test_phase_index_aligned(self):
        for i, phase in enumerate(PHASES):
            assert PHASE_INDEX[phase] == i


class TestMapTactic:
    @pytest.mark.parametrize("tactic,phase", [
        ("reconnaissance", "reconnaissance"),
        ("resource_development", "reconnaissance"),
        ("initial_access", "delivery"),
        ("execution", "exploitation"),
        ("privilege_escalation", "exploitation"),
        ("defense_evasion", "exploitation"),
        ("persistence", "installation"),
        ("command_and_control", "command_and_control"),
        ("credential_access", "command_and_control"),
        ("discovery", "command_and_control"),
        ("lateral_movement", "actions_on_objectives"),
        ("collection", "actions_on_objectives"),
        ("exfiltration", "actions_on_objectives"),
        ("impact", "actions_on_objectives"),
    ])
    def test_canonical_mappings(self, tactic, phase):
        assert map_tactic(tactic) == phase

    def test_normalizes_case_spacing_dashes(self):
        assert map_tactic("Reconnaissance") == "reconnaissance"
        assert map_tactic("LATERAL-MOVEMENT") == "actions_on_objectives"
        assert map_tactic("command and control") == "command_and_control"

    def test_unknown_returns_none(self):
        assert map_tactic("not_a_tactic") is None
        assert map_tactic("") is None
        assert map_tactic(None) is None


class TestDeriveHostState:
    def test_empty_returns_no_progression(self):
        state = derive_host_state("h1", [])
        assert state.host_id == "h1"
        assert state.current_phase is None
        assert state.next_phase is None
        assert state.progression_pct == 0
        assert state.reached == {}

    def test_single_recon_event(self):
        items = [{"mitre_tactic": "reconnaissance", "id": "e1", "timestamp": "T1"}]
        state = derive_host_state("h1", items)
        assert state.current_phase == "reconnaissance"
        assert state.next_phase == "delivery"
        assert state.progression_pct == round(1/6 * 100)
        assert state.reached["reconnaissance"]["count"] == 1

    def test_picks_deepest_phase_as_current(self):
        items = [
            {"tactic": "reconnaissance", "id": "e1"},
            {"tactic": "execution",      "id": "e2"},
            {"tactic": "command_and_control", "id": "e3"},
        ]
        state = derive_host_state("h1", items)
        assert state.current_phase == "command_and_control"
        assert state.next_phase == "actions_on_objectives"
        assert "reconnaissance" in state.reached
        assert "exploitation" in state.reached
        assert "command_and_control" in state.reached

    def test_full_progression_no_next_phase(self):
        items = [{"tactic": "exfiltration", "id": "e1"}]
        state = derive_host_state("h1", items)
        assert state.current_phase == "actions_on_objectives"
        assert state.next_phase is None
        assert state.progression_pct == 100

    def test_aggregates_multiple_evidences_per_phase(self):
        items = [
            {"tactic": "execution", "id": "e1", "timestamp": "T1"},
            {"tactic": "execution", "id": "e2", "timestamp": "T2"},
            {"tactic": "execution", "id": "e3", "timestamp": "T3"},
        ]
        state = derive_host_state("h1", items)
        assert state.reached["exploitation"]["count"] == 3
        assert state.reached["exploitation"]["last_seen"] == "T3"
        assert set(state.reached["exploitation"]["evidence_ids"]) == {"e1", "e2", "e3"}

    def test_tolerates_alternate_field_shapes(self):
        items = [
            {"mitre_tactic": "reconnaissance"},
            {"tactic": "execution"},
            {"tactics": ["persistence"]},
            {"mitre_tactics": ["lateral_movement"]},
            {"mitre": {"tactics": ["impact"]}},
        ]
        state = derive_host_state("h1", items)
        assert state.current_phase == "actions_on_objectives"
        for phase in ("reconnaissance", "exploitation", "installation", "actions_on_objectives"):
            assert phase in state.reached

    def test_skips_non_dict_items(self):
        items = [None, "string", 42, {"tactic": "execution"}]
        state = derive_host_state("h1", items)
        assert state.current_phase == "exploitation"

    def test_skips_items_without_tactics(self):
        items = [{"event_type": "noise", "severity": "low"}]
        state = derive_host_state("h1", items)
        assert state.current_phase is None
        assert state.reached == {}


class TestSerialization:
    def test_to_dict_has_all_six_phases(self):
        state = derive_host_state("h1", [{"tactic": "execution"}])
        out = state.to_dict()
        assert len(out["phases"]) == 6
        ids = [p["id"] for p in out["phases"]]
        assert ids == list(PHASES)

    def test_to_dict_marks_current(self):
        state = derive_host_state("h1", [{"tactic": "execution"}])
        out = state.to_dict()
        current_phases = [p for p in out["phases"] if p["is_current"]]
        assert len(current_phases) == 1
        assert current_phases[0]["id"] == "exploitation"

    def test_to_dict_includes_labels(self):
        state = derive_host_state("h1", [{"tactic": "reconnaissance"}])
        out = state.to_dict()
        assert out["current_label"] == "Reconhecimento"
        assert out["next_label"] == "Entrega"
