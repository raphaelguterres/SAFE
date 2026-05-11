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


# ── Heatmap aggregation ──────────────────────────────────────────
from engine.kill_chain_lockheed import aggregate_heatmap, KillChainHeatmap


class TestAggregateHeatmap:
    def test_empty_input(self):
        hm = aggregate_heatmap([])
        out = hm.to_dict()
        assert out["total_hosts"] == 0
        assert out["hosts"] == []
        assert len(out["phases"]) == 6
        assert out["phase_totals"] == {p: 0 for p in PHASES}
        assert out["max_phase_count"] == {p: 0 for p in PHASES}

    def test_single_host_single_phase(self):
        data = [{"host_id": "h1", "items": [{"tactic": "reconnaissance"}]}]
        out = aggregate_heatmap(data).to_dict()
        assert out["total_hosts"] == 1
        host = out["hosts"][0]
        assert host["host_id"] == "h1"
        assert host["display_name"] == "h1"  # default to host_id
        assert host["current_phase"] == "reconnaissance"
        assert host["current_phase_idx"] == 0
        assert host["progression_pct"] == round(1/6 * 100)
        # cells parallel to PHASES
        assert len(host["cells"]) == 6
        assert host["cells"][0]["phase"] == "reconnaissance"
        assert host["cells"][0]["reached"] is True
        assert host["cells"][0]["is_current"] is True
        assert host["cells"][0]["count"] == 1
        # intensity normalized — sole occurrence so 1.0
        assert host["cells"][0]["intensity"] == 1.0

    def test_intensity_normalized_by_column_max(self):
        data = [
            {"host_id": "h1", "items": [{"tactic": "execution"}, {"tactic": "execution"}]},
            {"host_id": "h2", "items": [{"tactic": "execution"}]},
        ]
        out = aggregate_heatmap(data).to_dict()
        # h1 has 2 events in exploitation, h2 has 1 → max is 2
        # h1 intensity = 1.0, h2 intensity = 0.5
        h1 = next(h for h in out["hosts"] if h["host_id"] == "h1")
        h2 = next(h for h in out["hosts"] if h["host_id"] == "h2")
        # exploitation is index 2
        assert h1["cells"][2]["intensity"] == 1.0
        assert h2["cells"][2]["intensity"] == 0.5
        assert out["max_phase_count"]["exploitation"] == 2

    def test_sorts_deepest_first(self):
        data = [
            {"host_id": "shallow", "items": [{"tactic": "reconnaissance"}]},
            {"host_id": "deep",    "items": [{"tactic": "exfiltration"}]},
            {"host_id": "mid",     "items": [{"tactic": "execution"}]},
        ]
        out = aggregate_heatmap(data).to_dict()
        order = [h["host_id"] for h in out["hosts"]]
        assert order == ["deep", "mid", "shallow"]

    def test_idle_hosts_at_end(self):
        data = [
            {"host_id": "active", "items": [{"tactic": "execution"}]},
            {"host_id": "idle",   "items": []},
        ]
        out = aggregate_heatmap(data).to_dict()
        order = [h["host_id"] for h in out["hosts"]]
        assert order == ["active", "idle"]
        idle = next(h for h in out["hosts"] if h["host_id"] == "idle")
        assert idle["current_phase"] is None
        assert idle["progression_pct"] == 0
        assert all(c["count"] == 0 for c in idle["cells"])
        assert all(c["intensity"] == 0.0 for c in idle["cells"])

    def test_phase_totals_aggregate_per_lockheed(self):
        # Lockheed phases (6) keys, not MITRE tactics (14). Renamed to avoid
        # stale .pyc cache from a previous version of this test.
        data = [
            {"host_id": "h1", "items": [{"tactic": "reconnaissance"}, {"tactic": "execution"}]},
            {"host_id": "h2", "items": [{"tactic": "reconnaissance"}, {"tactic": "reconnaissance"}]},
            {"host_id": "h3", "items": [{"tactic": "exfiltration"}]},
        ]
        out = aggregate_heatmap(data).to_dict()
        totals = out["phase_totals"]
        assert totals["reconnaissance"]        == 3
        assert totals["exploitation"]          == 1
        assert totals["actions_on_objectives"] == 1
        assert totals["delivery"]              == 0
        assert totals["installation"]          == 0

    def test_skips_invalid_entries(self):
        data = [
            None,
            {"host_id": "", "items": [{"tactic": "execution"}]},  # empty host_id
            {"items": [{"tactic": "execution"}]},                  # no host_id
            {"host_id": "valid", "items": [{"tactic": "execution"}]},
        ]
        out = aggregate_heatmap(data).to_dict()
        assert out["total_hosts"] == 1
        assert out["hosts"][0]["host_id"] == "valid"

    def test_uses_display_name_when_present(self):
        data = [{
            "host_id": "h1",
            "display_name": "QA Web Prod 01",
            "items": [{"tactic": "execution"}],
        }]
        out = aggregate_heatmap(data).to_dict()
        assert out["hosts"][0]["display_name"] == "QA Web Prod 01"

    def test_phases_metadata_in_canonical_order(self):
        out = aggregate_heatmap([]).to_dict()
        ids = [p["id"] for p in out["phases"]]
        assert ids == list(PHASES)
        for p in out["phases"]:
            assert "label_pt" in p and p["label_pt"]
            assert "desc"     in p and p["desc"]

    def test_cells_parallel_to_phases(self):
        data = [{"host_id": "h1", "items": [{"tactic": "persistence"}]}]
        out = aggregate_heatmap(data).to_dict()
        host = out["hosts"][0]
        # cell at index i should match PHASES[i]
        for i, phase_id in enumerate(PHASES):
            assert host["cells"][i]["phase"] == phase_id


from engine.kill_chain_lockheed import build_heatmap


class TestBuildHeatmap:
    def test_empty_returns_empty_matrix(self):
        out = build_heatmap([])
        assert out["hosts"] == []
        assert out["phases"] == list(PHASES)
        assert out["summary"]["total_hosts"] == 0
        assert out["summary"]["hosts_with_kc"] == 0
        assert out["summary"]["max_count"] == 0

    def test_single_host_basic(self):
        sample = [{"host_id": "h1", "events": [{"mitre_tactic": "execution"}]}]
        out = build_heatmap(sample)
        assert len(out["hosts"]) == 1
        h = out["hosts"][0]
        assert h["host_id"] == "h1"
        assert h["current_phase"] == "exploitation"
        assert len(h["cells"]) == 6
        # all phases present in cells, in order
        assert [c["phase"] for c in h["cells"]] == list(PHASES)

    def test_skips_hosts_without_id(self):
        sample = [{"events": [{"mitre_tactic": "execution"}]}, {"host_id": "h2"}]
        out = build_heatmap(sample)
        assert len(out["hosts"]) == 1
        assert out["hosts"][0]["host_id"] == "h2"

    def test_sort_by_progression_then_risk(self):
        sample = [
            {"host_id": "low_progression_high_risk", "risk_score": 90,
             "events": [{"mitre_tactic": "reconnaissance"}]},
            {"host_id": "high_progression_low_risk", "risk_score": 20,
             "events": [{"mitre_tactic": "exfiltration"}]},
            {"host_id": "high_progression_high_risk", "risk_score": 95,
             "events": [{"mitre_tactic": "exfiltration"}]},
        ]
        out = build_heatmap(sample)
        # Higher progression first; tie broken by risk score
        ids = [h["host_id"] for h in out["hosts"]]
        assert ids[0] == "high_progression_high_risk"
        assert ids[1] == "high_progression_low_risk"
        assert ids[2] == "low_progression_high_risk"

    def test_summary_counts_by_phase(self):
        sample = [
            {"host_id": "h1", "events": [{"mitre_tactic": "reconnaissance"}]},
            {"host_id": "h2", "events": [{"mitre_tactic": "reconnaissance"}, {"mitre_tactic": "execution"}]},
            {"host_id": "h3", "events": [{"mitre_tactic": "command_and_control"}]},
        ]
        out = build_heatmap(sample)
        bp = out["summary"]["by_phase"]
        assert bp["reconnaissance"] == 2
        assert bp["exploitation"] == 1
        assert bp["command_and_control"] == 1
        assert bp["installation"] == 0
        assert out["summary"]["hosts_with_kc"] == 3

    def test_uses_display_name_when_present(self):
        sample = [{"host_id": "h1", "display_name": "WIN-OPS-04",
                   "events": [{"mitre_tactic": "execution"}]}]
        out = build_heatmap(sample)
        assert out["hosts"][0]["display_name"] == "WIN-OPS-04"

    def test_falls_back_to_host_id_when_no_display_name(self):
        sample = [{"host_id": "h1", "events": [{"mitre_tactic": "execution"}]}]
        out = build_heatmap(sample)
        assert out["hosts"][0]["display_name"] == "h1"

    def test_pulls_from_multiple_event_keys(self):
        sample = [{
            "host_id": "h1",
            "events":         [{"mitre_tactic": "reconnaissance"}],
            "detections":     [{"tactic": "execution"}],
            "mitre_events":   [{"tactics": ["persistence"]}],
            "correlations":   [{"mitre": {"tactics": ["impact"]}}],
        }]
        out = build_heatmap(sample)
        h = out["hosts"][0]
        # Must have hit deepest = actions_on_objectives
        assert h["current_phase"] == "actions_on_objectives"
        assert h["progression_pct"] == 100

    def test_max_count_tracks_highest_phase_count(self):
        sample = [{
            "host_id": "h1",
            "events": [
                {"tactic": "execution"}, {"tactic": "execution"}, {"tactic": "execution"},
                {"tactic": "reconnaissance"},
            ],
        }]
        out = build_heatmap(sample)
        assert out["summary"]["max_count"] == 3
    def test_intensity_normalized_0_to_1(self):
        sample = [{
            "host_id": "h1",
            "events": [
                {"tactic": "execution"}, {"tactic": "execution"}, {"tactic": "execution"},
                {"tactic": "reconnaissance"},
            ],
        }]
        out = build_heatmap(sample)
        cells = {c["phase"]: c for c in out["hosts"][0]["cells"]}
        assert cells["exploitation"]["intensity"] == 1.0       # max count = 3
        assert cells["reconnaissance"]["intensity"] == round(1/3, 3)
        assert cells["delivery"]["intensity"] == 0.0

    def test_total_hosts_at_top_level(self):
        sample = [
            {"host_id": "h1", "events": [{"tactic": "execution"}]},
            {"host_id": "h2", "events": [{"tactic": "execution"}]},
            {"host_id": "h3"},
        ]
        out = build_heatmap(sample)
        assert out["total_hosts"] == 3
        assert out["summary"]["total_hosts"] == 3



from datetime import datetime as _dt, timezone as _tz
from engine.kill_chain_lockheed import derive_progression_timeline


_FIXED_NOW = _dt(2026, 5, 4, 12, 0, 0, tzinfo=_tz.utc)


class TestProgressionTimeline:
    def test_empty_returns_empty_buckets(self):
        out = derive_progression_timeline("h1", [], bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["host_id"] == "h1"
        assert len(out["buckets"]) == 6
        for b in out["buckets"]:
            assert b["count"] == 0
            assert b["phases"] == []
            assert b["deepest_phase"] is None
            assert b["deepest_index"] == -1
        assert out["summary"]["current_phase"] is None
        assert out["summary"]["first_phase"] is None

    def test_event_falls_in_correct_bucket(self):
        items = [{"tactic": "execution", "timestamp": "2026-05-04T08:30:00Z"}]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # 12:00 - 6h = 06:00 start, 08:30 falls in bucket starting at 08:00 (idx 2)
        assert out["buckets"][2]["count"] == 1
        assert out["buckets"][2]["phases"] == ["exploitation"]
        # Cumulative deepest persists forward
        for i in range(2, 6):
            assert out["buckets"][i]["deepest_phase"] == "exploitation"

    def test_deepest_is_cumulative(self):
        items = [
            {"tactic": "reconnaissance",      "timestamp": "2026-05-04T07:00:00Z"},
            {"tactic": "execution",           "timestamp": "2026-05-04T09:00:00Z"},
            {"tactic": "command_and_control", "timestamp": "2026-05-04T11:00:00Z"},
        ]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        deepest_seq = [b["deepest_phase"] for b in out["buckets"]]
        # buckets cover 06,07,08,09,10,11 — values shown when each event lands
        assert deepest_seq[0] is None                      # 06:00 — nothing yet
        assert deepest_seq[1] == "reconnaissance"          # 07:00
        assert deepest_seq[2] == "reconnaissance"          # 08:00 (carry)
        assert deepest_seq[3] == "exploitation"            # 09:00 (advance)
        assert deepest_seq[4] == "exploitation"            # 10:00 (carry)
        assert deepest_seq[5] == "command_and_control"     # 11:00 (advance)

    def test_events_outside_window_are_ignored(self):
        items = [
            {"tactic": "exfiltration", "timestamp": "2026-05-04T03:00:00Z"},  # 9h ago, outside 6h
            {"tactic": "execution",     "timestamp": "2026-05-04T10:00:00Z"},
        ]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["summary"]["current_phase"] == "exploitation"
        assert out["summary"]["first_phase"] == "exploitation"

    def test_summary_first_phase_is_earliest(self):
        items = [
            {"tactic": "execution",       "timestamp": "2026-05-04T11:00:00Z"},
            {"tactic": "reconnaissance",  "timestamp": "2026-05-04T07:00:00Z"},
        ]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["summary"]["first_phase"] == "reconnaissance"
        assert out["summary"]["current_phase"] == "exploitation"

    def test_events_without_timestamp_skipped(self):
        items = [
            {"tactic": "execution"},
            {"tactic": "reconnaissance", "timestamp": "2026-05-04T08:00:00Z"},
        ]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # only the timestamped event counts
        total = sum(b["count"] for b in out["buckets"])
        assert total == 1

    def test_bucket_count_matches_window_and_size(self):
        out = derive_progression_timeline("h1", [], bucket_minutes=15, window_hours=24, now=_FIXED_NOW)
        assert out["bucket_min"] == 15
        assert out["window_hours"] == 24
        assert len(out["buckets"]) == 24 * 4  # 96

    def test_invalid_bucket_size_raises(self):
        import pytest
        with pytest.raises(ValueError):
            derive_progression_timeline("h1", [], bucket_minutes=0, window_hours=6, now=_FIXED_NOW)
        with pytest.raises(ValueError):
            derive_progression_timeline("h1", [], bucket_minutes=15, window_hours=0, now=_FIXED_NOW)

    def test_phase_first_seen_in_summary(self):
        items = [
            {"tactic": "execution",       "timestamp": "2026-05-04T09:00:00Z"},
            {"tactic": "execution",       "timestamp": "2026-05-04T11:00:00Z"},
            {"tactic": "reconnaissance",  "timestamp": "2026-05-04T07:00:00Z"},
        ]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        seen = out["summary"]["phase_first_seen"]
        assert seen["reconnaissance"] == "2026-05-04T07:00:00Z"
        assert seen["exploitation"] == "2026-05-04T09:00:00Z"

    def test_epoch_timestamp_supported(self):
        ts = int(_dt(2026, 5, 4, 9, 0, 0, tzinfo=_tz.utc).timestamp())
        items = [{"tactic": "execution", "timestamp": ts}]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["summary"]["current_phase"] == "exploitation"

    def test_serializable_to_json(self):
        import json
        items = [{"tactic": "execution", "timestamp": "2026-05-04T09:00:00Z"}]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # Should not raise
        json.dumps(out)


from engine.kill_chain_lockheed import resolve_window_events


class TestResolveWindowEvents:
    def test_empty_in_empty_out(self):
        assert resolve_window_events([]) == []

    def test_filters_by_window(self):
        items = [
            {"tactic": "execution", "timestamp": "2026-05-04T08:00:00Z"},
            {"tactic": "execution", "timestamp": "2026-05-04T10:00:00Z"},
            {"tactic": "execution", "timestamp": "2026-05-04T12:00:00Z"},
        ]
        out = resolve_window_events(items,
                                    from_ts="2026-05-04T09:00:00Z",
                                    to_ts="2026-05-04T11:00:00Z")
        assert len(out) == 1
        assert out[0]["ts"] == "2026-05-04T10:00:00Z"

    def test_filters_by_phase(self):
        items = [
            {"tactic": "execution",      "timestamp": "2026-05-04T10:00:00Z"},
            {"tactic": "reconnaissance", "timestamp": "2026-05-04T10:01:00Z"},
            {"tactic": "exfiltration",   "timestamp": "2026-05-04T10:02:00Z"},
        ]
        out = resolve_window_events(items, phase="exploitation")
        assert len(out) == 1
        assert out[0]["mitre_tactic"] == "execution"
        assert out[0]["lockheed_phase"] == "exploitation"

    def test_sorted_descending_by_time(self):
        items = [
            {"tactic": "execution", "timestamp": "2026-05-04T08:00:00Z"},
            {"tactic": "execution", "timestamp": "2026-05-04T10:00:00Z"},
            {"tactic": "execution", "timestamp": "2026-05-04T09:00:00Z"},
        ]
        out = resolve_window_events(items)
        ts = [e["ts"] for e in out]
        assert ts == ["2026-05-04T10:00:00Z", "2026-05-04T09:00:00Z", "2026-05-04T08:00:00Z"]

    def test_skips_items_without_timestamp(self):
        items = [{"tactic": "execution"}, {"tactic": "execution", "timestamp": "2026-05-04T10:00:00Z"}]
        out = resolve_window_events(items)
        assert len(out) == 1

    def test_extracts_normalized_fields(self):
        items = [{
            "tactic": "execution",
            "timestamp": "2026-05-04T10:00:00Z",
            "severity": "high",
            "event_type": "process_create",
            "source_ip": "1.2.3.4",
            "process": "powershell.exe",
            "summary": "obfuscated cmdline",
        }]
        out = resolve_window_events(items)
        e = out[0]
        assert e["severity"] == "high"
        assert e["event_type"] == "process_create"
        assert e["source_ip"] == "1.2.3.4"
        assert e["process"] == "powershell.exe"
        assert e["summary"] == "obfuscated cmdline"
        assert e["lockheed_phase"] == "exploitation"
        assert "raw" in e

    def test_summary_truncated_to_240(self):
        long_summary = "x" * 500
        items = [{"tactic": "execution", "timestamp": "2026-05-04T10:00:00Z", "summary": long_summary}]
        out = resolve_window_events(items)
        assert len(out[0]["summary"]) == 240

    def test_walks_to_next_tactic_when_first_unknown(self):
        items = [{
            "tactics": ["unknown_tactic_xyz", "execution"],
            "timestamp": "2026-05-04T10:00:00Z",
        }]
        out = resolve_window_events(items)
        assert len(out) == 1
        assert out[0]["lockheed_phase"] == "exploitation"

    def test_phase_filter_skips_unknowns(self):
        items = [{"event_type": "noise", "timestamp": "2026-05-04T10:00:00Z"}]
        out = resolve_window_events(items, phase="exploitation")
        assert out == []



class TestProgressionTimelineDrillDown:
    def test_include_events_off_by_default(self):
        items = [{"tactic": "execution", "timestamp": "2026-05-04T09:00:00Z", "id": "e1"}]
        out = derive_progression_timeline("h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        for b in out["buckets"]:
            assert "events" not in b

    def test_include_events_attaches_per_bucket(self):
        items = [
            {"tactic": "reconnaissance", "timestamp": "2026-05-04T07:00:00Z",
             "id": "e1", "source_ip": "1.2.3.4", "summary": "Port scan"},
            {"tactic": "execution", "timestamp": "2026-05-04T09:00:00Z",
             "id": "e2", "process": "ps.exe", "summary": "Suspicious"},
        ]
        out = derive_progression_timeline(
            "h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW,
            include_events=True,
        )
        for b in out["buckets"]:
            assert "events" in b
        # Bucket 07:00 should hold the recon event
        recon_bucket = next(b for b in out["buckets"] if b["ts"].startswith("2026-05-04T07:00"))
        assert len(recon_bucket["events"]) == 1
        assert recon_bucket["events"][0]["id"] == "e1"
        assert recon_bucket["events"][0]["source_ip"] == "1.2.3.4"
        assert recon_bucket["events"][0]["phase"] == "reconnaissance"
        # Bucket 09:00 holds the execution event
        exec_bucket = next(b for b in out["buckets"] if b["ts"].startswith("2026-05-04T09:00"))
        assert exec_bucket["events"][0]["id"] == "e2"
        assert exec_bucket["events"][0]["process"] == "ps.exe"

    def test_event_recorded_once_even_with_multiple_tactics(self):
        items = [{"tactics": ["reconnaissance", "discovery"],
                  "timestamp": "2026-05-04T08:00:00Z", "id": "multi"}]
        out = derive_progression_timeline(
            "h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW,
            include_events=True,
        )
        bucket = next(b for b in out["buckets"] if b["ts"].startswith("2026-05-04T08:00"))
        # Despite 2 tactics, only one event entry per bucket per item
        assert len(bucket["events"]) == 1
        assert bucket["count"] == 2  # but count tracks tactic occurrences

    def test_max_events_per_bucket_caps(self):
        items = []
        for i in range(75):
            items.append({"tactic": "execution",
                          "timestamp": "2026-05-04T09:30:00Z",
                          "id": "e" + str(i)})
        out = derive_progression_timeline(
            "h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW,
            include_events=True, max_events_per_bucket=20,
        )
        bucket = next(b for b in out["buckets"] if b["ts"].startswith("2026-05-04T09:00"))
        assert bucket["count"] == 75       # all counted
        assert len(bucket["events"]) == 20  # but list capped

    def test_event_summary_fields_normalized(self):
        items = [{"mitre_tactic": "execution",
                  "timestamp": "2026-05-04T09:00:00Z",
                  "event_id": "x1", "src_ip": "5.6.7.8",
                  "process_name": "evil.exe", "description": "RAT install"}]
        out = derive_progression_timeline(
            "h1", items, bucket_minutes=60, window_hours=6, now=_FIXED_NOW,
            include_events=True,
        )
        ev = next(b for b in out["buckets"] if b["count"] > 0)["events"][0]
        assert ev["id"] == "x1"           # event_id normalized to id
        assert ev["source_ip"] == "5.6.7.8"
        assert ev["process"] == "evil.exe"
        assert ev["summary"] == "RAT install"



class TestHeatmapFilters:
    def _sample(self):
        return [
            {"host_id": "h1", "tenant_id": "t1", "risk_score": 30,
             "events": [{"tactic": "reconnaissance"}]},
            {"host_id": "h2", "tenant_id": "t2", "risk_score": 70,
             "events": [{"tactic": "command_and_control"}]},
            {"host_id": "h3", "tenant_id": "t1", "risk_score": 95,
             "events": [{"tactic": "exfiltration"}]},
            {"host_id": "h4", "tenant_id": "t1", "risk_score": 45,
             "events": [{"tactic": "execution"}]},
        ]

    def test_no_filters_returns_all(self):
        out = build_heatmap(self._sample())
        assert len(out["hosts"]) == 4
        assert out["total_hosts"] == 4

    def test_filter_by_tenant_id(self):
        out = build_heatmap(self._sample(), tenant_id="t1")
        ids = [r["host_id"] for r in out["hosts"]]
        assert "h2" not in ids
        assert set(ids) == {"h1", "h3", "h4"}

    def test_filter_by_phase(self):
        out = build_heatmap(self._sample(), phase="actions_on_objectives")
        assert [r["host_id"] for r in out["hosts"]] == ["h3"]

    def test_filter_by_phase_normalizes_input(self):
        out1 = build_heatmap(self._sample(), phase="Actions On Objectives")
        out2 = build_heatmap(self._sample(), phase="actions-on-objectives")
        assert [r["host_id"] for r in out1["hosts"]] == ["h3"]
        assert [r["host_id"] for r in out2["hosts"]] == ["h3"]

    def test_filter_by_min_progression(self):
        # h3 = 100%, h2 = 83%, h4 = 50%, h1 = 17%
        out = build_heatmap(self._sample(), min_progression_pct=80)
        ids = [r["host_id"] for r in out["hosts"]]
        assert set(ids) == {"h3", "h2"}

    def test_limit_caps_after_sort(self):
        out = build_heatmap(self._sample(), limit=2)
        ids = [r["host_id"] for r in out["hosts"]]
        # Sorted by progression desc then risk desc → h3 (100%, 95) first, then h2 (83%, 70)
        assert ids == ["h3", "h2"]

    def test_combo_tenant_and_min_progression(self):
        out = build_heatmap(self._sample(), tenant_id="t1", min_progression_pct=40)
        ids = [r["host_id"] for r in out["hosts"]]
        # t1 hosts only, pct >= 40 → h3 (100), h4 (50). h1 is 17%, excluded.
        assert set(ids) == {"h3", "h4"}

    def test_empty_string_filters_treated_as_no_filter(self):
        out = build_heatmap(self._sample(), tenant_id="", phase="")
        assert len(out["hosts"]) == 4

    def test_filter_summary_reflects_filtered_set(self):
        out = build_heatmap(self._sample(), tenant_id="t1")
        assert out["summary"]["total_hosts"] == 3
        assert out["total_hosts"] == 3
        # Only t1 hosts contribute to by_phase counts? No — by_phase is computed
        # before filtering (it represents the original universe). Verify it's still informative.
        assert isinstance(out["summary"]["by_phase"], dict)



from engine.kill_chain_lockheed import derive_fleet_timeline


class TestFleetTimeline:
    def test_empty_returns_empty_buckets(self):
        out = derive_fleet_timeline([], bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["summary"]["total_hosts"] == 0
        assert out["summary"]["hosts_with_kc"] == 0
        assert all(b["total_active"] == 0 for b in out["buckets"])
        assert len(out["buckets"]) == 6

    def test_single_host_appears_in_correct_bucket_onward(self):
        hosts = [{"host_id": "h1", "events": [
            {"tactic": "execution", "timestamp": "2026-05-04T08:30:00Z"}
        ]}]
        out = derive_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # window_start = 06:00; event at 08:30 lands in bucket 08:00 (idx 2)
        for i, b in enumerate(out["buckets"]):
            if i < 2:
                assert b["total_active"] == 0
            else:
                assert b["total_active"] == 1
                assert b["by_phase"]["exploitation"] == 1

    def test_host_advances_phase_over_time(self):
        hosts = [{"host_id": "h1", "events": [
            {"tactic": "reconnaissance", "timestamp": "2026-05-04T07:00:00Z"},
            {"tactic": "execution",      "timestamp": "2026-05-04T10:00:00Z"},
        ]}]
        out = derive_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        b07 = next(b for b in out["buckets"] if b["ts"].startswith("2026-05-04T07"))
        b10 = next(b for b in out["buckets"] if b["ts"].startswith("2026-05-04T10"))
        assert b07["by_phase"]["reconnaissance"] == 1
        assert b07["by_phase"]["exploitation"] == 0
        # By 10:00 the host has moved to exploitation, no longer counted in recon
        assert b10["by_phase"]["reconnaissance"] == 0
        assert b10["by_phase"]["exploitation"] == 1
        assert b10["total_active"] == 1

    def test_each_host_counted_once_per_bucket(self):
        hosts = [
            {"host_id": "h1", "events": [{"tactic": "reconnaissance", "timestamp": "2026-05-04T07:00:00Z"}]},
            {"host_id": "h2", "events": [{"tactic": "reconnaissance", "timestamp": "2026-05-04T08:00:00Z"}]},
            {"host_id": "h3", "events": [{"tactic": "exfiltration",   "timestamp": "2026-05-04T11:00:00Z"}]},
        ]
        out = derive_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        b11 = next(b for b in out["buckets"] if b["ts"].startswith("2026-05-04T11"))
        assert b11["total_active"] == 3
        # h1 + h2 in recon, h3 in actions
        assert b11["by_phase"]["reconnaissance"] == 2
        assert b11["by_phase"]["actions_on_objectives"] == 1

    def test_summary_peak_total(self):
        hosts = [
            {"host_id": "h1", "events": [{"tactic": "reconnaissance", "timestamp": "2026-05-04T07:00:00Z"}]},
            {"host_id": "h2", "events": [{"tactic": "execution",      "timestamp": "2026-05-04T11:00:00Z"}]},
            {"host_id": "h3", "events": [{"tactic": "exfiltration",   "timestamp": "2026-05-04T11:30:00Z"}]},
        ]
        out = derive_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["summary"]["peak_total"] == 3

    def test_skips_hosts_without_id_or_events(self):
        hosts = [
            {"host_id": "h1"},  # no events
            {"events": [{"tactic": "execution", "timestamp": "2026-05-04T10:00:00Z"}]},  # no host_id
        ]
        out = derive_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["summary"]["total_hosts"] == 1   # h1 counted (no events)
        assert out["summary"]["hosts_with_kc"] == 0  # but no progression
        assert all(b["total_active"] == 0 for b in out["buckets"])

    def test_events_outside_window_ignored(self):
        hosts = [{"host_id": "h1", "events": [
            {"tactic": "exfiltration", "timestamp": "2026-05-04T03:00:00Z"},  # 9h ago
            {"tactic": "reconnaissance", "timestamp": "2026-05-04T07:00:00Z"},
        ]}]
        out = derive_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # earliest event in window = recon at 07:00 — host should never reach actions
        for b in out["buckets"]:
            assert b["by_phase"]["actions_on_objectives"] == 0

    def test_serializable_to_json(self):
        import json
        hosts = [{"host_id": "h1", "events": [{"tactic": "execution", "timestamp": "2026-05-04T10:00:00Z"}]}]
        out = derive_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        json.dumps(out)  # should not raise

    def test_invalid_bucket_or_window_raises(self):
        import pytest
        with pytest.raises(ValueError):
            derive_fleet_timeline([], bucket_minutes=0, window_hours=6, now=_FIXED_NOW)
        with pytest.raises(ValueError):
            derive_fleet_timeline([], bucket_minutes=15, window_hours=0, now=_FIXED_NOW)



from engine.kill_chain_lockheed import build_fleet_timeline


class TestFleetTimeline:
    def test_empty_returns_zero_filled_buckets(self):
        out = build_fleet_timeline([], bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["host_count"] == 0
        assert len(out["buckets"]) == 6
        for b in out["buckets"]:
            assert b["total_active"] == 0
            assert b["phases"] == {p: 0 for p in PHASES}

    def test_single_host_recon_only(self):
        hosts = [{"host_id": "h1", "events": [
            {"tactic": "reconnaissance", "timestamp": "2026-05-04T08:00:00Z"}
        ]}]
        out = build_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # Buckets at 06,07,08,09,10,11 — host enters at 08:00 and persists
        assert out["buckets"][0]["total_active"] == 0  # 06
        assert out["buckets"][1]["total_active"] == 0  # 07
        for i in range(2, 6):
            assert out["buckets"][i]["total_active"] == 1
            assert out["buckets"][i]["phases"]["reconnaissance"] == 1

    def test_host_progresses_phase_changes_bucket_counts(self):
        hosts = [{"host_id": "h1", "events": [
            {"tactic": "reconnaissance", "timestamp": "2026-05-04T08:00:00Z"},
            {"tactic": "execution",      "timestamp": "2026-05-04T10:00:00Z"},
        ]}]
        out = build_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # 08-09: recon ; 10-11: exploitation (host moved on)
        assert out["buckets"][2]["phases"]["reconnaissance"] == 1
        assert out["buckets"][2]["phases"]["exploitation"] == 0
        assert out["buckets"][4]["phases"]["reconnaissance"] == 0
        assert out["buckets"][4]["phases"]["exploitation"] == 1

    def test_multi_hosts_stack(self):
        hosts = [
            {"host_id": "h1", "events": [{"tactic": "reconnaissance", "timestamp": "2026-05-04T08:00:00Z"}]},
            {"host_id": "h2", "events": [{"tactic": "execution",      "timestamp": "2026-05-04T08:30:00Z"}]},
            {"host_id": "h3", "events": [{"tactic": "exfiltration",   "timestamp": "2026-05-04T09:00:00Z"}]},
        ]
        out = build_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        # At bucket 09: all 3 hosts active in different phases
        b9 = out["buckets"][3]
        assert b9["phases"]["reconnaissance"] == 1
        assert b9["phases"]["exploitation"] == 1
        assert b9["phases"]["actions_on_objectives"] == 1
        assert b9["total_active"] == 3
        assert out["max_total"] == 3

    def test_tenant_filter(self):
        hosts = [
            {"host_id": "h1", "tenant_id": "acme",  "events": [{"tactic":"execution","timestamp":"2026-05-04T08:00:00Z"}]},
            {"host_id": "h2", "tenant_id": "other", "events": [{"tactic":"execution","timestamp":"2026-05-04T08:00:00Z"}]},
        ]
        out_all = build_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        out_acme = build_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW, tenant_id="acme")
        assert out_all["host_count"] == 2
        assert out_acme["host_count"] == 1
        assert out_acme["buckets"][2]["phases"]["exploitation"] == 1

    def test_events_outside_window_ignored(self):
        hosts = [{"host_id": "h1", "events": [
            {"tactic": "exfiltration", "timestamp": "2026-05-04T02:00:00Z"},  # 10h ago, outside 6h
        ]}]
        out = build_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        for b in out["buckets"]:
            assert b["total_active"] == 0

    def test_skips_hosts_without_id(self):
        hosts = [
            {"events": [{"tactic":"execution","timestamp":"2026-05-04T08:00:00Z"}]},  # no host_id
            {"host_id": "h2", "events": [{"tactic":"execution","timestamp":"2026-05-04T08:00:00Z"}]},
        ]
        out = build_fleet_timeline(hosts, bucket_minutes=60, window_hours=6, now=_FIXED_NOW)
        assert out["host_count"] == 1

    def test_invalid_inputs_raise(self):
        import pytest
        with pytest.raises(ValueError):
            build_fleet_timeline([], bucket_minutes=0, window_hours=6, now=_FIXED_NOW)
        with pytest.raises(ValueError):
            build_fleet_timeline([], bucket_minutes=60, window_hours=0, now=_FIXED_NOW)
