"""Tests for xdr.identity_engine."""

import pytest

from xdr.identity_engine import (
    PrivilegeLevel, AnomalyType, IdentityAnomaly, IdentityRiskProfile,
    detect_brute_force, detect_impossible_travel, detect_privilege_escalation,
    detect_login_chaining, detect_unusual_access, assess_identity_risk,
)


def _auth(ts, user="alice", host="h1", ip="1.2.3.4", failed=False, geo=None):
    return {
        "event_type": "login_failed" if failed else "login",
        "timestamp": ts,
        "user": user,
        "host_id": host,
        "source_ip": ip,
        "geo": geo,
    }


# Brute force
class TestBruteForce:
    def test_below_threshold_no_detection(self):
        events = [_auth(f"2026-05-04T08:0{i}:00Z", failed=True) for i in range(3)]
        assert detect_brute_force(events) == []

    def test_threshold_5_in_15_min_triggers(self):
        events = [_auth(f"2026-05-04T08:0{i}:00Z", failed=True) for i in range(5)]
        out = detect_brute_force(events)
        assert len(out) == 1
        assert out[0].type == AnomalyType.BRUTE_FORCE
        assert out[0].details["count"] == 5

    def test_failures_outside_window_excluded(self):
        events = [
            _auth("2026-05-04T08:00:00Z", failed=True),
            _auth("2026-05-04T08:01:00Z", failed=True),
            _auth("2026-05-04T09:00:00Z", failed=True),
            _auth("2026-05-04T09:01:00Z", failed=True),
            _auth("2026-05-04T09:02:00Z", failed=True),
        ]
        # Window is 15 minutes; first 2 + last 3 each are below threshold
        assert detect_brute_force(events) == []

    def test_severity_scales_with_count(self):
        events_5 = [_auth(f"2026-05-04T08:0{i}:00Z", failed=True) for i in range(5)]
        events_20 = [_auth(f"2026-05-04T08:{i:02d}:00Z", failed=True) for i in range(15)]
        s5 = detect_brute_force(events_5)[0].severity
        s20 = detect_brute_force(events_20)[0].severity
        assert s20 > s5

    def test_ignores_successful_auths(self):
        events = [_auth(f"2026-05-04T08:0{i}:00Z", failed=False) for i in range(10)]
        assert detect_brute_force(events) == []


# Impossible travel
class TestImpossibleTravel:
    def test_no_geo_no_detection(self):
        events = [
            _auth("2026-05-04T08:00:00Z"),
            _auth("2026-05-04T08:30:00Z"),
        ]
        assert detect_impossible_travel(events) == []

    def test_same_city_no_detection(self):
        events = [
            _auth("2026-05-04T08:00:00Z", geo={"lat": -30.034, "lon": -51.217}),
            _auth("2026-05-04T08:30:00Z", geo={"lat": -30.037, "lon": -51.219}),
        ]
        assert detect_impossible_travel(events) == []

    def test_globe_in_5_minutes_triggers(self):
        # Porto Alegre to Tokyo in 5 minutes is impossible.
        events = [
            _auth("2026-05-04T08:00:00Z", geo={"lat": -30.0, "lon": -51.0}),
            _auth("2026-05-04T08:05:00Z", geo={"lat":  35.7, "lon": 139.7}),
        ]
        out = detect_impossible_travel(events)
        assert len(out) == 1
        assert out[0].type == AnomalyType.IMPOSSIBLE_TRAVEL
        assert out[0].details["distance_km"] > 15000

    def test_realistic_travel_no_detection(self):
        # London to NYC in 8 hours is compatible with commercial flight travel.
        events = [
            _auth("2026-05-04T08:00:00Z", geo={"lat": 51.5, "lon":  -0.1}),
            _auth("2026-05-04T16:00:00Z", geo={"lat": 40.7, "lon": -74.0}),
        ]
        assert detect_impossible_travel(events) == []


# Privilege escalation
class TestPrivilegeEscalation:
    def test_explicit_privilege_grant_event(self):
        events = [{"event_type": "privilege_grant", "user": "alice",
                   "timestamp": "2026-05-04T08:00:00Z", "host_id": "h1",
                   "technique": "T1068"}]
        out = detect_privilege_escalation(events)
        assert len(out) == 1
        assert out[0].type == AnomalyType.PRIVILEGE_ESCALATION

    def test_uac_bypass_event(self):
        events = [{"event_type": "uac_bypass", "user": "alice",
                   "timestamp": "2026-05-04T08:00:00Z", "host_id": "h1"}]
        assert len(detect_privilege_escalation(events)) == 1

    def test_running_as_transition(self):
        events = [
            {"running_as": "standard", "user": "alice",
             "timestamp": "2026-05-04T08:00:00Z", "host_id": "h1"},
            {"running_as": "domain_admin", "user": "alice",
             "timestamp": "2026-05-04T08:05:00Z", "host_id": "h1"},
        ]
        out = detect_privilege_escalation(events)
        assert len(out) >= 1
        assert any(a.details.get("from") == "standard" and a.details.get("to") == "domain_admin"
                   for a in out)

    def test_running_as_no_change_no_detection(self):
        events = [
            {"running_as": "admin", "user": "alice", "timestamp": "2026-05-04T08:00:00Z"},
            {"running_as": "admin", "user": "alice", "timestamp": "2026-05-04T08:05:00Z"},
        ]
        assert detect_privilege_escalation(events) == []


# Login chaining
class TestLoginChaining:
    def test_single_host_no_chaining(self):
        events = [_auth(f"2026-05-04T08:0{i}:00Z", host="h1") for i in range(5)]
        assert detect_login_chaining(events) == []

    def test_four_hosts_in_10min_triggers(self):
        events = [
            _auth("2026-05-04T08:00:00Z", host="h1"),
            _auth("2026-05-04T08:02:00Z", host="h2"),
            _auth("2026-05-04T08:04:00Z", host="h3"),
            _auth("2026-05-04T08:06:00Z", host="h4"),
        ]
        out = detect_login_chaining(events)
        assert len(out) == 1
        assert out[0].type == AnomalyType.LOGIN_CHAINING
        assert set(out[0].details["hosts"]) == {"h1", "h2", "h3", "h4"}

    def test_hosts_across_long_window_no_detection(self):
        events = [
            _auth("2026-05-04T08:00:00Z", host="h1"),
            _auth("2026-05-04T09:00:00Z", host="h2"),
            _auth("2026-05-04T10:00:00Z", host="h3"),
            _auth("2026-05-04T11:00:00Z", host="h4"),
        ]
        assert detect_login_chaining(events) == []


# Unusual access
class TestUnusualAccess:
    def test_no_baseline_no_detection(self):
        events = [_auth("2026-05-04T08:00:00Z", host="h1")]
        assert detect_unusual_access(events, baseline_hosts=[]) == []

    def test_baseline_host_no_detection(self):
        events = [_auth("2026-05-04T08:00:00Z", host="h1")]
        assert detect_unusual_access(events, baseline_hosts=["h1"]) == []

    def test_off_baseline_host_triggers(self):
        events = [_auth("2026-05-04T08:00:00Z", host="h99")]
        out = detect_unusual_access(events, baseline_hosts=["h1", "h2"])
        assert len(out) == 1
        assert out[0].type == AnomalyType.UNUSUAL_ACCESS
        assert out[0].host_id == "h99"


# Top-level aggregator
class TestAssessIdentityRisk:
    def test_clean_user_low_risk(self):
        p = assess_identity_risk("clean", [_auth("2026-05-04T08:00:00Z")])
        assert p.risk_score < 30
        assert p.severity_band == "low"
        assert p.anomalies == []

    def test_brute_force_pushes_to_medium_or_higher(self):
        events = [_auth(f"2026-05-04T08:0{i}:00Z", failed=True) for i in range(7)]
        p = assess_identity_risk("alice", events)
        assert p.risk_score >= 30

    def test_privilege_level_is_highest_observed(self):
        events = [
            {"running_as": "standard", "user": "alice", "timestamp": "2026-05-04T08:00:00Z"},
            {"running_as": "domain_admin", "user": "alice", "timestamp": "2026-05-04T08:05:00Z"},
        ]
        p = assess_identity_risk("alice", events)
        assert p.privilege_level == PrivilegeLevel.DOMAIN_ADMIN

    def test_affected_hosts_collected(self):
        events = [
            _auth("2026-05-04T08:00:00Z", host="h1"),
            _auth("2026-05-04T08:01:00Z", host="h2"),
        ]
        p = assess_identity_risk("alice", events)
        assert set(p.affected_hosts) == {"h1", "h2"}

    def test_severity_band_critical(self):
        events = (
            [_auth(f"2026-05-04T08:0{i}:00Z", failed=True) for i in range(10)]
            + [_auth("2026-05-04T08:01:00Z", geo={"lat": -30.0, "lon": -51.0})]
            + [_auth("2026-05-04T08:05:00Z", geo={"lat":  35.7, "lon": 139.7})]
            + [{"event_type": "privilege_grant", "user": "alice",
                "timestamp": "2026-05-04T08:10:00Z", "host_id": "h1"}]
        )
        p = assess_identity_risk("alice", events)
        assert p.risk_score >= 60

    def test_active_incidents_collected(self):
        events = [
            {**_auth("2026-05-04T08:00:00Z"), "incident_id": "INC-1"},
            {**_auth("2026-05-04T08:01:00Z"), "incident_id": "INC-2"},
            {**_auth("2026-05-04T08:02:00Z"), "incident_id": "INC-1"},  # dup
        ]
        p = assess_identity_risk("alice", events)
        assert set(p.active_incidents) == {"INC-1", "INC-2"}

    def test_to_dict_json_safe(self):
        import json
        events = [_auth(f"2026-05-04T08:0{i}:00Z", failed=True) for i in range(5)]
        p = assess_identity_risk("alice", events)
        json.dumps(p.to_dict())  # should not raise
        d = p.to_dict()
        assert d["severity_band"] in ("low", "medium", "high", "critical")
        assert all("type" in a for a in d["anomalies"])

    def test_non_dict_events_ignored(self):
        events = [None, "string", 42, _auth("2026-05-04T08:00:00Z")]
        p = assess_identity_risk("alice", events)
        assert p.severity_band == "low"  # only one safe event

    def test_events_for_other_users_are_ignored(self):
        events = [_auth(f"2026-05-04T08:0{i}:00Z", user="bob", failed=True) for i in range(8)]
        p = assess_identity_risk("alice", events)
        assert p.risk_score == 0
        assert p.anomalies == []

    def test_first_last_seen_set(self):
        events = [
            _auth("2026-05-04T08:00:00Z"),
            _auth("2026-05-04T20:00:00Z"),
        ]
        p = assess_identity_risk("alice", events)
        assert p.first_seen == "2026-05-04T08:00:00Z"
        assert p.last_seen == "2026-05-04T20:00:00Z"
