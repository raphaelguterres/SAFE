"""SAFE Identity Risk Engine.

User-centric risk view layered on top of authentication and process events.
Complements the existing host-centric `risk_engine`: now the analyst can ask
"which IDENTITY is being abused right now?", not just "which HOST is at risk?".

Pure functions, no side effects, no DB writes. Engine consumes a list of
events (auth + process + access) and produces an IdentityRiskProfile per user.

Public API:
    PrivilegeLevel       - Enum
    AnomalyType          - Enum (canonical anomaly kinds)
    IdentityAnomaly      - dataclass (type, severity, ts, details)
    IdentityRiskProfile  - dataclass (user_id, risk_score, anomalies, hosts...)
    detect_brute_force(events, *, threshold=5, window_minutes=15)
    detect_impossible_travel(events, *, km_per_hour=900)
    detect_privilege_escalation(events)
    detect_login_chaining(events, *, hosts_threshold=4, window_minutes=10)
    detect_unusual_access(events, baseline_hosts)
    assess_identity_risk(user_id, events, *, baseline_hosts=None)
        -> IdentityRiskProfile

Severity buckets:
    risk_score < 30  : low
    30..59           : medium
    60..84           : high
    85..100          : critical
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Iterable, Optional


# Enums
class PrivilegeLevel(str, Enum):
    STANDARD       = "standard"
    POWER_USER     = "power_user"
    ADMIN          = "admin"
    DOMAIN_ADMIN   = "domain_admin"
    SERVICE        = "service"


_PRIV_WEIGHT = {
    PrivilegeLevel.STANDARD:     0,
    PrivilegeLevel.POWER_USER:   8,
    PrivilegeLevel.ADMIN:       18,
    PrivilegeLevel.DOMAIN_ADMIN: 28,
    PrivilegeLevel.SERVICE:     14,
}


class AnomalyType(str, Enum):
    BRUTE_FORCE           = "brute_force"
    IMPOSSIBLE_TRAVEL     = "impossible_travel"
    PRIVILEGE_ESCALATION  = "privilege_escalation"
    LOGIN_CHAINING        = "login_chaining"
    UNUSUAL_ACCESS        = "unusual_access"


_ANOMALY_BASE_SEVERITY = {
    AnomalyType.BRUTE_FORCE:          20,
    AnomalyType.IMPOSSIBLE_TRAVEL:    45,
    AnomalyType.PRIVILEGE_ESCALATION: 40,
    AnomalyType.LOGIN_CHAINING:       25,
    AnomalyType.UNUSUAL_ACCESS:       15,
}


# Dataclasses
@dataclass
class IdentityAnomaly:
    type:     AnomalyType
    severity: int                   # 0..100
    ts:       Optional[str] = None  # ISO 8601
    host_id:  Optional[str] = None
    source_ip:Optional[str] = None
    details:  dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        return d


@dataclass
class IdentityRiskProfile:
    user_id:           str
    risk_score:        int = 0
    privilege_level:   PrivilegeLevel = PrivilegeLevel.STANDARD
    anomalies:         list[IdentityAnomaly] = field(default_factory=list)
    affected_hosts:    list[str] = field(default_factory=list)
    active_incidents:  list[str] = field(default_factory=list)
    first_seen:        Optional[str] = None
    last_seen:         Optional[str] = None

    @property
    def severity_band(self) -> str:
        if self.risk_score >= 85: return "critical"
        if self.risk_score >= 60: return "high"
        if self.risk_score >= 30: return "medium"
        return "low"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["privilege_level"] = self.privilege_level.value
        d["anomalies"]       = [a.to_dict() for a in self.anomalies]
        d["severity_band"]   = self.severity_band
        return d


# Helpers
def _parse_ts(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None


def _is_auth_event(ev: dict) -> bool:
    t = (ev.get("event_type") or ev.get("type") or "").lower()
    return t in {
        "auth", "authentication", "login", "logon", "logon_failed",
        "login_failed", "auth_failed", "auth_success", "auth_failure"
    } or "logon" in t or "login" in t

def _is_failed_auth(ev: dict) -> bool:
    t = (ev.get("event_type") or ev.get("type") or "").lower()
    if "fail" in t:
        return True
    outcome = (ev.get("outcome") or ev.get("status") or "").lower()
    return outcome in {"failed", "failure", "denied"}


def _event_user_id(ev: dict) -> Optional[str]:
    for key in ("user_id", "user", "username", "account_name", "target_user"):
        value = ev.get(key)
        if value:
            return str(value).strip()
    return None


def _event_belongs_to_user(ev: dict, user_id: str) -> bool:
    observed = _event_user_id(ev)
    if not observed:
        return False
    return observed.casefold() == str(user_id).strip().casefold()


def _haversine_km(geo_a: dict, geo_b: dict) -> float:
    """Great-circle distance between two {lat, lon} dicts. Returns 0 if invalid."""
    try:
        lat1 = math.radians(float(geo_a["lat"]))
        lon1 = math.radians(float(geo_a["lon"]))
        lat2 = math.radians(float(geo_b["lat"]))
        lon2 = math.radians(float(geo_b["lon"]))
    except (KeyError, TypeError, ValueError):
        return 0.0
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    return 6371.0 * c


# Detectors
def detect_brute_force(
    events: Iterable[dict],
    *,
    threshold: int = 5,
    window_minutes: int = 15,
) -> list[IdentityAnomaly]:
    """N failed auths within the window produces one anomaly for the strongest cluster."""
    auths = [
        ev for ev in events
        if isinstance(ev, dict) and _is_auth_event(ev) and _is_failed_auth(ev)
    ]
    if len(auths) < threshold:
        return []

    # Sort by ts
    parsed: list[tuple[datetime, dict]] = []
    for ev in auths:
        ts = _parse_ts(ev.get("timestamp") or ev.get("ts"))
        if ts:
            parsed.append((ts, ev))
    parsed.sort(key=lambda p: p[0])

    window = timedelta(minutes=window_minutes)
    best_cluster: list[dict] = []
    best_end: Optional[datetime] = None
    left = 0

    for right, (end, _event) in enumerate(parsed):
        start = end - window
        while left <= right and parsed[left][0] < start:
            left += 1
        cluster = [ev for _ts, ev in parsed[left:right + 1]]
        if len(cluster) > len(best_cluster):
            best_cluster = cluster
            best_end = end

    if len(best_cluster) >= threshold and best_end is not None:
        ips = sorted({ev.get("source_ip") or ev.get("src_ip") or "" for ev in best_cluster})
        hosts = sorted({ev.get("host_id") or "" for ev in best_cluster})
        severity = min(100, _ANOMALY_BASE_SEVERITY[AnomalyType.BRUTE_FORCE]
                        + min(50, len(best_cluster) * 3))
        return [IdentityAnomaly(
            type=AnomalyType.BRUTE_FORCE,
            severity=severity,
            ts=best_end.isoformat().replace("+00:00", "Z"),
            host_id=hosts[0] if hosts else None,
            source_ip=ips[0] if ips else None,
            details={"count": len(best_cluster), "window_min": window_minutes,
                     "ips": ips, "hosts": hosts},
        )]
    return []


def detect_impossible_travel(
    events: Iterable[dict],
    *,
    km_per_hour: int = 900,
) -> list[IdentityAnomaly]:
    """Two successful auths from geo-distant IPs faster than km_per_hour allows."""
    succ_auths = []
    for ev in events:
        if not isinstance(ev, dict) or not _is_auth_event(ev) or _is_failed_auth(ev):
            continue
        geo = ev.get("geo") or {}
        if not isinstance(geo, dict) or "lat" not in geo or "lon" not in geo:
            continue
        ts = _parse_ts(ev.get("timestamp") or ev.get("ts"))
        if ts:
            succ_auths.append((ts, ev, geo))
    succ_auths.sort(key=lambda p: p[0])

    out: list[IdentityAnomaly] = []
    for i in range(1, len(succ_auths)):
        ts_a, ev_a, geo_a = succ_auths[i - 1]
        ts_b, ev_b, geo_b = succ_auths[i]
        delta_h = (ts_b - ts_a).total_seconds() / 3600.0
        if delta_h <= 0:
            continue
        dist = _haversine_km(geo_a, geo_b)
        if dist < 50:  # noise threshold for same-city travel
            continue
        max_dist_allowed = km_per_hour * delta_h
        if dist > max_dist_allowed:
            severity = min(100, _ANOMALY_BASE_SEVERITY[AnomalyType.IMPOSSIBLE_TRAVEL]
                            + min(40, int((dist - max_dist_allowed) / 100)))
            out.append(IdentityAnomaly(
                type=AnomalyType.IMPOSSIBLE_TRAVEL,
                severity=severity,
                ts=ts_b.isoformat().replace("+00:00", "Z"),
                source_ip=ev_b.get("source_ip") or ev_b.get("src_ip"),
                details={"distance_km": int(dist), "delta_hours": round(delta_h, 2),
                         "from_ip": ev_a.get("source_ip"), "to_ip": ev_b.get("source_ip")},
            ))
    return out


def detect_privilege_escalation(events: Iterable[dict]) -> list[IdentityAnomaly]:
    """Detects:
       (a) non-admin user later observed running as admin
       (b) sudden privilege grant/elevation events
       (c) UAC bypass markers
    """
    seen_priv: dict[str, PrivilegeLevel] = {}
    out: list[IdentityAnomaly] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        t = (ev.get("event_type") or ev.get("type") or "").lower()
        if t in {"privilege_grant", "privilege_escalation", "uac_bypass", "sudo_grant"}:
            ts = _parse_ts(ev.get("timestamp") or ev.get("ts"))
            out.append(IdentityAnomaly(
                type=AnomalyType.PRIVILEGE_ESCALATION,
                severity=_ANOMALY_BASE_SEVERITY[AnomalyType.PRIVILEGE_ESCALATION] + 25,
                ts=(ts.isoformat().replace("+00:00", "Z") if ts else None),
                host_id=ev.get("host_id"),
                details={"trigger": t, "via": ev.get("technique") or ev.get("via")},
            ))
            continue
        # Track running_as transitions
        priv = ev.get("running_as") or ev.get("privilege_level")
        if priv:
            try:
                cur = PrivilegeLevel(str(priv).lower())
            except ValueError:
                continue
            user = ev.get("user") or ev.get("user_id") or ""
            if not user:
                continue
            prev = seen_priv.get(user)
            if prev is not None and _PRIV_WEIGHT[cur] > _PRIV_WEIGHT[prev] + 10:
                ts = _parse_ts(ev.get("timestamp") or ev.get("ts"))
                out.append(IdentityAnomaly(
                    type=AnomalyType.PRIVILEGE_ESCALATION,
                    severity=_ANOMALY_BASE_SEVERITY[AnomalyType.PRIVILEGE_ESCALATION]
                              + min(40, _PRIV_WEIGHT[cur] - _PRIV_WEIGHT[prev]),
                    ts=(ts.isoformat().replace("+00:00", "Z") if ts else None),
                    host_id=ev.get("host_id"),
                    details={"from": prev.value, "to": cur.value},
                ))
            seen_priv[user] = cur
    return out


def detect_login_chaining(
    events: Iterable[dict],
    *,
    hosts_threshold: int = 4,
    window_minutes: int = 10,
) -> list[IdentityAnomaly]:
    """Same user successful logons across N different hosts in short window."""
    auths: list[tuple[datetime, dict]] = []
    for ev in events:
        if not isinstance(ev, dict) or not _is_auth_event(ev) or _is_failed_auth(ev):
            continue
        if not ev.get("host_id"):
            continue
        ts = _parse_ts(ev.get("timestamp") or ev.get("ts"))
        if ts:
            auths.append((ts, ev))
    auths.sort(key=lambda p: p[0])
    if len(auths) < hosts_threshold:
        return []

    window = timedelta(minutes=window_minutes)
    out: list[IdentityAnomaly] = []
    for i in range(len(auths)):
        end = auths[i][0]
        start = end - window
        cluster_hosts: list[str] = []
        for ts, ev in auths:
            if start <= ts <= end:
                hid = ev.get("host_id")
                if hid and hid not in cluster_hosts:
                    cluster_hosts.append(hid)
        if len(cluster_hosts) >= hosts_threshold:
            severity = _ANOMALY_BASE_SEVERITY[AnomalyType.LOGIN_CHAINING] \
                       + min(50, len(cluster_hosts) * 6)
            out.append(IdentityAnomaly(
                type=AnomalyType.LOGIN_CHAINING,
                severity=min(100, severity),
                ts=end.isoformat().replace("+00:00", "Z"),
                details={"hosts": cluster_hosts, "window_min": window_minutes,
                         "count": len(cluster_hosts)},
            ))
            return out
    return out


def detect_unusual_access(
    events: Iterable[dict],
    baseline_hosts: Optional[Iterable[str]] = None,
) -> list[IdentityAnomaly]:
    """User accesses host(s) not in their baseline."""
    baseline = set(baseline_hosts or [])
    if not baseline:
        return []
    out: list[IdentityAnomaly] = []
    seen_new: dict[str, dict] = {}
    for ev in events:
        if not isinstance(ev, dict) or not _is_auth_event(ev) or _is_failed_auth(ev):
            continue
        hid = ev.get("host_id")
        if not hid or hid in baseline or hid in seen_new:
            continue
        ts = _parse_ts(ev.get("timestamp") or ev.get("ts"))
        seen_new[hid] = {"ts": ts, "ev": ev}
    for hid, info in seen_new.items():
        ts = info["ts"]
        out.append(IdentityAnomaly(
            type=AnomalyType.UNUSUAL_ACCESS,
            severity=_ANOMALY_BASE_SEVERITY[AnomalyType.UNUSUAL_ACCESS] + 10,
            ts=(ts.isoformat().replace("+00:00", "Z") if ts else None),
            host_id=hid,
            details={"baseline_hosts": sorted(list(baseline))},
        ))
    return out


# Top-level aggregator
def assess_identity_risk(
    user_id: str,
    events: Iterable[dict],
    *,
    baseline_hosts: Optional[Iterable[str]] = None,
) -> IdentityRiskProfile:
    """Run all detectors over the user's events and produce a single profile."""
    ev_list = [
        e for e in events
        if isinstance(e, dict) and _event_belongs_to_user(e, user_id)
    ]

    anomalies: list[IdentityAnomaly] = []
    anomalies.extend(detect_brute_force(ev_list))
    anomalies.extend(detect_impossible_travel(ev_list))
    anomalies.extend(detect_privilege_escalation(ev_list))
    anomalies.extend(detect_login_chaining(ev_list))
    anomalies.extend(detect_unusual_access(ev_list, baseline_hosts))

    # Privilege level: highest observed
    highest_priv = PrivilegeLevel.STANDARD
    for ev in ev_list:
        priv = ev.get("running_as") or ev.get("privilege_level")
        if not priv:
            continue
        try:
            cand = PrivilegeLevel(str(priv).lower())
            if _PRIV_WEIGHT[cand] > _PRIV_WEIGHT[highest_priv]:
                highest_priv = cand
        except ValueError:
            pass

    # Affected hosts
    hosts_set = set()
    for ev in ev_list:
        hid = ev.get("host_id")
        if hid:
            hosts_set.add(hid)

    # Risk score: privilege weight + sum of anomaly severities (diminishing returns)
    base = _PRIV_WEIGHT.get(highest_priv, 0)
    anomaly_pts = 0
    for a in anomalies:
        # diminishing returns: 1.0, 0.7, 0.5, 0.3 ...
        weight = max(0.2, 1.0 - 0.3 * anomaly_pts / max(1, _ANOMALY_BASE_SEVERITY[AnomalyType.IMPOSSIBLE_TRAVEL]))
        anomaly_pts += int(a.severity * weight)
    risk = max(0, min(100, base + anomaly_pts))

    # First/last seen
    parsed_times = []
    for ev in ev_list:
        ts = _parse_ts(ev.get("timestamp") or ev.get("ts"))
        if ts:
            parsed_times.append(ts)
    first = min(parsed_times).isoformat().replace("+00:00", "Z") if parsed_times else None
    last  = max(parsed_times).isoformat().replace("+00:00", "Z") if parsed_times else None

    incidents = sorted({
        i for ev in ev_list
        for i in [ev.get("incident_id")] if i
    })

    return IdentityRiskProfile(
        user_id=user_id,
        risk_score=risk,
        privilege_level=highest_priv,
        anomalies=anomalies,
        affected_hosts=sorted(hosts_set),
        active_incidents=incidents,
        first_seen=first,
        last_seen=last,
    )


__all__ = [
    "PrivilegeLevel",
    "AnomalyType",
    "IdentityAnomaly",
    "IdentityRiskProfile",
    "detect_brute_force",
    "detect_impossible_travel",
    "detect_privilege_escalation",
    "detect_login_chaining",
    "detect_unusual_access",
    "assess_identity_risk",
]
