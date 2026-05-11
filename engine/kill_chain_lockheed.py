"""
SAFE — Lockheed Cyber Kill Chain view

Wraps the MITRE ATT&CK tactics already used by killchain.py / mitre_engine.py
into the 6 canonical Lockheed Martin Cyber Kill Chain phases.

Goal: give a clear "where in the attack lifecycle is this host?" view to
SOC analysts and CISOs who think in Lockheed terms, without rewriting the
underlying detection layer (which is MITRE-based).

Mapping (designed conservatively — when a tactic spans 2 Lockheed phases
we pick the dominant one):

    Reconnaissance              ← reconnaissance, resource_development
    Delivery                    ← initial_access
    Exploitation                ← execution, privilege_escalation, defense_evasion
    Installation                ← persistence
    Command & Control           ← command_and_control, credential_access, discovery
    Actions on Objectives       ← lateral_movement, collection, exfiltration, impact

Public surface:
    PHASES                      — ordered list of 6 phase ids
    PHASE_LABELS                — id → human label (en / pt-br pairs)
    MITRE_TO_LOCKHEED           — dict tactic_id → phase_id
    map_tactic(tactic) -> phase
    derive_host_state(events_or_detections) -> HostKillChainState

This module has no side effects and zero deps beyond stdlib.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable, Optional

logger = logging.getLogger("netguard.killchain.lockheed")

# ── 6 phases of Lockheed Cyber Kill Chain (canonical order) ─────
PHASES: tuple[str, ...] = (
    "reconnaissance",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
)

PHASE_INDEX: dict[str, int] = {p: i for i, p in enumerate(PHASES)}

PHASE_LABELS: dict[str, dict[str, str]] = {
    "reconnaissance":          {"en": "Reconnaissance",
                                "pt": "Reconhecimento"},
    "delivery":                {"en": "Delivery",
                                "pt": "Entrega"},
    "exploitation":            {"en": "Exploitation",
                                "pt": "Exploração"},
    "installation":            {"en": "Installation",
                                "pt": "Instalação"},
    "command_and_control":     {"en": "Command & Control",
                                "pt": "Comando e Controle"},
    "actions_on_objectives":   {"en": "Actions on Objectives",
                                "pt": "Ações no Alvo"},
}

PHASE_DESCRIPTIONS: dict[str, str] = {
    "reconnaissance":          "Atacante coleta informação sobre o alvo (port scans, DNS lookups, OSINT).",
    "delivery":                "Vetor de entrada usado para colocar payload no host (phish, USB, exploit público).",
    "exploitation":            "Código malicioso executa no host explorando vulnerabilidade ou usuário.",
    "installation":            "Persistência estabelecida (serviço, registry, scheduled task, web shell).",
    "command_and_control":     "Canal de comunicação atacante ↔ host comprometido ativo.",
    "actions_on_objectives":   "Atacante atinge objetivo: lateral movement, exfil de dados, impacto.",
}

# ── MITRE ATT&CK tactic → Lockheed phase mapping ─────────────────
MITRE_TO_LOCKHEED: dict[str, str] = {
    "reconnaissance":         "reconnaissance",
    "resource_development":   "reconnaissance",
    "initial_access":         "delivery",
    "execution":              "exploitation",
    "privilege_escalation":   "exploitation",
    "defense_evasion":        "exploitation",
    "persistence":            "installation",
    "command_and_control":    "command_and_control",
    "credential_access":      "command_and_control",
    "discovery":              "command_and_control",
    "lateral_movement":       "actions_on_objectives",
    "collection":             "actions_on_objectives",
    "exfiltration":           "actions_on_objectives",
    "impact":                 "actions_on_objectives",
}


def map_tactic(tactic: Optional[str]) -> Optional[str]:
    """Map a single MITRE tactic id to a Lockheed phase id. Returns None
    if the tactic is unknown or empty."""
    if not tactic:
        return None
    key = str(tactic).strip().lower().replace(" ", "_").replace("-", "_")
    # Tolerate "TA0001" and similar IDs by checking aliases
    if key in MITRE_TO_LOCKHEED:
        return MITRE_TO_LOCKHEED[key]
    return None


# ── State derivation ─────────────────────────────────────────────
@dataclass
class HostKillChainState:
    """Snapshot of where a host currently sits in the Lockheed Cyber Kill Chain.

    Fields:
        host_id            — host identifier
        reached            — dict phase_id -> dict(count, last_seen, evidence_ids)
        current_phase      — deepest phase reached (the most advanced)
        next_phase         — heuristic next phase if attack continues
        progression_pct    — 0..100, how deep in the chain we are
                             (current_phase index + 1) / 6 * 100, rounded
    """
    host_id: str
    reached: dict[str, dict] = field(default_factory=dict)
    current_phase: Optional[str] = None
    next_phase: Optional[str] = None
    progression_pct: int = 0

    def to_dict(self) -> dict:
        return {
            "host_id":         self.host_id,
            "phases":          [
                {
                    "id":       phase_id,
                    "label_en": PHASE_LABELS[phase_id]["en"],
                    "label_pt": PHASE_LABELS[phase_id]["pt"],
                    "desc":     PHASE_DESCRIPTIONS[phase_id],
                    "reached":  phase_id in self.reached,
                    "count":    self.reached.get(phase_id, {}).get("count", 0),
                    "last_seen": self.reached.get(phase_id, {}).get("last_seen"),
                    "is_current": phase_id == self.current_phase,
                }
                for phase_id in PHASES
            ],
            "current_phase":   self.current_phase,
            "current_label":   (PHASE_LABELS[self.current_phase]["pt"]
                                if self.current_phase else None),
            "next_phase":      self.next_phase,
            "next_label":      (PHASE_LABELS[self.next_phase]["pt"]
                                if self.next_phase else None),
            "progression_pct": self.progression_pct,
        }


def _extract_tactics(item: dict) -> list[str]:
    """Pull MITRE tactic identifiers out of any of the shapes the project
    uses in the wild (events, detections, correlations).

    Tolerated keys:
        item["mitre_tactic"]    str
        item["mitre_tactics"]   list[str]
        item["tactic"]          str
        item["tactics"]         list[str]
        item["mitre"]           {"tactics": [...], "techniques": [...]}
    """
    tactics: list[str] = []
    for key in ("mitre_tactic", "tactic"):
        v = item.get(key)
        if isinstance(v, str) and v:
            tactics.append(v)
    for key in ("mitre_tactics", "tactics"):
        v = item.get(key)
        if isinstance(v, (list, tuple)):
            tactics.extend(str(x) for x in v if x)
    mitre_obj = item.get("mitre")
    if isinstance(mitre_obj, dict):
        v = mitre_obj.get("tactics")
        if isinstance(v, (list, tuple)):
            tactics.extend(str(x) for x in v if x)
        v = mitre_obj.get("tactic")
        if isinstance(v, str):
            tactics.append(v)
    return tactics


def derive_host_state(
    host_id: str,
    items: Iterable[dict],
) -> HostKillChainState:
    """Given an iterable of detections / events / correlations carrying MITRE
    tactic info, produce a HostKillChainState.

    Items that don't carry tactic info are silently skipped.
    """
    state = HostKillChainState(host_id=host_id)
    deepest_idx = -1

    for item in items:
        if not isinstance(item, dict):
            continue
        timestamp = item.get("timestamp") or item.get("ts") or item.get("created_at")
        evidence_id = item.get("id") or item.get("event_id") or item.get("detection_id")

        for tactic in _extract_tactics(item):
            phase = map_tactic(tactic)
            if phase is None:
                continue
            entry = state.reached.setdefault(phase, {
                "count": 0,
                "last_seen": None,
                "evidence_ids": [],
            })
            entry["count"] += 1
            if timestamp and (entry["last_seen"] is None or str(timestamp) > str(entry["last_seen"])):
                entry["last_seen"] = timestamp
            if evidence_id and evidence_id not in entry["evidence_ids"]:
                entry["evidence_ids"].append(evidence_id)
            idx = PHASE_INDEX[phase]
            if idx > deepest_idx:
                deepest_idx = idx

    if deepest_idx >= 0:
        state.current_phase = PHASES[deepest_idx]
        state.progression_pct = round((deepest_idx + 1) / len(PHASES) * 100)
        if deepest_idx + 1 < len(PHASES):
            state.next_phase = PHASES[deepest_idx + 1]

    return state


__all__ = [
    "PHASES",
    "PHASE_INDEX",
    "PHASE_LABELS",
    "PHASE_DESCRIPTIONS",
    "MITRE_TO_LOCKHEED",
    "HostKillChainState",
    "map_tactic",
    "derive_host_state",
    "aggregate_heatmap",
]



def aggregate_heatmap(host_states: "list[HostKillChainState]") -> dict:
    """Aggregate a list of HostKillChainState into a heatmap-ready payload.

    The payload is shaped for the SOC overview heatmap: rows = hosts, cols =
    Lockheed phases, plus summary stats. Hosts with no progression are kept
    so analysts can see "all green" hosts too, but they sort to the bottom.

    Returns:
        {
          "phases": [
            {"id": "...", "label_pt": "...", "label_en": "..."},
            ...  # 6 entries
          ],
          "rows": [
            {
              "host_id": "...",
              "current_phase": "...",
              "current_label": "...",
              "progression_pct": int,
              "max_count": int,
              "cells": [
                {"phase_id": "...", "count": int, "reached": bool, "is_current": bool},
                ...  # 6 entries (one per phase, in canonical order)
              ],
            },
            ...
          ],
          "summary": {
            "total_hosts": int,
            "with_activity": int,
            "phase_counts": {phase_id: hosts_in_or_past_this_phase, ...},
            "deepest_phase": phase_id | None,
          },
        }
    """
    rows: list[dict] = []
    phase_counts: dict[str, int] = {p: 0 for p in PHASES}
    deepest_idx = -1
    with_activity = 0

    for state in host_states or []:
        if not isinstance(state, HostKillChainState):
            continue
        cells = []
        max_count = 0
        for phase_id in PHASES:
            entry = state.reached.get(phase_id) or {}
            count = int(entry.get("count", 0))
            reached = phase_id in state.reached
            is_current = phase_id == state.current_phase
            cells.append({
                "phase_id":  phase_id,
                "count":     count,
                "reached":   reached,
                "is_current": is_current,
            })
            if count > max_count:
                max_count = count
            if reached:
                phase_counts[phase_id] += 1

        if state.current_phase is not None:
            with_activity += 1
            idx = PHASE_INDEX[state.current_phase]
            if idx > deepest_idx:
                deepest_idx = idx

        rows.append({
            "host_id":         state.host_id,
            "current_phase":   state.current_phase,
            "current_label":   (PHASE_LABELS[state.current_phase]["pt"]
                                if state.current_phase else None),
            "progression_pct": state.progression_pct,
            "max_count":       max_count,
            "cells":           cells,
        })

    # Sort: deepest phase first, then by total event count desc
    rows.sort(
        key=lambda r: (
            -(PHASE_INDEX[r["current_phase"]] if r["current_phase"] else -1),
            -sum(c["count"] for c in r["cells"]),
            r["host_id"],
        )
    )

    deepest_phase = PHASES[deepest_idx] if deepest_idx >= 0 else None

    return {
        "phases": [
            {
                "id":       p,
                "label_pt": PHASE_LABELS[p]["pt"],
                "label_en": PHASE_LABELS[p]["en"],
            }
            for p in PHASES
        ],
        "rows":   rows,
        "summary": {
            "total_hosts":   len(rows),
            "with_activity": with_activity,
            "phase_counts":  phase_counts,
            "deepest_phase": deepest_phase,
        },
    }


# ── Multi-host aggregation (heatmap) ────────────────────────────
@dataclass
class KillChainHeatmap:
    """Aggregated view of multiple hosts across the 6 Lockheed phases.

    Used by the SOC overview to render a hosts × phases heatmap.
    """
    hosts: list[dict] = field(default_factory=list)
    phases: list[dict] = field(default_factory=list)
    total_hosts: int = 0
    phase_totals: dict[str, int] = field(default_factory=dict)
    max_phase_count: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "phases":          self.phases,
            "hosts":           self.hosts,
            "total_hosts":     self.total_hosts,
            "phase_totals":    self.phase_totals,
            "max_phase_count": self.max_phase_count,
        }


def _phase_meta_list() -> list[dict]:
    """Stable list of the 6 phases in canonical order, with labels."""
    return [
        {
            "id":       phase_id,
            "label_en": PHASE_LABELS[phase_id]["en"],
            "label_pt": PHASE_LABELS[phase_id]["pt"],
            "desc":     PHASE_DESCRIPTIONS[phase_id],
            "index":    PHASE_INDEX[phase_id],
        }
        for phase_id in PHASES
    ]


def aggregate_heatmap(host_data: Iterable[dict]) -> KillChainHeatmap:
    """Aggregate kill-chain state across many hosts.

    `host_data` is an iterable of dicts shaped like:
        {
          "host_id":      "h1",                    # required
          "display_name": "QA Web Prod 01",        # optional
          "items":        [event_or_detection, ...]   # required, may be []
        }

    Returns a KillChainHeatmap whose `hosts` list contains, per host:
        - host_id, display_name
        - current_phase (id / label / index)
        - progression_pct (0..100)
        - cells: 6-element list parallel to PHASES with:
            { phase, count, reached, is_current, intensity }
          intensity is 0..1 normalized against the per-phase max across all
          hosts (so a cell with the most events of that phase = 1.0).

    Phase totals and max_phase_count are exposed at top level so the UI can
    render column-level summaries / scaling legends.
    """
    states: list[tuple[str, str, HostKillChainState]] = []
    phase_totals: dict[str, int] = {p: 0 for p in PHASES}
    max_phase_count: dict[str, int] = {p: 0 for p in PHASES}

    for entry in host_data:
        if not isinstance(entry, dict):
            continue
        host_id = entry.get("host_id")
        if not host_id:
            continue
        display = entry.get("display_name") or host_id
        items = entry.get("items") or []
        state = derive_host_state(host_id, items)

        for phase_id, info in state.reached.items():
            count = int(info.get("count", 0))
            phase_totals[phase_id] = phase_totals.get(phase_id, 0) + count
            if count > max_phase_count.get(phase_id, 0):
                max_phase_count[phase_id] = count

        states.append((host_id, display, state))

    # Sort hosts: deepest current phase first, then by progression_pct
    def _sort_key(item):
        _h, _d, st = item
        return (-(PHASE_INDEX[st.current_phase] if st.current_phase else -1),
                -st.progression_pct)
    states.sort(key=_sort_key)

    hosts_out: list[dict] = []
    for host_id, display, state in states:
        cells = []
        for phase_id in PHASES:
            info = state.reached.get(phase_id) or {}
            count = int(info.get("count", 0))
            mx = max_phase_count.get(phase_id, 0)
            intensity = (count / mx) if mx > 0 and count > 0 else 0.0
            cells.append({
                "phase":      phase_id,
                "count":      count,
                "reached":    phase_id in state.reached,
                "is_current": phase_id == state.current_phase,
                "intensity":  round(intensity, 3),
            })
        hosts_out.append({
            "host_id":           host_id,
            "display_name":      display,
            "current_phase":     state.current_phase,
            "current_phase_idx": (PHASE_INDEX[state.current_phase]
                                  if state.current_phase else None),
            "current_label":     (PHASE_LABELS[state.current_phase]["pt"]
                                  if state.current_phase else None),
            "progression_pct":   state.progression_pct,
            "cells":             cells,
        })

    return KillChainHeatmap(
        hosts=hosts_out,
        phases=_phase_meta_list(),
        total_hosts=len(hosts_out),
        phase_totals=phase_totals,
        max_phase_count=max_phase_count,
    )


# ── Aggregator: heatmap multi-host ─────────────────────────────
def build_heatmap(
    hosts_data: Iterable[dict],
    *,
    tenant_id: Optional[str] = None,
    phase: Optional[str] = None,
    min_progression_pct: int = 0,
    limit: Optional[int] = None,
) -> dict:
    """Build a heatmap-ready matrix from a list of host snapshots.

    Each host snapshot must be a dict with at minimum:
        host_id    str
        events     list[dict]   # OR detections / mitre_events
    Optional fields used if present:
        display_name, last_ip, risk_score, status, tenant_id

    Returns:
        {
          "phases": [...6 phases ordered...],
          "phase_labels": [...labels...],
          "hosts": [
              {
                "host_id":..., "display_name":..., "risk_score":...,
                "current_phase":..., "current_label":..., "progression_pct":...,
                "cells": [
                    {"phase":..., "count":..., "reached":..., "is_current":...},
                    ... (always 6, in order)
                ],
              },
              ...
          ],
          "summary": {
              "total_hosts": int,
              "hosts_with_kc": int,
              "max_count": int,
              "by_phase": {phase_id: count_of_hosts_in_or_past_that_phase}
          }
        }
    """
    rows: list[dict] = []
    max_count = 0
    by_phase: dict[str, int] = {p: 0 for p in PHASES}

    for host in hosts_data:
        if not isinstance(host, dict):
            continue
        host_id = (host.get("host_id") or host.get("id") or "")
        if not host_id:
            continue

        items = []
        for key in ("events", "detections", "mitre_events", "recent_events", "correlations"):
            v = host.get(key)
            if isinstance(v, (list, tuple)):
                items.extend(v)

        state = derive_host_state(host_id, items)

        cells = []
        for phase_id in PHASES:
            entry = state.reached.get(phase_id, {})
            count = int(entry.get("count", 0))
            cells.append({
                "phase":      phase_id,
                "count":      count,
                "reached":    phase_id in state.reached,
                "is_current": phase_id == state.current_phase,
                "intensity":  0.0,
            })
            if count > max_count:
                max_count = count
            if phase_id in state.reached:
                by_phase[phase_id] += 1

        rows.append({
            "host_id":         host_id,
            "display_name":    host.get("display_name") or host.get("hostname") or host_id,
            "tenant_id":       host.get("tenant_id"),
            "risk_score":      host.get("risk_score") or host.get("score") or 0,
            "status":          host.get("status"),
            "last_ip":         host.get("last_ip"),
            "current_phase":   state.current_phase,
            "current_label":   (PHASE_LABELS[state.current_phase]["pt"]
                                if state.current_phase else None),
            "progression_pct": state.progression_pct,
            "cells":           cells,
        })

    # ── Apply filters before sorting / serialization ──
    filtered: list[dict] = []
    norm_phase = (phase or "").strip().lower().replace(" ", "_").replace("-", "_") or None
    norm_tenant = (str(tenant_id).strip() if tenant_id is not None else None) or None
    if norm_tenant == "":
        norm_tenant = None
    for row in rows:
        if norm_tenant is not None:
            row_tid = row.get("tenant_id")
            if row_tid is None or str(row_tid) != norm_tenant:
                continue
        if norm_phase is not None and row.get("current_phase") != norm_phase:
            continue
        if min_progression_pct and (row.get("progression_pct") or 0) < min_progression_pct:
            continue
        filtered.append(row)
    rows = filtered

    # Normalize cell intensity to 0..1 based on the matrix max
    if max_count > 0:
        for row in rows:
            for cell in row["cells"]:
                cell["intensity"] = round(cell["count"] / max_count, 3)

    # Sort: highest progression / risk first
    rows.sort(key=lambda r: (-(r.get("progression_pct") or 0), -(r.get("risk_score") or 0)))

    if limit is not None and limit > 0:
        rows = rows[:limit]

    hosts_with_kc = sum(1 for r in rows if r["current_phase"] is not None)

    return {
        "phases":       list(PHASES),
        "phase_labels": [PHASE_LABELS[p]["pt"] for p in PHASES],
        "hosts":        rows,
        "total_hosts":  len(rows),  # top-level shortcut for UI
        "summary": {
            "total_hosts":   len(rows),
            "hosts_with_kc": hosts_with_kc,
            "max_count":     max_count,
            "by_phase":      by_phase,
        },
    }


__all__ += ["build_heatmap"]


# ── Timeline aggregator (per-host progression over time) ────────
from datetime import datetime, timezone, timedelta


def _parse_ts(value) -> Optional[datetime]:
    """Best-effort parse of timestamp into aware datetime UTC.
    Accepts ISO 8601 strings, epoch numbers, or already-aware datetime."""
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
        # Tolerate trailing "Z"
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(s)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None
    return None



def _summarize_event(item: dict, ts: datetime, phase: str) -> dict:
    """Compact summary of an event for the timeline drill-down panel."""
    return {
        "id":         item.get("id") or item.get("event_id") or item.get("detection_id"),
        "ts":         ts.isoformat().replace("+00:00", "Z"),
        "phase":      phase,
        "tactic":     item.get("mitre_tactic") or item.get("tactic"),
        "technique":  item.get("technique") or item.get("mitre_technique"),
        "event_type": item.get("event_type") or item.get("type"),
        "source_ip":  item.get("source_ip") or item.get("src_ip") or item.get("ip"),
        "process":    item.get("process") or item.get("process_name"),
        "severity":   item.get("severity"),
        "summary":    (item.get("summary") or item.get("description")
                       or item.get("message") or item.get("name") or ""),
    }


def derive_progression_timeline(
    host_id: str,
    items: Iterable[dict],
    *,
    bucket_minutes: int = 15,
    window_hours: int = 24,
    now: Optional[datetime] = None,
    include_events: bool = False,
    max_events_per_bucket: int = 50,
) -> dict:
    """Produce a per-host time series of Lockheed phase progression.

    For each time bucket within `window_hours` ending at `now`, compute:
      • count of events that mapped to any phase
      • set of phases active in that bucket
      • deepest phase reached (cumulative since start of window)

    Returns:
        {
          "host_id":      str,
          "bucket_min":   int,
          "window_hours": int,
          "from_ts":      str (ISO),
          "to_ts":        str (ISO),
          "buckets": [
              {
                "ts":              ISO 8601 string (bucket start),
                "count":           int,
                "phases":          [phase_id, ...] active in this bucket,
                "deepest_phase":   phase_id (cumulative — highest reached so far),
                "deepest_index":   int (0..5)
              },
              ...
          ],
          "summary": {
              "first_phase":   phase_id or None,
              "current_phase": phase_id or None,
              "current_index": int (0..5) or -1,
              "phase_first_seen": {phase_id: ts_iso, ...},
          }
        }
    """
    if bucket_minutes <= 0:
        raise ValueError("bucket_minutes must be > 0")
    if window_hours <= 0:
        raise ValueError("window_hours must be > 0")

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    window_start = now - timedelta(hours=window_hours)
    bucket_count = (window_hours * 60) // bucket_minutes

    # Pre-allocate bucket slots aligned to bucket boundaries
    bucket_seconds = bucket_minutes * 60
    base_epoch = int(window_start.timestamp())
    base_epoch -= base_epoch % bucket_seconds  # snap down

    buckets: list[dict] = []
    for i in range(bucket_count):
        ts = datetime.fromtimestamp(base_epoch + i * bucket_seconds, tz=timezone.utc)
        bucket = {
            "ts":            ts.isoformat().replace("+00:00", "Z"),
            "_ts_epoch":     base_epoch + i * bucket_seconds,
            "count":         0,
            "phases":        set(),
        }
        if include_events:
            bucket["events"] = []
        buckets.append(bucket)

    phase_first_seen: dict[str, datetime] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        ts = _parse_ts(item.get("timestamp") or item.get("ts") or item.get("created_at"))
        if ts is None or ts < window_start or ts > now:
            continue
        item_epoch = int(ts.timestamp())
        if item_epoch < base_epoch:
            continue
        bucket_idx = (item_epoch - base_epoch) // bucket_seconds
        if bucket_idx < 0 or bucket_idx >= len(buckets):
            continue

        item_recorded_in_bucket = False
        for tactic in _extract_tactics(item):
            phase = map_tactic(tactic)
            if phase is None:
                continue
            buckets[bucket_idx]["count"] += 1
            buckets[bucket_idx]["phases"].add(phase)
            if phase not in phase_first_seen or ts < phase_first_seen[phase]:
                phase_first_seen[phase] = ts
            if include_events and not item_recorded_in_bucket:
                lst = buckets[bucket_idx]["events"]
                if len(lst) < max_events_per_bucket:
                    lst.append(_summarize_event(item, ts, phase))
                item_recorded_in_bucket = True

    # Cumulative deepest-phase pass + serialize phase set
    deepest_idx = -1
    first_phase: Optional[str] = None
    for b in buckets:
        for phase in b["phases"]:
            idx = PHASE_INDEX[phase]
            if idx > deepest_idx:
                deepest_idx = idx
            if first_phase is None or PHASE_INDEX[phase] < PHASE_INDEX[first_phase]:
                first_phase = phase
        b["deepest_index"] = deepest_idx
        b["deepest_phase"] = PHASES[deepest_idx] if deepest_idx >= 0 else None
        b["phases"] = sorted(b["phases"], key=lambda p: PHASE_INDEX[p])
        b.pop("_ts_epoch", None)

    return {
        "host_id":      host_id,
        "bucket_min":   bucket_minutes,
        "window_hours": window_hours,
        "from_ts":      datetime.fromtimestamp(base_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "to_ts":        now.isoformat().replace("+00:00", "Z"),
        "buckets":      buckets,
        "summary": {
            "first_phase":      first_phase,
            "current_phase":    PHASES[deepest_idx] if deepest_idx >= 0 else None,
            "current_index":    deepest_idx,
            "phase_first_seen": {
                p: dt.isoformat().replace("+00:00", "Z")
                for p, dt in phase_first_seen.items()
            },
        },
    }


__all__ += ["derive_progression_timeline"]


def resolve_window_events(
    items: Iterable[dict],
    *,
    from_ts: Optional[str | datetime] = None,
    to_ts: Optional[str | datetime] = None,
    phase: Optional[str] = None,
) -> list[dict]:
    """Filter and normalize events for a drill-down window.

    Each returned dict carries:
        ts             ISO 8601 string
        ts_epoch       int (sortable)
        mitre_tactic   first tactic detected
        lockheed_phase mapped phase (or None)
        severity       passthrough
        event_type     passthrough
        source_ip      passthrough
        process        passthrough
        summary        short text (best-effort)
        raw            original dict (for full inspection)

    Sorted descending by timestamp. If `phase` is given, only events whose
    mapped Lockheed phase matches are included.
    """
    from_dt = _parse_ts(from_ts) if from_ts is not None else None
    to_dt   = _parse_ts(to_ts)   if to_ts   is not None else None

    out: list[dict] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ts = _parse_ts(item.get("timestamp") or item.get("ts") or item.get("created_at"))
        if ts is None:
            continue
        if from_dt and ts < from_dt:
            continue
        if to_dt and ts > to_dt:
            continue
        tactics = _extract_tactics(item)
        first_tactic = tactics[0] if tactics else None
        mapped_phase = map_tactic(first_tactic) if first_tactic else None
        # Walk other tactics in case the first didn't map
        if mapped_phase is None:
            for t in tactics[1:]:
                p = map_tactic(t)
                if p:
                    mapped_phase = p
                    first_tactic = t
                    break
        if phase and mapped_phase != phase:
            continue

        ts_iso = ts.isoformat().replace("+00:00", "Z")
        summary = (
            item.get("summary")
            or item.get("description")
            or item.get("message")
            or item.get("rule_id")
            or item.get("event_type")
            or ""
        )
        out.append({
            "ts":             ts_iso,
            "ts_epoch":       int(ts.timestamp()),
            "mitre_tactic":   first_tactic,
            "lockheed_phase": mapped_phase,
            "severity":       item.get("severity") or item.get("level"),
            "event_type":     item.get("event_type") or item.get("type"),
            "source_ip":      item.get("source_ip") or item.get("src_ip"),
            "process":        item.get("process") or item.get("process_name"),
            "summary":        str(summary)[:240] if summary else "",
            "raw":            item,
        })
    out.sort(key=lambda e: e["ts_epoch"], reverse=True)
    return out


__all__ += ["resolve_window_events"]


def derive_fleet_timeline(
    hosts_data: Iterable[dict],
    *,
    bucket_minutes: int = 15,
    window_hours: int = 24,
    now: Optional[datetime] = None,
) -> dict:
    """Aggregate multi-host kill-chain progression over time.

    For each time bucket within `window_hours`, count how many hosts have
    reached each Lockheed phase by that point. The count is *cumulative*:
    once a host enters a phase, it stays in (or past) that phase forever.

    Each host is counted in exactly one phase per bucket — its deepest at
    that point in time. Hosts with no events yet contribute nothing.

    Returns:
        {
          "bucket_min":   int,
          "window_hours": int,
          "from_ts":      iso str,
          "to_ts":        iso str,
          "phases":       [...6 phase ids in canonical order...],
          "phase_labels": [...labels pt-br...],
          "buckets": [
              {
                "ts":          iso str (bucket start),
                "by_phase": {
                    phase_id: int,  # number of hosts in this phase at this bucket
                    ...
                },
                "total_active": int,  # hosts that have any progression by this bucket
              },
              ...
          ],
          "summary": {
              "total_hosts":     int,
              "hosts_with_kc":   int,
              "peak_total":      int,  # max total_active across buckets
              "peak_phase":      phase_id with highest count at the last bucket
          }
        }
    """
    if bucket_minutes <= 0:
        raise ValueError("bucket_minutes must be > 0")
    if window_hours <= 0:
        raise ValueError("window_hours must be > 0")

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    bucket_seconds = bucket_minutes * 60
    base_epoch = int(window_start.timestamp())
    base_epoch -= base_epoch % bucket_seconds
    bucket_count = (window_hours * 60) // bucket_minutes

    # Pre-allocate empty buckets
    buckets: list[dict] = []
    for i in range(bucket_count):
        ts = datetime.fromtimestamp(base_epoch + i * bucket_seconds, tz=timezone.utc)
        buckets.append({
            "ts":           ts.isoformat().replace("+00:00", "Z"),
            "_ts_epoch":    base_epoch + i * bucket_seconds,
            "by_phase":     {p: 0 for p in PHASES},
            "total_active": 0,
        })

    total_hosts = 0
    hosts_with_kc = 0

    for host in hosts_data:
        if not isinstance(host, dict):
            continue
        host_id = host.get("host_id") or host.get("id") or ""
        if not host_id:
            continue
        total_hosts += 1

        # Collect all events with valid timestamps + tactic mappings
        events: list[tuple[int, int]] = []  # (epoch, phase_idx)
        sources = []
        for key in ("events", "detections", "mitre_events", "recent_events", "correlations"):
            v = host.get(key)
            if isinstance(v, (list, tuple)):
                sources.extend(v)
        for item in sources:
            if not isinstance(item, dict):
                continue
            ts = _parse_ts(item.get("timestamp") or item.get("ts") or item.get("created_at"))
            if ts is None:
                continue
            ev_epoch = int(ts.timestamp())
            # Skip events outside the visible window — fleet timeline reflects
            # only what happened within [base_epoch, now]
            if ev_epoch < base_epoch or ts > now:
                continue
            for tactic in _extract_tactics(item):
                phase = map_tactic(tactic)
                if phase is None:
                    continue
                events.append((ev_epoch, PHASE_INDEX[phase]))

        if not events:
            continue
        hosts_with_kc += 1

        # Walk buckets, track this host's deepest phase at each one (cumulative)
        events.sort(key=lambda e: e[0])
        deepest = -1
        ev_iter = iter(events)
        next_event = next(ev_iter, None)

        for b in buckets:
            bucket_end_epoch = b["_ts_epoch"] + bucket_seconds
            # advance through events that occurred up to this bucket's end
            while next_event is not None and next_event[0] < bucket_end_epoch:
                if next_event[1] > deepest:
                    deepest = next_event[1]
                next_event = next(ev_iter, None)
            if deepest >= 0:
                b["by_phase"][PHASES[deepest]] += 1
                b["total_active"] += 1

    # Find peak total + peak phase at last meaningful bucket
    peak_total = max((b["total_active"] for b in buckets), default=0)
    peak_phase: Optional[str] = None
    if hosts_with_kc and buckets:
        last = buckets[-1]
        if last["total_active"] > 0:
            peak_phase = max(last["by_phase"].items(), key=lambda kv: kv[1])[0]

    # Strip internal helper field
    for b in buckets:
        b.pop("_ts_epoch", None)

    return {
        "bucket_min":   bucket_minutes,
        "window_hours": window_hours,
        "from_ts":      datetime.fromtimestamp(base_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "to_ts":        now.isoformat().replace("+00:00", "Z"),
        "phases":       list(PHASES),
        "phase_labels": [PHASE_LABELS[p]["pt"] for p in PHASES],
        "buckets":      buckets,
        "summary": {
            "total_hosts":   total_hosts,
            "hosts_with_kc": hosts_with_kc,
            "peak_total":    peak_total,
            "peak_phase":    peak_phase,
        },
    }


__all__ += ["derive_fleet_timeline"]


# ── Fleet timeline aggregator (multi-host stacked area) ──────────
def build_fleet_timeline(
    hosts_data: Iterable[dict],
    *,
    bucket_minutes: int = 60,
    window_hours: int = 24,
    now: Optional[datetime] = None,
    tenant_id: Optional[str] = None,
) -> dict:
    """Aggregate per-host kill-chain progression into a time-bucketed fleet view.

    For every bucket in the time window, count how many hosts are at each
    Lockheed phase (using cumulative deepest reached up to that bucket).
    Resulting payload is ready for a stacked-area chart.

    Input host shape (same as build_heatmap):
        {host_id, tenant_id?, events|detections|mitre_events: [items with timestamp]}

    Returns:
        {
          "phases":       [...6 ids...],
          "phase_labels": [...pt labels...],
          "bucket_min":   int,
          "window_hours": int,
          "from_ts":      ISO,
          "to_ts":        ISO,
          "host_count":   int (total distinct hosts considered),
          "buckets": [
              {
                "ts":           ISO,
                "phases":       {phase_id: hosts_count, ...} (always 6 keys),
                "total_active": int (hosts that reached at least Recon at this bucket),
              },
              ...
          ],
          "max_total":   int (peak total_active across buckets — useful for chart scaling),
        }
    """
    if bucket_minutes <= 0:
        raise ValueError("bucket_minutes must be > 0")
    if window_hours <= 0:
        raise ValueError("window_hours must be > 0")

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    window_start = now - timedelta(hours=window_hours)
    bucket_seconds = bucket_minutes * 60
    base_epoch = int(window_start.timestamp())
    base_epoch -= base_epoch % bucket_seconds
    bucket_count = (window_hours * 60) // bucket_minutes

    # Pre-allocate
    bucket_phase_counts: list[dict[str, int]] = []
    for _ in range(bucket_count):
        bucket_phase_counts.append({p: 0 for p in PHASES})

    norm_tenant = (str(tenant_id).strip() if tenant_id is not None else None) or None

    host_seen = 0
    for host in hosts_data:
        if not isinstance(host, dict):
            continue
        host_id = host.get("host_id") or host.get("id") or ""
        if not host_id:
            continue
        if norm_tenant is not None:
            if str(host.get("tenant_id") or "") != norm_tenant:
                continue
        host_seen += 1

        items: list = []
        for key in ("events", "detections", "mitre_events", "recent_events", "correlations"):
            v = host.get(key)
            if isinstance(v, (list, tuple)):
                items.extend(v)

        # For this host, find deepest-phase reached per bucket cumulatively
        per_bucket_deepest: list[int] = [-1] * bucket_count
        for item in items:
            if not isinstance(item, dict):
                continue
            ts = _parse_ts(item.get("timestamp") or item.get("ts") or item.get("created_at"))
            if ts is None or ts < window_start or ts > now:
                continue
            item_epoch = int(ts.timestamp())
            if item_epoch < base_epoch:
                continue
            bidx = (item_epoch - base_epoch) // bucket_seconds
            if bidx < 0 or bidx >= bucket_count:
                continue
            for tactic in _extract_tactics(item):
                phase = map_tactic(tactic)
                if phase is None:
                    continue
                pidx = PHASE_INDEX[phase]
                if pidx > per_bucket_deepest[bidx]:
                    per_bucket_deepest[bidx] = pidx

        # Propagate forward (cumulative): once a host reaches a phase, it stays
        running = -1
        for i in range(bucket_count):
            if per_bucket_deepest[i] > running:
                running = per_bucket_deepest[i]
            if running >= 0:
                bucket_phase_counts[i][PHASES[running]] += 1

    # Serialize
    buckets_out: list[dict] = []
    max_total = 0
    for i, counts in enumerate(bucket_phase_counts):
        ts = datetime.fromtimestamp(base_epoch + i * bucket_seconds, tz=timezone.utc)
        total = sum(counts.values())
        if total > max_total:
            max_total = total
        buckets_out.append({
            "ts":           ts.isoformat().replace("+00:00", "Z"),
            "phases":       counts,
            "total_active": total,
        })

    return {
        "phases":       list(PHASES),
        "phase_labels": [PHASE_LABELS[p]["pt"] for p in PHASES],
        "bucket_min":   bucket_minutes,
        "window_hours": window_hours,
        "from_ts":      datetime.fromtimestamp(base_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "to_ts":        now.isoformat().replace("+00:00", "Z"),
        "host_count":   host_seen,
        "buckets":      buckets_out,
        "max_total":    max_total,
    }


__all__ += ["build_fleet_timeline"]
