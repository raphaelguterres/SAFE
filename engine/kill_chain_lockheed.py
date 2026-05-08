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
