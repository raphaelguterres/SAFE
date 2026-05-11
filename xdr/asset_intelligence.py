"""SAFE Asset Intelligence — classification, criticality and enrichment.

This module enriches the host data already collected by the agent/risk
pipeline with the asset-side context an analyst needs to prioritize:

    asset_class       — workstation | server | domain_controller | database |
                        developer_machine | executive_device | critical_asset
    environment       — production | staging | development | lab
    sensitivity       — public | internal | confidential | restricted
    criticality_score — 0..100 (value of the asset, not threat)
    business_impact   — short label ("blast radius" hint)
    owner             — free-form ("infra-team", "ceo@acme")
    tags              — free-form list

Risk = threat * exposure; criticality = value of the asset on its own.
They combine downstream in prioritization, but stay separate here so SOCs
can compare like-for-like across tenants.

Pure stdlib. Read-only enrichment — never mutates the input dict.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Optional

logger = logging.getLogger("safe.asset_intel")


# ── Enums ────────────────────────────────────────────────────────
class AssetClass(str, Enum):
    WORKSTATION        = "workstation"
    SERVER             = "server"
    DOMAIN_CONTROLLER  = "domain_controller"
    DATABASE           = "database"
    DEVELOPER_MACHINE  = "developer_machine"
    EXECUTIVE_DEVICE   = "executive_device"
    CRITICAL_ASSET     = "critical_asset"
    UNKNOWN            = "unknown"


class Environment(str, Enum):
    PRODUCTION  = "production"
    STAGING     = "staging"
    DEVELOPMENT = "development"
    LAB         = "lab"
    UNKNOWN     = "unknown"


class Sensitivity(str, Enum):
    PUBLIC       = "public"
    INTERNAL     = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED   = "restricted"


# ── Heuristics (hostname / role / process / tag patterns) ────────
# Order matters — the most specific class wins on conflict.

_DC_PATTERNS = re.compile(
    r"(?:^|[\-_.])(?:dc\d*|adc|domain[\-_]?controller|kdc\d*)(?:[\-_.]|$)",
    re.IGNORECASE,
)
_DB_PATTERNS = re.compile(
    r"(?:^|[\-_.])(?:db|sql|mssql|postgres|pg|oracle|mongo|mysql|redis|cassandra)(?:[\-_0-9]|[\-_.]|$)",
    re.IGNORECASE,
)
_DEV_PATTERNS = re.compile(
    r"(?:^|[\-_.])(?:dev|devel|developer|laptop|wks[\-_]?dev)(?:[\-_.]|$)",
    re.IGNORECASE,
)
_EXEC_PATTERNS = re.compile(
    r"(?:^|[\-_.])(?:ceo|cto|cfo|cio|cso|exec|board|director|vp)(?:[\-_.]|$)",
    re.IGNORECASE,
)
_SERVER_PATTERNS = re.compile(
    r"(?:^|[\-_.])(?:srv|server|web|api|app|prod|svc|backend|nginx|apache)(?:[\-_0-9]|[\-_.]|$)",
    re.IGNORECASE,
)
_WKS_PATTERNS = re.compile(
    r"(?:^|[\-_.])(?:wks|workstation|desktop|pc|client)(?:[\-_0-9]|[\-_.]|$)",
    re.IGNORECASE,
)

_PROD_TAGS  = {"prod", "production"}
_STAGE_TAGS = {"staging", "stage", "qa", "uat"}
_DEV_TAGS   = {"dev", "development"}
_LAB_TAGS   = {"lab", "test", "sandbox"}

_SENSITIVE_TAGS = {
    "pii", "phi", "pci", "secret", "kms", "vault", "backup",
    "finance", "payroll", "hr", "legal", "compliance",
}


@dataclass
class AssetProfile:
    host_id:           str
    display_name:      Optional[str] = None
    asset_class:       AssetClass    = AssetClass.UNKNOWN
    environment:       Environment   = Environment.UNKNOWN
    sensitivity:       Sensitivity   = Sensitivity.INTERNAL
    criticality_score: int           = 0           # 0..100
    business_impact:   str           = ""
    owner:             Optional[str] = None
    tags:              list          = field(default_factory=list)
    classification_reasons: list     = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "host_id":                self.host_id,
            "display_name":           self.display_name,
            "asset_class":            self.asset_class.value,
            "environment":            self.environment.value,
            "sensitivity":            self.sensitivity.value,
            "criticality_score":      self.criticality_score,
            "business_impact":        self.business_impact,
            "owner":                  self.owner,
            "tags":                   list(self.tags),
            "classification_reasons": list(self.classification_reasons),
        }


# ── Public API ───────────────────────────────────────────────────
def classify_asset(host: dict) -> tuple[AssetClass, list[str]]:
    """Heuristically classify an asset based on hostname/role/tags/processes.

    Manual override via ``host["asset_class"]`` always wins.
    Returns (AssetClass, reasons[]).
    """
    if not isinstance(host, dict):
        return AssetClass.UNKNOWN, []

    # 1) Manual override always wins
    manual = host.get("asset_class")
    if isinstance(manual, str):
        try:
            return AssetClass(manual.strip().lower()), ["manual_override"]
        except ValueError:
            pass

    # 2) Explicit role field
    role = str(host.get("role") or "").strip().lower()
    if role:
        for ac in AssetClass:
            if ac.value == role:
                return ac, [f"role={role}"]

    # 3) Hostname pattern matching
    name = str(host.get("display_name") or host.get("hostname") or host.get("host_id") or "")
    reasons: list[str] = []

    if _DC_PATTERNS.search(name):
        return AssetClass.DOMAIN_CONTROLLER, [f"hostname:{name} matches DC pattern"]
    if _DB_PATTERNS.search(name):
        return AssetClass.DATABASE, [f"hostname:{name} matches DB pattern"]
    if _EXEC_PATTERNS.search(name):
        return AssetClass.EXECUTIVE_DEVICE, [f"hostname:{name} matches exec pattern"]
    if _DEV_PATTERNS.search(name):
        return AssetClass.DEVELOPER_MACHINE, [f"hostname:{name} matches dev pattern"]
    if _SERVER_PATTERNS.search(name):
        return AssetClass.SERVER, [f"hostname:{name} matches server pattern"]
    if _WKS_PATTERNS.search(name):
        return AssetClass.WORKSTATION, [f"hostname:{name} matches workstation pattern"]

    # 4) Platform-based fallback
    platform = str(host.get("platform") or host.get("os") or "").lower()
    if "windows server" in platform or "linux" in platform:
        if "server" in platform or "rhel" in platform or "ubuntu server" in platform:
            return AssetClass.SERVER, [f"platform:{platform}"]

    # 5) Tag inference
    tags = {str(t).lower() for t in (host.get("tags") or []) if t}
    if tags & {"dc", "domain-controller"}:
        return AssetClass.DOMAIN_CONTROLLER, ["tag:dc"]
    if tags & {"db", "database"}:
        return AssetClass.DATABASE, ["tag:db"]
    if tags & {"executive", "vip", "c-level"}:
        return AssetClass.EXECUTIVE_DEVICE, ["tag:executive"]

    return AssetClass.UNKNOWN, ["no_signal"]


def infer_environment(host: dict) -> Environment:
    """Pick environment from explicit field, then tags, then hostname hints."""
    if not isinstance(host, dict):
        return Environment.UNKNOWN

    explicit = str(host.get("environment") or "").strip().lower()
    if explicit:
        for env in Environment:
            if env.value == explicit:
                return env

    tags = {str(t).lower() for t in (host.get("tags") or []) if t}
    if tags & _PROD_TAGS:  return Environment.PRODUCTION
    if tags & _STAGE_TAGS: return Environment.STAGING
    if tags & _DEV_TAGS:   return Environment.DEVELOPMENT
    if tags & _LAB_TAGS:   return Environment.LAB

    name = str(host.get("display_name") or host.get("hostname") or host.get("host_id") or "").lower()
    if "-prod" in name or name.endswith("prod"):  return Environment.PRODUCTION
    if "-stg" in name or "-staging" in name:      return Environment.STAGING
    if "-dev" in name:                             return Environment.DEVELOPMENT
    if "-lab" in name or "-test" in name:          return Environment.LAB

    return Environment.UNKNOWN


def infer_sensitivity(host: dict, asset_class: AssetClass) -> Sensitivity:
    """Pick sensitivity from explicit field, then class defaults, then tags."""
    if not isinstance(host, dict):
        return Sensitivity.INTERNAL

    explicit = str(host.get("sensitivity") or "").strip().lower()
    if explicit:
        for s in Sensitivity:
            if s.value == explicit:
                return s

    tags = {str(t).lower() for t in (host.get("tags") or []) if t}
    if tags & _SENSITIVE_TAGS:
        return Sensitivity.RESTRICTED

    # Class-based defaults
    if asset_class in (AssetClass.DOMAIN_CONTROLLER, AssetClass.DATABASE,
                       AssetClass.EXECUTIVE_DEVICE, AssetClass.CRITICAL_ASSET):
        return Sensitivity.CONFIDENTIAL
    if asset_class == AssetClass.SERVER:
        return Sensitivity.INTERNAL

    return Sensitivity.INTERNAL


def compute_criticality(
    asset_class: AssetClass,
    environment: Environment,
    sensitivity: Sensitivity,
    tags: Iterable[str] = (),
) -> tuple[int, str]:
    """Compute criticality score 0..100 and a short business_impact label.

    Score formula:
        base by class + environment boost + sensitivity boost + tag boost
    Capped at 100.
    """
    class_base = {
        AssetClass.WORKSTATION:        20,
        AssetClass.SERVER:             50,
        AssetClass.DEVELOPER_MACHINE:  30,
        AssetClass.DOMAIN_CONTROLLER:  90,
        AssetClass.DATABASE:           80,
        AssetClass.EXECUTIVE_DEVICE:   75,
        AssetClass.CRITICAL_ASSET:     95,
        AssetClass.UNKNOWN:            10,
    }[asset_class]

    env_boost = {
        Environment.PRODUCTION:  15,
        Environment.STAGING:      5,
        Environment.DEVELOPMENT:  0,
        Environment.LAB:         -5,
        Environment.UNKNOWN:      0,
    }[environment]

    sens_boost = {
        Sensitivity.PUBLIC:       -5,
        Sensitivity.INTERNAL:      0,
        Sensitivity.CONFIDENTIAL: 10,
        Sensitivity.RESTRICTED:   20,
    }[sensitivity]

    tag_boost = 0
    tag_set = {str(t).lower() for t in tags or ()}
    if tag_set & _SENSITIVE_TAGS:
        tag_boost += 5

    score = max(0, min(100, class_base + env_boost + sens_boost + tag_boost))

    # Business impact label
    if score >= 85:
        impact = "Critical — outage or data loss affects whole tenant"
    elif score >= 65:
        impact = "High — service or compliance impact"
    elif score >= 40:
        impact = "Medium — workgroup impact"
    elif score >= 20:
        impact = "Low — individual user impact"
    else:
        impact = "Minimal"

    return score, impact


def enrich_host(host: dict) -> AssetProfile:
    """Public entry point: takes a raw host record and returns AssetProfile.

    Never mutates the input. Always returns a profile (UNKNOWN class if no
    signal is available).
    """
    if not isinstance(host, dict):
        return AssetProfile(host_id="")

    host_id = str(host.get("host_id") or host.get("id") or "")
    display = host.get("display_name") or host.get("hostname")

    asset_class, reasons = classify_asset(host)
    env = infer_environment(host)
    sens = infer_sensitivity(host, asset_class)
    tags = [str(t) for t in (host.get("tags") or []) if t]

    score, impact = compute_criticality(asset_class, env, sens, tags)

    return AssetProfile(
        host_id=host_id,
        display_name=display,
        asset_class=asset_class,
        environment=env,
        sensitivity=sens,
        criticality_score=score,
        business_impact=impact,
        owner=host.get("owner") or None,
        tags=tags,
        classification_reasons=reasons,
    )


__all__ = [
    "AssetClass",
    "Environment",
    "Sensitivity",
    "AssetProfile",
    "classify_asset",
    "infer_environment",
    "infer_sensitivity",
    "compute_criticality",
    "enrich_host",
]
