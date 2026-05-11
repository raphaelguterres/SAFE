"""SAFE Asset Intelligence — enrichment do host com classificação e criticality.

Separa **risk_score** (quão ameaçado o host está, motor de `risk_engine`) de
**criticality_score** (quão valioso o ativo é). Um servidor de produção sem
ataques nenhum pode ter criticality 95 mas risk 0; um workstation comprometida
pode ter criticality 30 mas risk 90. A prioridade real combina ambos.

API pública:
    AssetClass               — Enum das classes canônicas
    Sensitivity              — Enum 1-4
    Environment              — prod/staging/dev/unknown
    AssetProfile             — dataclass com todos os campos
    classify_asset(hint)     — heurística por hostname/tags/role
    score_criticality(profile)  → 0..100
    enrich_host(host_record) → AssetProfile (não muta o host, só projeta)
    business_impact_label(score) → "low|medium|high|critical"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ── Classes canônicas ───────────────────────────────────────────
class AssetClass(str, Enum):
    WORKSTATION       = "workstation"
    SERVER            = "server"
    DOMAIN_CONTROLLER = "domain_controller"
    DATABASE          = "database"
    DEV_MACHINE       = "dev_machine"
    EXECUTIVE_DEVICE  = "executive_device"
    CRITICAL_ASSET    = "critical_asset"
    UNKNOWN           = "unknown"


class Sensitivity(int, Enum):
    PUBLIC   = 1
    INTERNAL = 2
    CONFIDENTIAL = 3
    RESTRICTED = 4


class Environment(str, Enum):
    PROD    = "prod"
    STAGING = "staging"
    DEV     = "dev"
    UNKNOWN = "unknown"


# ── Profile schema ──────────────────────────────────────────────
@dataclass
class AssetProfile:
    host_id:           str
    asset_class:       AssetClass = AssetClass.UNKNOWN
    criticality_score: int = 0                 # 0..100
    business_impact:   str = "low"             # low|medium|high|critical
    owner:             Optional[str] = None
    environment:       Environment = Environment.UNKNOWN
    sensitivity:       Sensitivity = Sensitivity.INTERNAL
    tags:              list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["asset_class"] = self.asset_class.value
        d["environment"] = self.environment.value
        d["sensitivity"] = int(self.sensitivity)
        return d


# ── Heurísticas de classificação ────────────────────────────────
# Match order matters: more specific first.
_CLASS_PATTERNS = [
    (AssetClass.DOMAIN_CONTROLLER, [
        r"\bdc\d*\b", r"-dc-?\d*", r"\bdomctl", r"\badctrl", r"domain.controller",
    ]),
    (AssetClass.DATABASE, [
        r"\bdb\d*\b", r"-db-?\d*", r"sqlsrv", r"\bpgsql", r"\bmysql", r"\bmongo",
        r"\boracle\b", r"\bmssql",
    ]),
    (AssetClass.EXECUTIVE_DEVICE, [
        r"\bceo\b", r"\bcfo\b", r"\bcto\b", r"\bciso\b", r"\bcoo\b",
        r"-exec-", r"-vp-", r"-board-",
    ]),
    (AssetClass.DEV_MACHINE, [
        r"\bdev\d*\b", r"-dev-", r"\bdevbox", r"workstation-dev",
    ]),
    (AssetClass.SERVER, [
        r"\bsrv\d*\b", r"\bsvr\d*\b", r"\bweb\d*\b", r"-prod-", r"-srv-",
        r"\bapp\d*\b", r"\bapi\d*\b", r"linux\d*", r"\bsrvr",
    ]),
    (AssetClass.WORKSTATION, [
        r"\bwin\d+", r"-wks-", r"\bwks\d*", r"\blaptop", r"\bdesktop\b",
    ]),
]

_TAG_OVERRIDES = {
    "domain-controller":   AssetClass.DOMAIN_CONTROLLER,
    "dc":                  AssetClass.DOMAIN_CONTROLLER,
    "database":            AssetClass.DATABASE,
    "db":                  AssetClass.DATABASE,
    "server":              AssetClass.SERVER,
    "workstation":         AssetClass.WORKSTATION,
    "dev":                 AssetClass.DEV_MACHINE,
    "executive":           AssetClass.EXECUTIVE_DEVICE,
    "vip":                 AssetClass.EXECUTIVE_DEVICE,
    "critical":            AssetClass.CRITICAL_ASSET,
    "critical-asset":      AssetClass.CRITICAL_ASSET,
}

_ENV_HINTS = {
    "prod":    Environment.PROD,
    "production": Environment.PROD,
    "live":    Environment.PROD,
    "staging": Environment.STAGING,
    "stage":   Environment.STAGING,
    "stg":     Environment.STAGING,
    "qa":      Environment.STAGING,
    "test":    Environment.STAGING,
    "dev":     Environment.DEV,
    "develop": Environment.DEV,
    "sandbox": Environment.DEV,
}


def classify_asset(hint: dict) -> AssetClass:
    """Decide asset_class por hostname, tags explícitas ou role.

    Ordem de prioridade:
        1. tag explícita (e.g. ['critical-asset'])
        2. campo `role` direto se for AssetClass válido
        3. regex no hostname / display_name
    """
    if not isinstance(hint, dict):
        return AssetClass.UNKNOWN

    # 1. Tag overrides
    tags = hint.get("tags") or []
    if isinstance(tags, (list, tuple)):
        for tag in tags:
            key = str(tag).strip().lower()
            if key in _TAG_OVERRIDES:
                return _TAG_OVERRIDES[key]

    # 2. Direct role field
    role = (hint.get("role") or hint.get("asset_class") or "").strip().lower()
    if role:
        try:
            return AssetClass(role)
        except ValueError:
            pass

    # 3. Hostname regex
    name = str(
        hint.get("hostname")
        or hint.get("display_name")
        or hint.get("host_id")
        or ""
    ).lower()
    if name:
        for cls, patterns in _CLASS_PATTERNS:
            for pat in patterns:
                if re.search(pat, name):
                    return cls

    return AssetClass.UNKNOWN


def detect_environment(hint: dict) -> Environment:
    """Detecta environment via tags ou hostname."""
    if not isinstance(hint, dict):
        return Environment.UNKNOWN

    explicit = (hint.get("environment") or "").strip().lower()
    if explicit in _ENV_HINTS:
        return _ENV_HINTS[explicit]

    tags = hint.get("tags") or []
    if isinstance(tags, (list, tuple)):
        for tag in tags:
            key = str(tag).strip().lower()
            if key in _ENV_HINTS:
                return _ENV_HINTS[key]

    name = str(
        hint.get("hostname")
        or hint.get("display_name")
        or hint.get("host_id")
        or ""
    ).lower()
    for token, env in _ENV_HINTS.items():
        if token in name:
            return env

    return Environment.UNKNOWN


# ── Criticality scoring ─────────────────────────────────────────
# Base score per class — what the asset is worth if everything else is equal
_CLASS_BASE_SCORE = {
    AssetClass.DOMAIN_CONTROLLER: 95,
    AssetClass.CRITICAL_ASSET:    90,
    AssetClass.DATABASE:          80,
    AssetClass.EXECUTIVE_DEVICE:  75,
    AssetClass.SERVER:            60,
    AssetClass.WORKSTATION:       30,
    AssetClass.DEV_MACHINE:       20,
    AssetClass.UNKNOWN:           25,
}

_ENV_MULTIPLIER = {
    Environment.PROD:    1.0,
    Environment.STAGING: 0.65,
    Environment.DEV:     0.35,
    Environment.UNKNOWN: 0.80,
}

_SENSITIVITY_BUMP = {
    Sensitivity.PUBLIC:       -10,
    Sensitivity.INTERNAL:       0,
    Sensitivity.CONFIDENTIAL:  +8,
    Sensitivity.RESTRICTED:   +15,
}


def score_criticality(profile: AssetProfile) -> int:
    """Compute criticality_score 0..100 from profile fields."""
    base = _CLASS_BASE_SCORE.get(profile.asset_class, 25)
    mult = _ENV_MULTIPLIER.get(profile.environment, 0.80)
    score = base * mult + _SENSITIVITY_BUMP.get(profile.sensitivity, 0)
    return max(0, min(100, int(round(score))))


def business_impact_label(score: int) -> str:
    """Map criticality_score → low|medium|high|critical bucket label."""
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


# ── High-level enrich entrypoint ────────────────────────────────
def enrich_host(host_record: dict) -> AssetProfile:
    """Project a host record (whatever shape) into an AssetProfile.

    Never mutates input. Falls back to safe defaults.
    """
    if not isinstance(host_record, dict):
        return AssetProfile(host_id="")

    host_id = host_record.get("host_id") or host_record.get("id") or ""

    asset_class = classify_asset(host_record)
    environment = detect_environment(host_record)

    sensitivity = Sensitivity.INTERNAL
    raw_sens = host_record.get("sensitivity")
    if isinstance(raw_sens, int) and 1 <= raw_sens <= 4:
        sensitivity = Sensitivity(raw_sens)
    elif isinstance(raw_sens, str):
        try:
            sensitivity = Sensitivity[raw_sens.strip().upper()]
        except KeyError:
            pass

    tags = list(host_record.get("tags") or [])
    owner = host_record.get("owner")

    profile = AssetProfile(
        host_id=host_id,
        asset_class=asset_class,
        environment=environment,
        sensitivity=sensitivity,
        tags=tags,
        owner=owner,
    )
    profile.criticality_score = score_criticality(profile)
    profile.business_impact   = business_impact_label(profile.criticality_score)
    return profile


__all__ = [
    "AssetClass",
    "Sensitivity",
    "Environment",
    "AssetProfile",
    "classify_asset",
    "detect_environment",
    "score_criticality",
    "business_impact_label",
    "enrich_host",
]
