"""Detection pack management for SAFE."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class PackRollout:
    mode: str = "stable"
    canary_percent: int = 0
    staged_tenants: list[str] = field(default_factory=list)
    rollback_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "canary_percent": self.canary_percent,
            "staged_tenants": list(self.staged_tenants),
            "rollback_version": self.rollback_version,
        }


@dataclass
class DetectionPack:
    pack_id: str
    name: str
    version: str
    description: str
    rules: list[Mapping[str, Any]]
    enabled: bool = True
    dependencies: list[str] = field(default_factory=list)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    rollout: PackRollout = field(default_factory=PackRollout)
    tenant_tuning: dict[str, Mapping[str, Any]] = field(default_factory=dict)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "enabled": self.enabled,
            "dependencies": list(self.dependencies),
            "metadata": dict(self.metadata),
            "rollout": self.rollout.to_dict(),
            "tenant_tuning": {tenant: dict(value) for tenant, value in self.tenant_tuning.items()},
            "updated_at": self.updated_at,
            "rules": [dict(rule) for rule in self.rules],
            "rule_count": len(self.rules),
        }


class DetectionPackManager:
    """Manage pack visibility, enablement and tenant-specific tuning."""

    def __init__(self, packs: list[DetectionPack] | None = None) -> None:
        self._packs: dict[str, DetectionPack] = {pack.pack_id: pack for pack in (packs or [])}

    @classmethod
    def from_rule_catalog(cls, catalog: Mapping[str, Any]) -> "DetectionPackManager":
        rules = [dict(rule) for rule in (catalog.get("rules") or [])]
        builtin = [rule for rule in rules if rule.get("source") == "builtin"]
        yaml_rules = [rule for rule in rules if rule.get("source") == "yaml"]
        packs = [
            DetectionPack(
                pack_id="safe-builtin-core",
                name="SAFE Built-in Core",
                version="1.0.0",
                description="Built-in process, auth, network and behavior detections.",
                rules=builtin,
                metadata={"source": "builtin", "tuning_guidance": "Keep enabled for baseline XDR coverage."},
            ),
            DetectionPack(
                pack_id="safe-yaml-sigma",
                name="SAFE YAML / Sigma-like Rules",
                version="1.0.0",
                description="Tenant-portable YAML detection content.",
                rules=yaml_rules,
                metadata={"source": "yaml", "tuning_guidance": "Roll out canary first for noisy environments."},
            ),
        ]
        return cls([pack for pack in packs if pack.rules])

    def list_packs(self, *, tenant_id: str | None = None) -> list[dict[str, Any]]:
        result = []
        for pack in self._packs.values():
            data = pack.to_dict()
            if tenant_id and tenant_id in pack.tenant_tuning:
                data["effective_tuning"] = dict(pack.tenant_tuning[tenant_id])
            result.append(data)
        return sorted(result, key=lambda item: item["pack_id"])

    def set_enabled(self, pack_id: str, enabled: bool) -> dict[str, Any]:
        pack = self._require_pack(pack_id)
        pack.enabled = bool(enabled)
        pack.updated_at = _now()
        return pack.to_dict()

    def set_rollout(self, pack_id: str, *, mode: str, canary_percent: int = 0, staged_tenants: list[str] | None = None) -> dict[str, Any]:
        pack = self._require_pack(pack_id)
        if mode not in {"stable", "staged", "canary", "disabled"}:
            raise ValueError("invalid rollout mode")
        pack.rollout = PackRollout(
            mode=mode,
            canary_percent=max(0, min(100, int(canary_percent))),
            staged_tenants=list(staged_tenants or []),
            rollback_version=pack.version,
        )
        pack.updated_at = _now()
        return pack.to_dict()

    def tune_for_tenant(self, pack_id: str, tenant_id: str, tuning: Mapping[str, Any]) -> dict[str, Any]:
        pack = self._require_pack(pack_id)
        tenant = str(tenant_id or "").strip()
        if not tenant:
            raise ValueError("tenant_id is required")
        pack.tenant_tuning[tenant] = safe_tuning(tuning)
        pack.updated_at = _now()
        return pack.to_dict()

    def rollback(self, pack_id: str) -> dict[str, Any]:
        pack = self._require_pack(pack_id)
        pack.enabled = True
        pack.rollout = PackRollout(mode="stable", rollback_version=pack.rollout.rollback_version or pack.version)
        pack.updated_at = _now()
        return pack.to_dict()

    def _require_pack(self, pack_id: str) -> DetectionPack:
        try:
            return self._packs[pack_id]
        except KeyError as exc:
            raise KeyError(f"unknown detection pack: {pack_id}") from exc


def safe_tuning(tuning: Mapping[str, Any]) -> dict[str, Any]:
    allowed = {"enabled", "severity_override", "suppression_window_minutes", "notes", "excluded_hosts", "canary"}
    return {str(key): value for key, value in tuning.items() if key in allowed}
