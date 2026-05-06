"""Detection rule catalog and coverage summary for SOC operations."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from rules.yaml_loader import (
    DEFAULT_RULES_DIR,
    YamlDetectionRule,
    YamlRuleLoadReport,
    load_yaml_rule_report,
)

from .detections import DEFAULT_RULES, DetectionRule, YamlRuleSet
from .killchain_engine import KillChainStage, TACTIC_TO_STAGE
from .schema import ALLOWED_EVENT_TYPES


def build_detection_rule_catalog(
    *,
    rules: tuple[Any, ...] | list[Any] | None = None,
    yaml_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Build an operator-facing catalog without exposing local secrets/paths."""

    active_rules = tuple(DEFAULT_RULES if rules is None else rules)
    yaml_report = load_yaml_rule_report(yaml_dir or DEFAULT_RULES_DIR)
    records = [
        _record_builtin_rule(rule)
        for rule in active_rules
        if not isinstance(rule, YamlRuleSet)
    ]
    records.extend(_record_yaml_rule(rule) for rule in yaml_report.registry.rules)
    records = sorted(records, key=lambda item: (item["source"], item["rule_id"]))
    return {
        "rules": records,
        "summary": _summarize(records, yaml_report, yaml_dir or DEFAULT_RULES_DIR),
    }


def build_detection_coverage(
    *,
    rules: tuple[Any, ...] | list[Any] | None = None,
    yaml_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Return MITRE and Kill Chain coverage, tolerating invalid YAML files."""

    catalog = build_detection_rule_catalog(rules=rules, yaml_dir=yaml_dir)
    records = catalog["rules"]
    rules_by_tactic: Counter[str] = Counter()
    rules_by_technique: Counter[str] = Counter()
    stages = set()
    for record in records:
        mitre = record.get("mitre") or {}
        tactic = _normalize_tactic(mitre.get("tactic"))
        technique = str(mitre.get("technique") or "").strip()
        if tactic:
            rules_by_tactic[tactic] += 1
            mapped_stage = TACTIC_TO_STAGE.get(tactic)
            if mapped_stage:
                stages.add(mapped_stage.value)
        else:
            rules_by_tactic["unmapped"] += 1
        if technique:
            for piece in _split_techniques(technique):
                rules_by_technique[piece] += 1

    all_stages = {stage.value for stage in KillChainStage}
    uncovered = sorted(all_stages - stages)
    coverage_score = int((len(stages) / len(all_stages)) * 100) if all_stages else 0
    top_detections = sorted(
        (
            {
                "rule_id": record.get("rule_id", ""),
                "name": record.get("name", ""),
                "source": record.get("source", ""),
                "severity": record.get("severity", ""),
                "tactic": (record.get("mitre") or {}).get("tactic", ""),
                "technique": (record.get("mitre") or {}).get("technique", ""),
            }
            for record in records
        ),
        key=lambda item: (_severity_rank(item["severity"]), item["tactic"], item["rule_id"]),
        reverse=True,
    )[:10]
    return {
        "total_rules": len(records),
        "rules_by_tactic": dict(sorted(rules_by_tactic.items())),
        "rules_by_technique": dict(sorted(rules_by_technique.items())),
        "uncovered_tactics": uncovered,
        "top_detections": top_detections,
        "killchain_coverage_score": coverage_score,
        "covered_killchain_stages": sorted(stages),
        "yaml_health": catalog["summary"].get("yaml_health", {}),
    }


def _record_builtin_rule(rule: DetectionRule) -> dict[str, Any]:
    return {
        "rule_id": str(getattr(rule, "rule_id", "")),
        "name": str(getattr(rule, "rule_name", "")),
        "source": "builtin",
        "source_file": "",
        "enabled": True,
        "severity": "dynamic",
        "event_types": list(getattr(rule, "supported_event_types", ()) or []),
        "alert_type": str(getattr(rule, "alert_type", "")),
        "mitre": {
            "tactic": str(getattr(rule, "mitre_tactic", "")),
            "technique": str(getattr(rule, "mitre_technique", "")),
        },
        "tags": list(getattr(rule, "base_tags", ()) or []),
        "recommended_action": str(getattr(rule, "recommended_action", "")),
        "sigma_like": False,
        "aggregation": False,
        "status": "active",
    }


def _record_yaml_rule(rule: YamlDetectionRule) -> dict[str, Any]:
    metadata = dict(rule.metadata or {})
    return {
        "rule_id": rule.rule_id,
        "name": rule.title,
        "description": rule.description,
        "source": "yaml",
        "source_file": rule.source_path,
        "enabled": True,
        "severity": rule.severity,
        "event_types": list(rule.event_types),
        "alert_type": rule.alert_type or rule.rule_id.lower().replace("-", "_"),
        "mitre": {
            "tactic": rule.tactic,
            "technique": rule.technique,
        },
        "tags": list(rule.tags),
        "recommended_action": rule.recommended_action,
        "sigma_like": bool(metadata.get("logsource") or metadata.get("status")),
        "aggregation": rule.aggregation is not None,
        "status": str(metadata.get("status") or "active"),
        "metadata": metadata,
    }


def _summarize(
    records: list[dict[str, Any]],
    yaml_report: YamlRuleLoadReport,
    yaml_dir: str | Path,
) -> dict[str, Any]:
    by_source = Counter(str(item.get("source") or "unknown") for item in records)
    by_severity = Counter(str(item.get("severity") or "unknown") for item in records)
    by_tactic = Counter(
        str((item.get("mitre") or {}).get("tactic") or "unmapped")
        for item in records
    )
    event_types = Counter()
    techniques = set()
    for item in records:
        for event_type in item.get("event_types") or []:
            event_types[str(event_type)] += 1
        technique = str((item.get("mitre") or {}).get("technique") or "").strip()
        if technique:
            techniques.add(technique)

    covered_events = set(event_types)
    return {
        "total_rules": len(records),
        "by_source": dict(sorted(by_source.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "by_tactic": dict(sorted(by_tactic.items())),
        "by_event_type": dict(sorted(event_types.items())),
        "mitre_techniques": sorted(techniques),
        "event_type_coverage": {
            "covered": sorted(covered_events),
            "missing": sorted(ALLOWED_EVENT_TYPES - covered_events),
        },
        "yaml_health": {
            "rules_dir": _safe_display_path(Path(yaml_dir)),
            "total_files": yaml_report.total_files,
            "loaded_files": yaml_report.loaded_files,
            "skipped_files": yaml_report.skipped_files,
            "errors": [
                {"source_path": item.source_path, "error": item.error}
                for item in yaml_report.errors
            ],
        },
    }


def _safe_display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(Path.cwd().resolve())).replace("\\", "/")
    except Exception:
        return path.name


def _normalize_tactic(value: Any) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _split_techniques(value: str) -> list[str]:
    parts: list[str] = []
    for chunk in str(value or "").replace("->", ",").replace(";", ",").split(","):
        text = chunk.strip()
        if text:
            parts.append(text)
    return parts


def _severity_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "dynamic": 0}.get(
        str(value or "").strip().lower(),
        0,
    )
