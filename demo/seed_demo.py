"""Seed a safe enterprise demo dataset.

The command is intentionally defensive: it creates synthetic telemetry only,
does not include real secrets, and never executes response actions.
"""

from __future__ import annotations

import argparse
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any


DEMO_TENANT_ID = "safe-demo-enterprise"
DEMO_OUTPUT = Path("demo") / "safe_demo_dataset.json"


@dataclass(slots=True)
class DemoDataset:
    tenant: dict[str, Any]
    hosts: list[dict[str, Any]]
    incidents: list[dict[str, Any]]
    cases: list[dict[str, Any]]
    attack_timeline: list[dict[str, Any]]
    detections: list[dict[str, Any]]
    response_approvals: list[dict[str, Any]]
    executive_dashboard: dict[str, Any]
    generated_at: str = field(default_factory=lambda: _now())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_demo_dataset() -> DemoDataset:
    hosts = [
        _host("SAFE-WS-14", "windows", 92, "isolated", "Credential access and C2 activity"),
        _host("SAFE-FIN-02", "windows", 78, "needs_approval", "Persistence review required"),
        _host("SAFE-SRV-01", "linux", 42, "suspicious", "Unusual outbound connection"),
        _host("SAFE-MAC-07", "darwin", 8, "protected", "Healthy telemetry"),
    ]
    detections = [
        _detection("det-powershell-enc", hosts[0], "critical", "T1059.001", "Execution"),
        _detection("det-credential-dump", hosts[0], "critical", "T1003", "Credential Access"),
        _detection("det-scheduled-task", hosts[1], "high", "T1053", "Persistence"),
        _detection("det-beaconing", hosts[2], "medium", "T1071", "Command and Control"),
    ]
    timeline = [
        _timeline("Execution", hosts[0], "Encoded PowerShell launched from Office process.", -95),
        _timeline("Credential Access", hosts[0], "Credential dumping indicator observed.", -83),
        _timeline("Command and Control", hosts[0], "Beaconing to suspicious infrastructure.", -71),
        _timeline("Persistence", hosts[1], "Scheduled task persistence attempt detected.", -54),
    ]
    incidents = [
        {
            "incident_id": "inc-demo-001",
            "tenant_id": DEMO_TENANT_ID,
            "title": "Credential access with C2 follow-up",
            "severity": "critical",
            "status": "investigating",
            "host_id": hosts[0]["host_id"],
            "killchain_stage": "command_and_control",
            "mitre_tactic": "Credential Access",
            "recommendation": "Keep host isolated, collect diagnostics, and reset exposed credentials.",
        },
        {
            "incident_id": "inc-demo-002",
            "tenant_id": DEMO_TENANT_ID,
            "title": "Persistence attempt requires approval",
            "severity": "high",
            "status": "triage",
            "host_id": hosts[1]["host_id"],
            "killchain_stage": "persistence",
            "mitre_tactic": "Persistence",
            "recommendation": "Review scheduled task evidence before approving containment.",
        },
    ]
    cases = [
        {
            "case_id": "case-demo-001",
            "tenant_id": DEMO_TENANT_ID,
            "title": "Finance workstation compromise investigation",
            "severity": "critical",
            "status": "investigating",
            "assigned_to": "analyst.demo",
            "related_incidents": ["inc-demo-001"],
            "related_hosts": [hosts[0]["host_id"]],
            "mitre_tactics": ["Execution", "Credential Access", "Command and Control"],
            "attack_story": (
                "A workstation executed encoded PowerShell, showed credential access indicators, "
                "and then initiated beaconing to suspicious infrastructure."
            ),
        }
    ]
    approvals = [
        {
            "approval_id": "apr-demo-001",
            "tenant_id": DEMO_TENANT_ID,
            "host_id": hosts[1]["host_id"],
            "action_type": "collect_diagnostics",
            "status": "pending",
            "requested_by": "analyst.demo",
            "reason": "Collect evidence before containment.",
        }
    ]
    return DemoDataset(
        tenant={"tenant_id": DEMO_TENANT_ID, "name": "SAFE Demo Enterprise", "plan": "enterprise-preview"},
        hosts=hosts,
        incidents=incidents,
        cases=cases,
        attack_timeline=timeline,
        detections=detections,
        response_approvals=approvals,
        executive_dashboard={
            "posture_score": 73,
            "risk_level": "attention_needed",
            "protected_hosts": len(hosts),
            "active_incidents": len(incidents),
            "recommended_action": "Review critical incident inc-demo-001 and approve diagnostics for SAFE-FIN-02.",
        },
    )


def seed_storage(dataset: DemoDataset, *, db_path: str | None = None) -> dict[str, int]:
    """Best-effort seed into existing SQLite-first repositories."""
    counts = {"events": 0, "storage_records": 0}
    try:
        from storage.event_repository import EventRepository

        repo = EventRepository(db_path=db_path, tenant_id=DEMO_TENANT_ID) if db_path else EventRepository(tenant_id=DEMO_TENANT_ID)
        for event in dataset.detections + dataset.attack_timeline:
            if repo.save(_repo_event(event)):
                counts["events"] += 1
    except Exception:
        counts["events"] = 0

    try:
        from storage.storage_adapter import SQLiteStorageAdapter

        adapter = SQLiteStorageAdapter(db_path or "safe_demo_storage.db")
        for event in dataset.detections + dataset.attack_timeline:
            adapter.write_hot_event(DEMO_TENANT_ID, event)
            counts["storage_records"] += 1
        for incident in dataset.incidents:
            adapter.write_incident(DEMO_TENANT_ID, incident)
            counts["storage_records"] += 1
    except Exception:
        counts["storage_records"] = 0
    return counts


def write_dataset(dataset: DemoDataset, path: Path = DEMO_OUTPUT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dataset.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    return path


def _host(name: str, platform: str, risk: int, state: str, next_action: str) -> dict[str, Any]:
    return {
        "host_id": name.lower().replace("-", "_"),
        "hostname": name,
        "tenant_id": DEMO_TENANT_ID,
        "platform": platform,
        "agent_version": "1.0.0",
        "risk_score": risk,
        "protection_state": state,
        "last_seen": _now(offset_minutes=-5),
        "next_action": next_action,
    }


def _detection(rule_id: str, host: dict[str, Any], severity: str, technique: str, tactic: str) -> dict[str, Any]:
    return {
        "event_id": f"evt-{uuid.uuid4().hex[:12]}",
        "tenant_id": DEMO_TENANT_ID,
        "host_id": host["host_id"],
        "hostname": host["hostname"],
        "event_type": "threat_detection",
        "category": "security",
        "severity": severity,
        "confidence": 92 if severity == "critical" else 78,
        "rule_id": rule_id,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "timestamp": _now(offset_minutes=-30),
        "evidence": f"{tactic} signal on {host['hostname']}",
        "raw": {"demo": True},
    }


def _timeline(stage: str, host: dict[str, Any], evidence: str, offset: int) -> dict[str, Any]:
    return {
        "event_id": f"tl-{uuid.uuid4().hex[:12]}",
        "tenant_id": DEMO_TENANT_ID,
        "host_id": host["host_id"],
        "hostname": host["hostname"],
        "event_type": "attack_timeline",
        "category": "security",
        "killchain_stage": stage.lower().replace(" ", "_"),
        "severity": "high",
        "confidence": 86,
        "timestamp": _now(offset_minutes=offset),
        "evidence": evidence,
        "raw": {"demo": True},
    }


def _repo_event(event: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        event_id=event["event_id"],
        tenant_id=event["tenant_id"],
        timestamp=event["timestamp"],
        host_id=event["host_id"],
        event_type=event["event_type"],
        severity=str(event.get("severity", "low")).upper(),
        source="safe-demo",
        rule_id=event.get("rule_id", "safe-demo"),
        rule_name=event.get("mitre_tactic", "Demo Signal"),
        details={"evidence": event.get("evidence"), "demo": True},
        mitre={},
        tags=["demo", "safe"],
        raw=json.dumps(event, sort_keys=True),
        acknowledged=False,
    )


def _now(*, offset_minutes: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat()


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed SAFE enterprise demo data.")
    parser.add_argument("--output", default=str(DEMO_OUTPUT))
    parser.add_argument("--db-path", default=None)
    parser.add_argument("--no-db", action="store_true", help="Only write JSON dataset.")
    args = parser.parse_args()
    dataset = build_demo_dataset()
    output = write_dataset(dataset, Path(args.output))
    counts = {"events": 0, "storage_records": 0} if args.no_db else seed_storage(dataset, db_path=args.db_path)
    print(json.dumps({"ok": True, "dataset": str(output), "tenant_id": DEMO_TENANT_ID, "seeded": counts}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
