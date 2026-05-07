# SAFE EDR/XDR Evolution Plan

## Target architecture

```text
SAFE Agent
  -> API ingestion layer
  -> Detection engine
  -> Correlation engine
  -> Response engine
  -> SOC dashboard
```

## Design goals

- Lightweight endpoint agent
- Behavior-first detection
- SaaS-friendly multi-tenant pipeline
- Secure token-based ingestion
- Minimal dependencies
- Backward compatibility with current SAFE dashboard and engines

## Recommended folder structure

```text
agent.py
xdr/
  __init__.py
  severity.py
  schema.py
  detection.py
  correlation.py
  response.py
  pipeline.py
  agent/
    __init__.py
    buffer.py
    client.py
    service.py
engine/
storage/
app.py
```

## Event schema

```json
{
  "host_id": "host_01",
  "event_type": "process_execution",
  "severity": "medium",
  "timestamp": "2026-04-13T12:00:00Z",
  "process_name": "powershell.exe",
  "command_line": "powershell.exe -enc AAAA",
  "username": "alice",
  "source": "agent",
  "platform": "windows",
  "pid": 1337,
  "parent_process": "winword.exe",
  "details": {
    "cpu": 12.5
  }
}
```

Required baseline fields:

- `host_id`
- `event_type`
- `timestamp`
- `source`

Supported phase 1 event types:

- `process_execution`
- `script_execution`
- `authentication`
- `persistence_indicator`
- `network_connection`
- `behavioral_anomaly`

Severity standard:

- `low`
- `medium`
- `high`
- `critical`

## Detection logic examples

Implemented phase 1 rules:

1. Suspicious PowerShell execution
2. Suspicious Bash execution
3. Brute force authentication pattern
4. Persistence mechanism observed
5. Suspicious process tree
6. Suspicious outbound connection
7. Process anomaly compared to host baseline

## Correlation logic examples

Implemented phase 1 concepts:

1. Multiple suspicious script executions in short window
2. Suspicious execution followed by persistence
3. Authentication abuse followed by script activity

## Response engine structure

Response plans are generated first:

- `generate_incident_ticket`
- `tag_host_risk`
- `escalate_alert`
- `kill_process`
- `block_execution_pattern`
- `block_source_ip`

Automatic in phase 1:

- incident ticket
- host risk tag
- alert escalation

Agent-mediated in later phases:

- process kill
- execution block
- source block

## Integration with existing SAFE

Safe migration path:

1. Keep `/api/agent/push` for legacy snapshot ingestion.
2. Add `/api/xdr/events` for structured endpoint telemetry.
3. Persist normalized XDR outputs into the same repository model.
4. Reuse existing risk engine and dashboard widgets where possible.
5. Add host timeline and response views incrementally instead of rewriting the UI.

## Incremental delivery plan

### Phase 1

- stabilize agent structure
- define schema
- normalize severity
- ship structured ingestion
- implement baseline rules
- correlate weak signals

### Phase 2

- response execution through agent
- host risk scoring UI
- host timeline view
- baseline rules pack expansion

### Phase 3

- threat intelligence adapters
- lateral movement detection enrichment
- anomaly tuning and policy controls
- tenant-aware response policies

## SaaS readiness notes

- keep ingestion stateless at API boundary
- keep event schema tenant-ready
- use token auth per tenant or endpoint
- persist structured events in repository-compatible format
- avoid heavy dependencies in agent and backend
- keep response actions auditable and policy-driven

## Enterprise Protection Layer

SAFE now adds a defensive protection layer between XDR analytics and
endpoint action execution. The design is intentionally conservative: detections
and correlations can recommend containment, but endpoint actions are gated by a
policy decision, a short-lived HMAC approval, local safety checks, and audit
events.

```text
Agent
  -> Event Ingest
  -> Detection
  -> Correlation
  -> Kill Chain
  -> Policy Engine
  -> Response Queue
  -> Agent Executor
  -> Audit Log
```

Core modules:

- `xdr/killchain_engine.py`: maps events, detections, and correlations into MITRE-style Kill Chain findings.
- `xdr/attack_timeline.py`: builds a host-level attack story with active stages, highest stage, progression score, and recommended next action.
- `xdr/policy_engine.py`: decides whether response actions are automatic, approval-gated, or blocked.
- `agent/response_executor.py`: executes only signed defensive actions and refuses unsafe actions fail-closed.
- `/api/detection/coverage`: exposes MITRE tactic, technique, and Kill Chain coverage for SOC operators.

Safety model:

- `monitor_only` never performs containment.
- `manual_approval` is the default operating posture for guarded response.
- `semi_auto` can allow high-confidence IP blocking when evidence is complete.
- `full_auto_containment` is explicit and still requires evidence, signatures, and local denylist checks.
- `delete_file` remains disabled; file quarantine moves evidence and preserves audit history.
