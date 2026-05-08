# SAFE SOC Operations & Case Management

SAFE SOC Operations & Case Management turns the platform into an operational SOC workspace with case lifecycle, workflows, hunt operations, approval review, evidence handling, metrics, and executive reporting.

The implementation is defensive, audit-oriented, tenant-scoped, and approval-gated for critical response concepts.

## Incident Lifecycle

SAFE cases use the following lifecycle:

- `new`
- `triage`
- `investigating`
- `contained`
- `monitoring`
- `resolved`
- `closed`

Each case includes:

- case id
- tenant id
- title
- severity
- status
- assignment
- related incidents
- related hosts
- related IOCs
- MITRE tactics
- attack story
- evidence
- notes
- timeline
- containment status
- resolution summary

Module:

```text
xdr/case_management.py
```

## Analyst Workflows

Module:

```text
xdr/workflow_engine.py
```

Supported workflows:

- triage
- ransomware
- credential access
- persistence
- beaconing
- insider threat

Each workflow provides:

- checklist
- evidence requirements
- recommended actions
- escalation rules
- rollback guidance

## Playbooks

Module:

```text
xdr/playbook_executor.py
```

Supported defensive playbooks:

- isolate host
- collect diagnostics
- IOC hunt
- suspend user
- force password reset recommendation
- persistence review
- network containment recommendation

Critical actions require approval. Simulation mode is enabled by default.

## Case Timeline Experience

Route:

```text
/soc/case/<case_id>
```

The page shows:

- investigation timeline
- evidence cards
- analyst notes
- host and incident links
- containment status
- workflow checklist

## IOC Management

Module:

```text
xdr/ioc_manager.py
```

Supported IOC types:

- IP
- hash
- domain
- URL
- filename

Records include confidence, source, first seen, last seen, expiration, linked cases, and linked hosts.

## Hunt Operations

Route:

```text
/soc/hunts
```

The Hunt Operations Center shows:

- active hunts
- completed hunts
- scheduled hunts
- IOC hunts
- MITRE hunts
- rare behavior hunts

## Analyst Collaboration

SAFE supports case-level collaboration primitives:

- analyst notes
- evidence pinning
- escalation comments
- investigation ownership
- activity feed
- case watchers

## Response Approval Center

Route:

```text
/soc/approvals
```

The page shows:

- pending approvals
- requester
- reason
- affected hosts
- rollback capability
- expiration context

Approve/reject/request-investigation/defer controls are displayed as workflow placeholders unless connected to a CSRF/RBAC-protected action endpoint.

## Evidence Management

Module:

```text
xdr/evidence_store.py
```

Evidence records are append-only and include:

- process evidence
- telemetry evidence
- correlation evidence
- screenshot metadata
- response logs
- investigation notes

Controls:

- tenant isolation
- integrity hash
- hash-chain verification
- immutable evidence records
- redaction of sensitive keys

## SOAR-Like Orchestration

Module:

```text
xdr/orchestration_engine.py
```

The orchestration layer supports:

- chained playbooks
- conditional workflows
- staged containment
- rollback chains
- escalation routing
- analyst confirmation checkpoints

## SOC Metrics

Route:

```text
/soc/metrics
```

Module:

```text
xdr/soc_metrics.py
```

Metrics:

- MTTD
- MTTR
- incident volume
- false-positive ratio
- containment success
- analyst workload
- unresolved criticals

## Executive Reporting

Module:

```text
xdr/reporting_engine.py
```

The reporting structure includes:

- executive summary
- incident trends
- top attack types
- posture evolution
- critical incidents
- response effectiveness
- JSON output
- CSV output
- PDF-ready structure

## Validation

Run:

```powershell
python run_pentest_audit.py
python -m pytest tests\test_case_management.py tests\test_workflow_engine.py tests\test_playbook_executor.py tests\test_ioc_manager.py tests\test_evidence_store.py tests\test_soc_metrics.py -q
python -m pytest tests\ -q
```
