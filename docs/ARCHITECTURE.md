# SAFE Architecture

```text
SAFE Agent / External Producers
        |
        v
Telemetry APIs
  /api/events
  /api/agent/events
  /api/xdr/events
        |
        v
Canonical Data Platform
  normalization -> enrichment -> lineage -> replay
        |
        v
Defense Engines
  detection -> correlation -> behavior -> Kill Chain -> risk
        |
        v
Policy + Orchestration
  approval -> signed action -> guarded agent executor -> audit
        |
        v
SOC Console
  overview -> inbox -> host triage -> case -> response center
```

## Storage

SAFE defaults to SQLite for local and demo usage. PostgreSQL is recommended for
production-like multi-tenant scale. The storage adapter separates hot events,
telemetry history, audit logs, and incidents.

## Multi-Tenant Model

Tenant identity is carried through tokens, host registration, repository calls,
search, queues, deduplication, heartbeat, orchestration, and audit records.
Tenant scope is a hard requirement for enterprise flows.

## Reliability Model

The operational core includes bounded queues, priority handling, worker health,
dead-letter recovery, observability metrics, SAFE Mode, and disaster recovery
snapshot preparation.
