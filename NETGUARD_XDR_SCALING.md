# NetGuard XDR Scaling Architecture

This document describes the Scalable XDR Platform Core added to NetGuard. The
goal is to let the platform handle multiple endpoints, noisy telemetry, and SOC
response workflows without unbounded queues or cross-tenant data leakage.

## Flow

```text
Agent Fleet
    |
    v
Telemetry Queues
    |
    v
Priority Engine
    |
    v
Deduplication + Backpressure
    |
    v
Detection / Correlation / Kill Chain
    |
    v
Response Orchestration
    |
    v
SOC Dashboard + Audit Trail
```

## Core Modules

| Module | Purpose |
|---|---|
| `xdr/ingestion_pipeline.py` | Bounded in-process queues, async consumers, batching, backpressure, queue metrics |
| `xdr/priority_engine.py` | P0-P3 telemetry classification so critical events outrank noisy debug telemetry |
| `xdr/dedup_engine.py` | Tenant-scoped rolling TTL fingerprints for repeated process/auth/network/alert floods |
| `xdr/performance_metrics.py` | Events/sec, queue latency, ingestion latency, detection latency, dropped events, dedup ratio, memory snapshot |
| `xdr/heartbeat_engine.py` | Host liveness and freshness state: healthy, degraded, delayed, offline, isolated |
| `xdr/orchestration_engine.py` | Staged multi-host response, approval chaining, retries, timeouts, rollback |
| `xdr/correlation_engine.py` | Incident correlation V2 for temporal progression, multi-host campaigns, and repeated attacker infrastructure |
| `storage/storage_adapter.py` | SQLite local backend and PostgreSQL-ready adapter for hot events, incidents, audit logs, and telemetry history |

## Priority Model

```text
P0 critical
  credential access, ransomware/impact, privilege escalation

P1 security
  persistence, suspicious PowerShell, beaconing, LOLBIN abuse

P2 telemetry
  behavioral anomalies and medium-risk signals

P3 debug
  low-risk operational telemetry
```

The bounded queue always drains in priority order. Low-risk lanes are allowed to
drop under pressure; high-risk signals are preserved as long as their own lane
has capacity.

## Feature Flag Rollout

The current `/api/xdr/events` path stays synchronous unless explicitly changed.
This preserves existing demos, tests, and integrations that expect inline
detection records.

Enable the V2 queue path with:

```text
NETGUARD_XDR_INGEST_V2=true
NETGUARD_XDR_QUEUE_MAX=5000
NETGUARD_XDR_BATCH_SIZE=100
NETGUARD_XDR_CONSUMERS=1
```

When enabled, `/api/xdr/events` validates the request, enforces tenant scope,
queues accepted telemetry, and returns `202 Accepted` with queue metadata. If the
bounded queue cannot accept any event, the endpoint returns `429` instead of
growing memory unbounded.

`NETGUARD_XDR_INGEST_V2_DRAIN_INLINE=true` exists only for tests and controlled
single-process validation. Production should normally leave it disabled so
worker threads perform the queued processing.

## Deduplication

Deduplication is intentionally tenant-scoped. A noisy event from `tenant-a`
cannot suppress an identical event from `tenant-b`.

Fingerprints ignore volatile event ids and focus on stable attributes:

- process execution: tenant, host, process, parent, command line, user
- authentication: tenant, host, result, source IP, user
- network: tenant, host, process, destination IP/port, direction
- alerts: tenant, host, rule id, alert type, severity, summary

## Storage Separation

The storage adapter separates data by operational temperature:

| Table | Retention default | Use |
|---|---:|---|
| `hot_events` | 14 days | Active SOC investigation and recent dashboard queries |
| `telemetry_history` | 30 days | Broader endpoint telemetry history |
| `incidents` | 365 days | Incident lifecycle and reporting |
| `audit_logs` | 365 days | Administrative and response traceability |

All read APIs require explicit `tenant_id`. There is no wildcard tenant query in
the adapter API.

## Performance Dashboard

Admins can inspect runtime metrics at:

```text
GET /admin/performance
GET /api/admin/performance
```

The dashboard exposes queue depth, events/sec, latency, dropped events, dedup
ratio, and tenant-safe counters. It does not expose secrets, raw tokens, host
keys, or `.env` values.

## Rollout Guidance

1. Keep `/api/xdr/events` synchronous for local/demo mode.
2. Enable the bounded ingestion pipeline for high-volume deployments after
   validating queue sizes and batch sizes against the target host count.
3. Keep SQLite for demo/local deployments and move hot event storage to
   PostgreSQL for production multi-tenant deployments.
4. Monitor `/admin/performance` during agent rollout. Watch dropped events,
   latency, dedup ratio, and queue depth.
5. Use response orchestration in `manual_approval` or `semi_auto` first. Do not
   enable full containment automation until SOC approval and rollback workflows
   are tested.

## Defensive Boundaries

The scalable core is defensive infrastructure only:

- no bypass logic
- no evasion logic
- no credential dumping
- no destructive action without approval
- no cross-tenant telemetry mixing
- no unbounded queues
- no hardcoded secrets

Failures are designed to be visible and fail closed through rejected events,
dropped low-priority telemetry, explicit metrics, and audit records.
