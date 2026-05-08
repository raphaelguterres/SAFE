# SAFE Operational Reliability & Real-Time Core

This phase prepares SAFE for continuous SOC/XDR operations across multiple tenants, endpoints and analysts while keeping the current synchronous ingest path compatible.

SAFE remains defensive-only, fail-closed and tenant-scoped. The reliability core is intentionally dependency-light so local SQLite/demo deployments keep working, while the module boundaries are ready for Redis, Kafka, PostgreSQL and WebSocket adapters later.

## Architecture

```text
Agent Fleet
  |
  v
Ingestion
  |
  v
Event Bus
  |
  v
Workers
  |
  v
Detection / Correlation
  |
  v
Orchestration
  |
  v
Streaming Layer
  |
  v
SOC Console
```

## Components

- `xdr/queue_manager.py`: bounded priority queues, tenant accounting, retry counters, dead-letter queues, poison-message handling and overflow protection.
- `xdr/event_bus.py`: internal tenant-scoped publish/subscribe fabric for security events, orchestration events, UI updates and metrics signals.
- `xdr/realtime_stream.py`: authenticated stream hub for future WebSocket/SSE adapters with host-specific, incident-specific and tenant-scoped channels.
- `workers/`: restart-safe worker abstractions for telemetry, correlation, orchestration, cleanup, metrics and hunts.
- `xdr/observability.py`: in-memory operational metrics for worker latency, ingestion latency, websocket latency, queue pressure, dropped events, retries and orchestration failures.
- `xdr/health_engine.py`: health scoring for database, queues, streaming, workers, ingestion, orchestration and host heartbeat freshness.
- `xdr/recovery_engine.py`: queue recovery, worker restart planning, expired approval cleanup, failed containment recovery and orchestration rollback planning.
- `safe_mode/`: degraded-mode controller that prioritizes P0/P1 detections, critical incidents and essential telemetry when the system is overloaded.
- `xdr/disaster_recovery.py`: tenant-safe snapshots for incidents, audit logs and queue state with redaction and integrity verification.

## Real-Time Event Streaming

The current implementation is transport-agnostic. `RealtimeStreamHub` manages:

- authenticated client sessions
- tenant isolation
- channel subscriptions
- host-specific channels
- incident channels
- heartbeat freshness
- per-client rate limiting
- bounded backlogs through the event bus

This can be exposed through SSE or WebSocket later without changing the publish/subscribe model.

## Queue Reliability

The queue manager is bounded by design:

- no infinite queues
- per-tenant queue limits
- strict payload size checks
- P0/P1 priority lanes
- low-priority shedding under pressure
- dead-letter queue for failed, poison or overflowed messages
- retry budget per message

This prevents memory explosions during telemetry floods and keeps critical security signals flowing first.

## SAFE Mode

SAFE Mode activates when the system becomes unstable, critical or overloaded.

When active, SAFE prioritizes:

- P0 detections
- P1 detections
- critical incidents
- response queue state
- essential telemetry

SAFE reduces or suppresses:

- debug telemetry
- heavy hunts
- secondary analytics
- low-priority exports

SAFE Mode never disables audit, RBAC, tenant isolation or critical detection flow.

## Observability

Admin views:

- `/admin/observability`
- `/admin/performance-live`

Admin APIs:

- `/api/admin/observability`
- `/api/admin/performance-live`

Tracked signals:

- events per second
- active workers
- failed workers
- queue pressure
- dead letters
- dropped events
- streaming clients
- worker latency
- ingestion latency
- websocket latency
- replay/retry counts
- orchestration failures
- SAFE Mode state

## Recovery

Recovery primitives are explicit and audit-friendly:

- requeue dead-letter messages with tenant scope
- restart failed/degraded workers
- expire stale approvals
- expire stale response actions
- plan rollback for failed containment
- plan rollback for chained orchestration

Destructive recovery is not automatic. The engine returns plans and safe actions that higher-level approval workflows can execute.

## Disaster Recovery

`DisasterRecoveryManager` exports redacted snapshots with integrity hashes.

Snapshot contents:

- tenant id
- incident backup
- audit backup
- queue state
- metadata
- integrity hash

Restore plans are tenant-safe:

- snapshot integrity must validate
- target tenant must match snapshot tenant
- secrets are redacted
- restore is described as a plan, not executed implicitly

## Production Scaling Path

The current implementation is local-process for compatibility. The next production path is:

- replace in-memory queues with Redis Streams or Kafka topics
- store event bus offsets in PostgreSQL/Redis
- expose `RealtimeStreamHub` through authenticated WebSocket/SSE endpoints
- persist dead-letter queue state
- move workers to supervised service processes
- add PostgreSQL partitioning for timelines and incident history
- add retention/archival workers for audit and telemetry history

## Testing

Focused tests:

```bash
python -m pytest tests/test_queue_manager.py tests/test_event_bus.py tests/test_realtime_stream.py tests/test_worker_recovery.py tests/test_health_engine.py tests/test_safe_mode.py tests/test_disaster_recovery.py tests/test_observability.py -v
```

Full gates:

```bash
python run_pentest_audit.py
python -m pytest tests/ -v
```
