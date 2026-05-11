# SAFE Security Data Platform

SAFE now includes a security data layer for normalized telemetry, enrichment, lineage, detection QA, replay, graph pivots and retention planning.

The implementation is defensive, audit-friendly and tenant-scoped. It does not execute payloads, run offensive automation or hide critical detections.

## Architecture

```text
Raw telemetry
  |
  v
Telemetry Normalization
  |
  v
CanonicalEvent
  |
  v
Enrichment Pipeline
  |
  v
Detection / Correlation / QA
  |
  v
Lineage + Replay
  |
  v
Knowledge Graph + Search
  |
  v
SOC workflows
```

## Canonical Telemetry

`schema/canonical_event.py` defines `CanonicalEvent` with:

- event id
- tenant id
- host id
- user id
- event type
- category
- timestamp
- process context
- network context
- auth context
- telemetry source
- severity
- raw event reference
- normalized fields
- enrichment
- lineage reference
- confidence

The raw event is not discarded. SAFE stores a redacted hash reference for lineage, replay and debugging.

## Normalization

`xdr/normalization_engine.py` normalizes:

- process telemetry
- authentication telemetry
- network telemetry
- registry-style telemetry
- PowerShell telemetry
- persistence telemetry

Malformed events fail closed with normalization issues instead of crashing the pipeline.

## Enrichment

`xdr/enrichment_pipeline.py` enriches canonical events with offline-safe context:

- private/public IP scope
- deterministic geo placeholder
- ASN placeholder
- domain context
- MITRE context from detections/correlations
- asset context
- identity context
- campaign linkage
- threat intel matches
- process signer trust
- anomaly metadata

External APIs are not required for local operation.

## Event Lineage

`xdr/event_lineage.py` records:

- source event
- enrichments applied
- detections triggered
- correlations generated
- playbooks related
- incidents linked

Lineage supports explainability, replay, debugging and auditability.

## Detection Ecosystem

`detections/packs.py` introduces detection pack management:

- pack metadata
- version visibility
- enable/disable state
- staged rollout
- canary rollout
- tenant-specific tuning
- rollback metadata

`xdr/detection_qa.py` validates:

- noisy detections
- missing MITRE tags
- invalid rules
- duplicate rule ids
- overlapping signatures
- low-confidence rules

## Replay

`xdr/replay_engine.py` reprocesses historical events defensively.

Supported use cases:

- validate new rules
- validate tuning
- estimate false-positive pressure
- test correlations
- reproduce campaign timelines

Replay never executes payloads.

## Knowledge Graph

`xdr/security_graph.py` adds a tenant-safe graph with:

- event lineage
- campaign linkage
- asset relationships
- identity relationships
- detection relationships
- process ancestry
- infrastructure reuse
- MITRE tactic relationships

## Retention Model

`xdr/retention_engine.py` creates retention plans for:

- hot telemetry
- warm telemetry
- archived telemetry
- audit records
- evidence
- incidents

The engine produces plans only. Storage deletion/purge should remain an explicit administrative workflow.

## SOC Views

New pages:

- `/soc/detection-packs`
- `/soc/search`

New API:

- `/api/soc/security-data`

These views show detection content health, canonical telemetry samples, lineage preview, graph pivots, retention summary and tenant-scoped search.

## Testing

Focused tests:

```bash
python -m pytest tests/test_canonical_event.py tests/test_normalization_engine.py tests/test_enrichment_pipeline.py tests/test_event_lineage.py tests/test_detection_qa.py tests/test_replay_engine.py tests/test_security_graph_retention_search.py tests/test_security_data_platform_pages.py -v
```

Full gates:

```bash
python run_pentest_audit.py
python -m pytest tests/ -v
```
