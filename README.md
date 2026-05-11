# SAFE

![Release](https://img.shields.io/badge/release-v0.1.0--enterprise--preview-0f172a)
![Tests](https://img.shields.io/badge/tests-1151%20passed-16a34a)
![Pentest Audit](https://img.shields.io/badge/pentest%20audit-37%2F37%20passed-16a34a)

**Enterprise XDR / EDR Platform**

SAFE is an enterprise-style defense platform built from the original IDS codebase. It combines endpoint telemetry, XDR ingestion, deterministic detection, MITRE ATT&CK mapping, Kill Chain context, tenant-aware SOC workflows, incident lifecycle, and guarded response actions in one Python/Flask platform.

SAFE is packaged as an enterprise-preview product for professional demos, portfolio presentation, client-pilot conversations, and future SaaS evolution.

The project keeps the existing technical contracts for compatibility while presenting a cleaner SAFE product identity:

- **SAFE Core:** Flask server, auth, RBAC, multi-tenant routing, audit, and APIs.
- **SAFE Agent:** Windows-first endpoint runtime with service mode, offline buffer, telemetry collection, and guarded response executor.
- **SAFE Console:** admin, SOC, host triage, incidents, live response, and performance views.
- **SAFE Telemetry:** `/api/events`, `/api/agent/events`, and `/api/xdr/events` ingestion paths.
- **SAFE Defense Engine:** detection, correlation, Kill Chain, behavior, risk, and response policy engines.
- **SAFE Orchestration:** response queue, approvals, action signing, and safe rollback-oriented controls.

> Compatibility note: legacy API headers and environment variables such as `X-NetGuard-Agent-Key` and `NETGUARD_*` remain supported so existing agents and tests do not break during the rebrand.

## Architecture

```text
SAFE Agent / External Producers
        |
        v
SAFE Telemetry API
  /api/events
  /api/agent/events
  /api/xdr/events
        |
        v
Operational Reliability Core
  bounded queues -> event bus -> workers
  -> health -> observability -> safe mode
        |
        v
SAFE Defense Engine
  normalize -> detect -> correlate
  -> behavior -> Kill Chain -> risk
        |
        v
Policy + Orchestration
  approvals -> signed actions -> agent executor
        |
        v
Storage + SOC
  SQLite local/demo
  PostgreSQL-ready repositories
  SAFE Console / incidents / exports / audit
```

## Core Capabilities

- **Endpoint telemetry:** process, network, host, memory-safe indicators, file quarantine metadata, heartbeat, and agent liveness.
- **Detection engineering:** built-in XDR detections plus Sigma-like YAML rules in `rules/yaml/`.
- **Threat correlation:** deterministic correlations across process, network, auth, persistence, and repeated alert patterns.
- **Kill Chain and MITRE mapping:** host attack stages, tactic/technique context, progression score, and attack story generation.
- **Risk-based triage:** host score, highest severity, recommended next action, and Operator Inbox prioritization.
- **Incident workflow:** create, list, assign, comment, update severity/status, export JSON/CSV with redaction.
- **Multi-tenant operations:** tenant-scoped storage, host registry, tokens, dashboards, drilldowns, and admin overview.
- **Live response:** safe actions, guarded actions, policy approval, signed response envelopes, and agent-side verification.
- **Scalable ingest foundation:** bounded queues, priority lanes, deduplication, heartbeat state, orchestration, and performance metrics.
- **Enterprise hardening:** HMAC agent trust, nonce replay guard, config validator, API abuse guard, audit integrity, and secrets self-check.
- **AI-assisted SOC:** explainable alert context, false-positive reduction, investigation guidance, incident prioritization, playbook recommendations, and attack progression prediction.
- **SOC operations:** case management, analyst workflows, approval center, hunt operations, immutable evidence, SOC metrics, and executive reporting.
- **Operational reliability:** real-time event bus, tenant-scoped stream hub, bounded queue manager, restart-safe workers, health engine, SAFE Mode, recovery planning, and disaster recovery snapshots.
- **Security data platform:** canonical telemetry, normalization, enrichment, event lineage, detection QA, safe replay, knowledge graph pivots, retention planning, detection packs, and tenant-scoped search.

## AI-Assisted SOC Core

SAFE includes a defensive, deterministic Copilot layer for analyst productivity. It does not execute dangerous actions, does not hide critical detections, and keeps every recommendation explainable.

Core components:

- `xdr/alert_context_engine.py` enriches detections with likely attack stage, objective, business impact, affected assets, and recommended investigation.
- `xdr/fp_reduction_engine.py` reduces SOC fatigue by labeling alerts as likely true positive, suspicious, low confidence, or likely benign while preserving critical alerts.
- `xdr/investigation_assistant.py` turns event context into next steps, containment suggestions, and an evidence checklist.
- `xdr/explainability_engine.py` explains why a detection fired, which engines contributed, and which evidence chain supports it.
- `xdr/prioritization_engine.py` ranks incidents by impact, critical assets, progression, credential access, persistence, lateral movement, and threat intel.
- `xdr/progression_predictor.py` predicts likely next-stage progression and recommends prevention steps.
- `xdr/playbook_engine.py` recommends defensive playbooks without executing them automatically.
- `/soc/copilot` provides the analyst panel for summaries, explanations, false-positive context, playbooks, and guided next steps.

## SAFE Console

Primary workspaces:

- **Overview:** posture, active incidents, critical hosts, security activity, and recommended next action.
- **Operator Inbox:** highest-risk hosts ordered by risk and operational priority.
- **Host Triage:** host profile, attack timeline, risk explanation, related signals, and response actions.
- **Incidents:** status, severity, assignment, comments, and lifecycle updates.
- **Copilot:** explainable investigation summaries, false-positive context, priority, evidence chain, and safe playbook recommendations.
- **Case Management:** case timeline, evidence cards, analyst notes, ownership, containment state, and workflow checklist.
- **Hunt Operations:** active hunts, completed hunts, scheduled IOC/MITRE/rare-behavior hunts, and investigation guidance.
- **Approvals:** pending response approvals, requester, reason, affected hosts, rollback capability, and expiration context.
- **Metrics:** MTTD, MTTR, incident volume, false-positive ratio, containment success, analyst workload, and executive reporting.
- **Detection Packs:** versioned rule packs, staged rollout visibility, canary readiness, tenant tuning and detection QA.
- **Security Search:** tenant-scoped search across hosts, users, IOCs, detections, incidents, telemetry and campaigns.
- **Agents:** host inventory, liveness, enrollment, heartbeat, and key lifecycle.
- **Live Response:** pending security actions, approvals, containment state, MITRE context, and response queue.
- **Performance:** ingest V2 status, queue pressure, dedup ratio, latency, dropped events, and throughput.
- **Observability:** live queue pressure, worker state, streaming clients, health components, and SAFE Mode state.

## Operational Reliability & Real-Time Core

SAFE now includes an enterprise reliability layer designed for continuous SOC/XDR operations without changing the existing synchronous ingest path by default.

Core components:

- `xdr/queue_manager.py` provides bounded priority queues, retry counters, overflow protection, poison-message handling, and dead-letter recovery.
- `xdr/event_bus.py` centralizes tenant-scoped publish/subscribe events for detections, incidents, approvals, host state changes, orchestration, and UI updates.
- `xdr/realtime_stream.py` provides an authenticated, tenant-isolated streaming hub ready for SSE/WebSocket adapters with heartbeat and client rate limiting.
- `workers/` defines restart-safe telemetry, correlation, orchestration, cleanup, metrics, and hunt workers with graceful shutdown and queue metrics.
- `xdr/observability.py`, `xdr/health_engine.py`, `xdr/recovery_engine.py`, `safe_mode/`, and `xdr/disaster_recovery.py` add operational metrics, health evaluation, recovery plans, degraded SAFE Mode, and tenant-safe snapshots.

Admin views:

- `GET /admin/observability`
- `GET /admin/performance-live`

## SAFE Agent

The Windows-first endpoint runtime lives in `agent/` and can run as Python or as `agent.exe`.

```powershell
cd agent
python -m agent --config config.yaml
```

Build standalone Windows binary:

```powershell
cd agent
powershell -ExecutionPolicy Bypass -File .\build_agent.ps1 -Clean -WithService
```

The SAFE Agent supports:

- stable host identity
- API key authentication
- offline buffer and retry backoff
- process and network telemetry
- local audit JSONL for response actions
- guarded process kill
- reversible quarantine
- simulated and controlled isolation flows

## Security Model

SAFE is defensive-only. It does not implement bypass, evasion, malware behavior, credential dumping, stealth persistence, or destructive actions by default.

Security controls include:

- `TOKEN_SIGNING_SECRET` required outside dev/test
- `IDS_AUTH=true` recommended for production
- RBAC roles: `owner`, `admin`, `responder`, `analyst`, `viewer`
- CSRF protection on destructive session-authenticated routes
- tenant-scoped repositories, caches, deduplication, heartbeat, and orchestration
- signed response action envelopes
- HMAC-signed optional Agent Trust V2 requests
- replay protection with timestamp and nonce
- audit log integrity verification
- API abuse protection for ingest surfaces
- redacted incident export

Strict agent request signing can be enabled with:

```bash
NETGUARD_AGENT_TRUST_V2=true
```

## Agent Trust Model

Agent Trust V2 validates:

- tenant id
- host id
- agent id
- timestamp within a 60 second window
- nonce uniqueness
- active registered host
- HMAC signature over the canonical request

The legacy host API key model remains available for compatibility.

## Deployment

Local demo:

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Enterprise demo dataset:

```bash
python demo/seed_demo.py
```

Open:

- `http://127.0.0.1:5000/admin`
- `http://127.0.0.1:5000/soc`
- `http://127.0.0.1:5000/soc/live-response`
- `http://127.0.0.1:5000/admin/performance`
- `http://127.0.0.1:5000/admin/observability`
- `http://127.0.0.1:5000/admin/performance-live`

Release readiness:

```bash
python -m pytest -q
python run_pentest_audit.py
python scripts/release_check.py
python scripts/project_health_report.py
```

Docker development:

```bash
cp .env.example .env
docker compose up --build safe-web redis
```

Production posture:

- use `IDS_AUTH=true`
- configure strong `TOKEN_SIGNING_SECRET` and `SECRET_KEY`
- place the app behind TLS/reverse proxy
- use PostgreSQL for production-scale storage
- keep rate limiting enabled
- enable Agent Trust V2 for enterprise agent flows
- rotate host keys and response signing secrets

## Important APIs

```text
POST /api/events
POST /api/agent/register
POST /api/agent/heartbeat
POST /api/agent/events
POST /api/xdr/events
GET  /api/detection/rules
GET  /api/detection/coverage
GET  /api/host/<tenant_id>/<host_id>/attack-timeline
GET  /api/incidents
GET  /api/incidents/export
GET  /api/soc/live-response
GET  /api/soc/security-data
GET  /api/admin/performance
GET  /api/admin/observability
GET  /api/admin/performance-live
GET  /api/admin/config/status
GET  /api/admin/audit/integrity
```

## Testing

```bash
python run_pentest_audit.py
python -m pytest tests/ -v
```

Current quality gates cover auth, RBAC, CSRF, tenant isolation, agent flows, XDR pipeline, incident lifecycle, YAML rules, response executor safety, replay protection, action signing, API guard, config validator, and secure export.

## Documentation

- [INSTALL.md](INSTALL.md): installation, bootstrap, Docker, demo and troubleshooting
- [CHANGELOG.md](CHANGELOG.md): release history
- [RELEASE_NOTES.md](RELEASE_NOTES.md): v0.1.0 enterprise-preview release notes
- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md): transparent product boundaries
- [docs/PRODUCT_OVERVIEW.md](docs/PRODUCT_OVERVIEW.md): product positioning and capabilities
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): system architecture
- [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md): controls, trust model and hardening checklist
- [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md): professional demo flow
- [docs/ROADMAP.md](docs/ROADMAP.md): evolution plan
- [docs/PORTFOLIO_SUMMARY.md](docs/PORTFOLIO_SUMMARY.md): LinkedIn/resume-ready summary
- [DEPLOY.md](DEPLOY.md): deployment patterns and production checklist
- [SECURITY.md](SECURITY.md): security model and hardening posture
- [NETGUARD_AGENT_SERVER_ARCHITECTURE.md](NETGUARD_AGENT_SERVER_ARCHITECTURE.md): Agent + Server compatibility architecture
- [NETGUARD_XDR_SCALING.md](NETGUARD_XDR_SCALING.md): scalable XDR pipeline and bounded ingestion
- [NETGUARD_ENTERPRISE_HARDENING.md](NETGUARD_ENTERPRISE_HARDENING.md): Agent Trust V2, action signing, replay protection, and audit integrity
- [NETGUARD_EDR_OPERATIONS.md](NETGUARD_EDR_OPERATIONS.md): SOC operations and response workflows
- [SAFE_OPERATIONAL_RELIABILITY.md](SAFE_OPERATIONAL_RELIABILITY.md): real-time event bus, resilient workers, health, SAFE Mode, recovery, and DR
- [SAFE_SECURITY_DATA_PLATFORM.md](SAFE_SECURITY_DATA_PLATFORM.md): canonical telemetry, enrichment, lineage, replay, detection QA, graph and retention

## Roadmap

- [x] SAFE Agent + Server foundation
- [x] Structured XDR telemetry ingest
- [x] Incident lifecycle and SOC workflows
- [x] YAML/Sigma-like rule support
- [x] MITRE and Kill Chain context
- [x] Guarded response queue and SAFE Agent executor
- [x] Scalable XDR platform core
- [x] Enterprise hardening and trust core
- [x] Operational reliability and real-time core
- [x] Security data platform
- [x] Production readiness and release core
- [ ] Client Dashboard Clean Experience with executive and technical modes
- [ ] Full production PostgreSQL migration set for legacy tables
- [ ] Fleet-grade agent rollout, update, and policy management

## License

MIT © Raphael Guterres
