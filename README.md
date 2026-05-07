# SAFE

**Enterprise XDR / EDR Platform**

SAFE is an enterprise-style defense platform built from the original IDS codebase. It combines endpoint telemetry, XDR ingestion, deterministic detection, MITRE ATT&CK mapping, Kill Chain context, tenant-aware SOC workflows, incident lifecycle, and guarded response actions in one Python/Flask platform.

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

## SAFE Console

Primary workspaces:

- **Overview:** posture, active incidents, critical hosts, security activity, and recommended next action.
- **Operator Inbox:** highest-risk hosts ordered by risk and operational priority.
- **Host Triage:** host profile, attack timeline, risk explanation, related signals, and response actions.
- **Incidents:** status, severity, assignment, comments, and lifecycle updates.
- **Agents:** host inventory, liveness, enrollment, heartbeat, and key lifecycle.
- **Live Response:** pending security actions, approvals, containment state, MITRE context, and response queue.
- **Performance:** ingest V2 status, queue pressure, dedup ratio, latency, dropped events, and throughput.

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

Open:

- `http://127.0.0.1:5000/admin`
- `http://127.0.0.1:5000/soc`
- `http://127.0.0.1:5000/soc/live-response`
- `http://127.0.0.1:5000/admin/performance`

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
GET  /api/admin/performance
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

- [DEPLOY.md](DEPLOY.md): deployment patterns and production checklist
- [SECURITY.md](SECURITY.md): security model and hardening posture
- [NETGUARD_AGENT_SERVER_ARCHITECTURE.md](NETGUARD_AGENT_SERVER_ARCHITECTURE.md): Agent + Server compatibility architecture
- [NETGUARD_XDR_SCALING.md](NETGUARD_XDR_SCALING.md): scalable XDR pipeline and bounded ingestion
- [NETGUARD_ENTERPRISE_HARDENING.md](NETGUARD_ENTERPRISE_HARDENING.md): Agent Trust V2, action signing, replay protection, and audit integrity
- [NETGUARD_EDR_OPERATIONS.md](NETGUARD_EDR_OPERATIONS.md): SOC operations and response workflows

## Roadmap

- [x] SAFE Agent + Server foundation
- [x] Structured XDR telemetry ingest
- [x] Incident lifecycle and SOC workflows
- [x] YAML/Sigma-like rule support
- [x] MITRE and Kill Chain context
- [x] Guarded response queue and SAFE Agent executor
- [x] Scalable XDR platform core
- [x] Enterprise hardening and trust core
- [ ] Client Dashboard Clean Experience with executive and technical modes
- [ ] Full production PostgreSQL migration set for legacy tables
- [ ] Fleet-grade agent rollout, update, and policy management

## License

MIT © Raphael Guterres
