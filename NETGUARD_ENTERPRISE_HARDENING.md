# NetGuard Enterprise Hardening & Trust Core

This phase strengthens NetGuard for enterprise-like EDR/XDR operation. The
focus is trust, tenant isolation, auditability, replay resistance, and safe
production readiness. It is defensive only: no bypass, no evasion, no malware
behavior, and no destructive endpoint action without explicit policy approval.

## Agent Trust Model V2

Agent Trust V2 adds request signing on top of enrolled host keys.

Required request fields:

- `X-NetGuard-Agent-ID`
- `X-NetGuard-Tenant-ID`
- `X-NetGuard-Host-ID`
- `X-NetGuard-Timestamp`
- `X-NetGuard-Nonce`
- `X-NetGuard-Signature`

The signature is HMAC-SHA256 over a canonical request message:

```text
netguard-agent-trust-v2
METHOD
PATH
tenant_id
agent_id
host_id
timestamp
nonce
sha256(body)
```

Server validation is fail-closed:

- tenant scope must match the authenticated host key
- host id must match the registered host
- timestamp must be inside a 60 second window
- nonce must not have been used before for the same tenant and agent
- host must exist and not be revoked
- HMAC signature must match the stored host key

Enable strict validation with:

```bash
NETGUARD_AGENT_TRUST_V2=true
```

## Nonce And Replay Protection

`server/replay_guard.py` implements a bounded TTL cache keyed by
`tenant_id + agent_id + nonce`. A repeated nonce is rejected and can be audited
as suspicious agent behavior. The cache is bounded to avoid unbounded memory
growth during telemetry floods.

## Tenant Isolation

Tenant scope helpers live in `security/tenant_scope.py` for static checks and
future migration into a package-safe security module.

Principles:

- tenant id is mandatory on multi-tenant data paths
- wildcard tenant scope is forbidden in tenant flows
- cache keys include tenant id
- storage queries are tenant-filtered
- deduplication and heartbeat state are tenant-scoped
- exports filter by tenant before redaction and serialization

## Audit Log Integrity

`xdr/audit_integrity.py` supports hash-chain canonicalization for audit events.
It can verify chained audit records and can compute a virtual chain over legacy
JSONL audit files.

Admin endpoint:

```text
GET /api/admin/audit/integrity
```

Response includes:

- `valid`
- `checked_records`
- `first_broken_record`
- `last_hash`

## Response Action Signing V2

`xdr/action_signing.py` signs server-to-agent response actions. The signed
envelope includes:

- `action_id`
- `tenant_id`
- `host_id`
- `action_type`
- `parameters_hash`
- `issued_at`
- `expires_at`
- `policy_mode`
- `approval_id`
- `signature`

The agent refuses actions when:

- the envelope is expired
- tenant or host scope does not match
- action type was changed
- parameters were modified
- signature verification fails

The signature envelope may travel inside the action payload as `policy_v2`.
That envelope is excluded from the signed parameter hash so the payload remains
self-contained without invalidating itself.

## RBAC Approval Workflow

Enterprise roles:

- `owner`
- `admin`
- `responder`
- `analyst`
- `viewer`

Approval rules:

- `viewer`: no response approval
- `analyst`: may create investigations
- `responder`: may approve safe diagnostics and IP blocking
- `admin`: may approve host isolation, guarded process kill, and quarantine
- `owner`: may alter policy mode and approve all response types

Permanent delete remains disabled by policy defaults.

## Secrets Hygiene

Run the local self-check:

```bash
python scripts/security_self_check.py
```

The check validates:

- `.env` is not intended for commit
- docs do not contain obvious live token material
- response HMAC secret is configured for production
- debug mode is off in production
- sensitive files are not world-readable on POSIX systems

## Production Config Validator

Admin endpoint:

```text
GET /api/admin/config/status
```

It returns safe status only and never prints secrets. It validates:

- strong `SECRET_KEY`
- `IDS_AUTH=true` in production
- CSRF posture
- cookie `SameSite`
- secure cookies when HTTPS is expected
- rate-limit posture
- bounded ingest V2 configuration
- storage backend suitability

## API Abuse Controls

`server/api_guard.py` protects ingest surfaces with:

- payload size limits
- batch size limits
- event type whitelist
- tenant-scoped rate limits
- agent-scoped rate limits
- backoff recommendation

Applied to:

- `POST /api/events`
- `POST /api/xdr/events`
- `POST /api/agent/events`
- `POST /api/agent/heartbeat`
- `POST /api/admin/ingest-v2/control`

## Secure Incident Export

Endpoint:

```text
GET /api/incidents/export?format=json|csv
```

Export rules:

- RBAC required
- tenant scope required
- record limit enforced
- secret-like fields redacted
- audit event emitted
- no cross-tenant serialization

## Operational Checklist

- Set `TOKEN_SIGNING_SECRET` and `SECRET_KEY` to strong random values.
- Set `IDS_AUTH=true` outside local dev.
- Enable HTTPS and secure cookies in production.
- Keep `NETGUARD_AGENT_TRUST_V2=true` for enterprise agent flows.
- Configure `NETGUARD_RESPONSE_POLICY_SECRET` and optionally `NETGUARD_RESPONSE_ACTION_SECRET`.
- Keep guarded endpoint actions in manual approval unless a tested policy mode is intentionally enabled.
- Run `python run_pentest_audit.py` and `pytest tests/ -v` before deployment.
