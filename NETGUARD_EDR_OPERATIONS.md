# SAFE EDR Operations

This guide describes the defensive SOC workflow for the SAFE Enterprise
Defense Core. SAFE is a defensive EDR/SOC lab platform. It does not provide
offensive bypass, stealth, credential dumping, malware behavior, or destructive
automation.

## SOC Flow

```text
Endpoint Agent
  -> Event Ingest
  -> Detection Engine
  -> Behavioral Engine
  -> Correlation Engine
  -> Kill Chain Engine
  -> Host Defense Engine
  -> Policy Engine
  -> Response Queue
  -> Agent Executor
  -> Local + Server Audit
```

The intended analyst path is:

```text
Overview -> Operator Inbox -> Host Triage -> Live Response -> Incident -> Resolution
```

## Incident Lifecycle

1. Endpoint telemetry creates detections, behavioral findings, correlations, and
   Kill Chain findings.
2. The Host Defense Engine computes host state and recommended actions.
3. High-risk or late-stage activity creates or recommends an incident.
4. The analyst reviews Host Triage before containment.
5. Status moves through `open`, `in_progress`, `contained`, `resolved`, or
   `false_positive`.

## Approval Workflow

Default mode is `manual_approval`.

Safe telemetry actions may run automatically when policy allows:

- `ping`
- `flush_buffer`
- `collect_diagnostics`

Guarded actions require signed policy and audit:

- `safe_host_isolation`
- `rollback_host_isolation`
- `block_ip_windows_firewall`
- `kill_process_guarded`
- `quarantine_file_guarded`

Disabled by default:

- `delete_file`
- `delete_file_guarded`

## Containment Flow

Host isolation is designed to be reversible and conservative.

1. Analyst validates Host Triage and Kill Chain progression.
2. Policy Engine returns a short-lived decision.
3. Server queues an approved endpoint action.
4. Agent validates tenant, host, action type, nonce, expiry, and signature.
5. Agent applies only SAFE-owned firewall rules.
6. Agent preserves localhost and SAFE server connectivity.
7. Agent writes a local JSONL audit event.

Dry-run remains the safest default for local testing.

## Rollback Flow

Rollback is also policy-signed.

1. Analyst selects rollback for the contained host.
2. Agent validates signed policy.
3. Agent removes only `SAFE Isolation ...` rules.
4. Agent restores a known-safe firewall policy.
5. Agent writes a local audit event.

## Quarantine Flow

Quarantine never permanently deletes files.

1. Agent validates path, SHA256, and signature/origin check.
2. Agent rejects path traversal.
3. Agent rejects files outside allowed roots unless explicit approval exists.
4. File is moved to `C:\ProgramData\SAFE\Quarantine`.
5. Metadata JSON records original path, quarantine path, hash, host, tenant, and
   timestamps.
6. Restore moves the file back after explicit operator action.

## Operational Safety Rules

- No unsigned endpoint action is accepted.
- No protected Windows process is killed.
- No action should expose secrets in UI or audit logs.
- No broad destructive action is automatic.
- Read-only SOC APIs still require auth and RBAC.
- All response paths must be auditable and reversible.
