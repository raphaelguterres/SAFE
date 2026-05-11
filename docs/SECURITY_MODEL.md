# SAFE Security Model

SAFE is defensive-only and fail-closed by design.

## Controls

- Strong token signing secret outside dev/test.
- Optional Agent Trust V2 HMAC signing with timestamp and nonce.
- Replay protection with tenant and agent scope.
- RBAC roles: owner, admin, responder, analyst, viewer.
- CSRF protection on destructive session-authenticated routes.
- Tenant-scoped repositories and caches.
- Signed response action envelopes.
- Policy engine for response approvals.
- Audit log integrity verification.
- Redacted exports and secret scanning.

## Response Safety

SAFE does not execute destructive actions by default. Isolation, process kill,
block IP, and quarantine flows require policy decisions, approval, audit, and
rollback capability where applicable.

## Production Checklist

- Set `IDS_AUTH=true`.
- Set strong `TOKEN_SIGNING_SECRET` and `SECRET_KEY`.
- Keep `IDS_CSRF_DISABLED=false`.
- Enable HTTPS and secure cookies.
- Use PostgreSQL for production-like deployments.
- Keep rate limits enabled.
- Rotate host keys and response signing secrets.
- Run `python scripts/release_check.py` before release.
