# SAFE API Reference

SAFE exposes telemetry, agent lifecycle, incident, detection, and admin APIs for the enterprise-preview pilot path.

The canonical OpenAPI file is `openapi/safe-api.yaml`. When the Flask app is running, the same spec is available at:

- `GET /api/openapi.yaml`
- `GET /api/openapi.json`

Authentication headers:

- Prefer `X-SAFE-Agent-Key` for SAFE Agent telemetry.
- `X-NetGuard-Agent-Key` remains accepted for legacy NetGuard compatibility.
- Admin and operator APIs use the existing bearer/session controls.

Documented endpoints include:

- `POST /api/events`
- `POST /api/agent/register`
- `POST /api/agent/heartbeat`
- `POST /api/agent/events`
- `POST /api/xdr/events`
- `GET /api/incidents`
- `GET /api/incidents/export`
- `GET /api/detection/rules`
- `GET /api/detection/coverage`
- `GET /api/admin/performance`
- `GET /api/admin/observability`
- `GET /api/admin/config/status`
- `GET /api/admin/audit/integrity`

Common errors are documented as `400`, `401`, `403`, `429`, and `500` responses in the OpenAPI components.
