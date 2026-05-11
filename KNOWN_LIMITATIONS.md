# Known Limitations

SAFE is an enterprise-preview platform. It is intentionally transparent about
its maturity and boundaries.

- Endpoint telemetry is user-mode and not driver-level.
- SAFE does not replace commercial EDR products.
- Threat intelligence can run offline-safe and may use mock/contextual data.
- SQLite is suitable for demo/local use; PostgreSQL is recommended for scale.
- Redis-backed queueing is prepared but not mandatory in local mode.
- Destructive actions are blocked by design unless explicitly approved.
- Agent isolation is guarded and rollback-oriented, not stealthy.
- Detection packs are local and version-aware, not yet a marketplace.
- The UI is demo/pilot ready, but screenshots should be refreshed for public launches.
- CI gates validate release posture, but production hosting still requires infrastructure hardening.
