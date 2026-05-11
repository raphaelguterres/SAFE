# SAFE v0.1.0-enterprise-preview

SAFE v0.1.0-enterprise-preview packages the project as a professional,
demonstrable enterprise security platform.

## Highlights

- Enterprise SOC/XDR/EDR-lite architecture.
- SAFE Agent and central Flask console.
- Canonical security data platform.
- Detection, correlation, MITRE, Kill Chain, risk, and response policy layers.
- Case management and SOC operations workflows.
- AI-assisted analyst context and explainable recommendations.
- Release quality gate and project health reporting.
- Demo dataset and installation guide.

## Security Posture

SAFE is defensive-only. Destructive actions are blocked by design unless policy,
approval, signature, audit, and rollback requirements are satisfied.

## Validation

Expected release gates:

- `python -m pytest -q`
- `python run_pentest_audit.py`
- `python scripts/release_check.py`

## Known Limitations

See `KNOWN_LIMITATIONS.md`.
