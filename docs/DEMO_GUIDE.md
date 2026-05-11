# SAFE Demo Guide

## Goal

Show SAFE as a polished enterprise security platform without depending on real
customer telemetry or secrets.

## Prepare Demo

```powershell
python demo\seed_demo.py
python app.py
```

Open:

- `/login`
- `/admin`
- `/soc`
- `/soc/search`
- `/soc/detection-packs`
- `/soc/copilot`
- `/soc/approvals`
- `/executive`

## Demo Flow

1. Start with Executive View to explain environment posture.
2. Open SOC Overview to show live operations.
3. Move to Operator Inbox or critical host triage.
4. Explain Kill Chain and MITRE context.
5. Show Case Management and approvals.
6. Open Security Search and Detection Packs.
7. Close with Release Quality Gates and docs.

## Safe Messaging

Use language such as:

- "EDR/XDR-like enterprise lab platform."
- "Defensive telemetry and SOC workflows."
- "Guarded response with explicit approval."
- "Designed for learning, demos, pilots, and future SaaS evolution."

Avoid claims that SAFE replaces commercial EDR products.
