# SAFE AI-Assisted SOC Core

SAFE AI-Assisted SOC Core adds deterministic, explainable analyst assistance to the SAFE Enterprise Defense Platform. It is designed for defensive security operations, alert triage, incident prioritization, and investigation acceleration.

This layer does not execute dangerous actions automatically, does not hide critical detections, and does not create offensive agent behavior. It assists human analysts with context and keeps recommendations auditable.

## Goals

- Contextualize alerts with attack stage, objective, impact, confidence, and affected assets.
- Reduce false-positive fatigue without suppressing critical or high-consequence detections.
- Explain why detections were generated and which evidence contributed.
- Prioritize incidents using business impact, critical assets, progression, persistence, lateral movement, credential access, and threat intelligence.
- Predict likely next attack stage to help analysts prevent escalation.
- Recommend defensive playbooks while keeping containment approval-gated.

## Architecture

```text
SAFE Telemetry
    |
    v
Detections + Correlations + Kill Chain
    |
    v
AI-Assisted SOC Core
    alert context
    false-positive reduction
    explainability
    investigation assistant
    prioritization
    progression prediction
    playbook recommendation
    |
    v
SAFE Copilot (/soc/copilot)
    analyst guidance
    evidence chain
    recommended next steps
    approval-gated response suggestions
```

## Modules

### Alert Context Engine

`xdr/alert_context_engine.py`

Builds alert context:

- alert summary
- likely attack stage
- likely objective
- confidence
- business impact
- affected assets
- recommended investigation
- recommended response
- false-positive probability

### False Positive Reduction Engine

`xdr/fp_reduction_engine.py`

Classifies alerts as:

- `likely_true_positive`
- `suspicious`
- `low_confidence`
- `likely_benign`

Critical detections, ransomware indicators, and credential-access indicators are always preserved.

### Investigation Assistant

`xdr/investigation_assistant.py`

Generates:

- attack summary
- likely root cause
- probable attacker behavior
- suggested next steps
- suggested containment
- evidence checklist

### Incident Prioritization Engine

`xdr/prioritization_engine.py`

Prioritizes incidents as:

- Critical
- High
- Medium
- Low

Inputs include business impact, affected hosts, critical assets, attack progression, persistence, lateral movement, credential access, and threat intelligence severity.

### Explainability Engine

`xdr/explainability_engine.py`

Explains:

- why a detection was generated
- contributing events
- contributing engines
- confidence
- evidence chain

### Threat Intelligence Enrichment

`xdr/threat_intel.py`

Adds offline-safe IOC context:

- IOC confidence
- IOC aging
- reputation
- ASN-style context
- domain-age context
- geo context

It can wrap the existing threat-intel facade but does not require external APIs.

### Progression Predictor

`xdr/progression_predictor.py`

Predicts likely next stage, for example:

- persistence plus beaconing -> credential access
- lateral movement -> privilege escalation
- credential access -> lateral movement

### Executive Summary Engine

`xdr/executive_summary_engine.py`

Translates technical security signals into non-technical executive risk language.

### Playbook Recommendation Engine

`xdr/playbook_engine.py`

Recommends defensive playbooks:

- forensic collection
- IOC hunt
- persistence review
- credential reset review
- host isolation review

Containment-oriented recommendations require approval and are not executed automatically.

## SAFE Copilot

Route:

```text
/soc/copilot
```

The Copilot panel shows:

- analyst brief
- executive risk explanation
- contextualized alert cards
- false-positive probability
- evidence chain
- suggested next steps
- recommended playbooks
- predicted next stage
- guardrails

## Guardrails

- Defensive only.
- Human-in-the-loop by default.
- No automatic destructive action.
- Critical detections are never hidden.
- Containment remains approval-gated.
- No secrets, host keys, tokens, or raw sensitive values are shown in the UI.
- Every recommendation is explainable and auditable.

## Testing

Run:

```powershell
python run_pentest_audit.py
python -m pytest tests\test_alert_context_engine.py tests\test_fp_reduction_engine.py tests\test_investigation_assistant.py tests\test_prioritization_engine.py tests\test_explainability_engine.py tests\test_progression_predictor.py tests\test_safe_ai_soc_panel.py -q
python -m pytest tests\ -q
```
