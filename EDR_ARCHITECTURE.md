# SAFE EDR Architecture — current state

> Auditoria contra o plano "EDR enterprise-grade based on Cyber Kill Chain principles".
> **Veredicto:** ~80% do plano já está implementado. O projeto não é IDS, é EDR/XDR maduro
> com camadas de detecção, correlação, resposta automática, agente, threat intel,
> incident management, RBAC, audit, e dashboard analítica.

## TL;DR

O que falta de fato:
1. **Vista "Lockheed Cyber Kill Chain" explícita** (6 fases canônicas) — hoje usa MITRE ATT&CK (14 tactics) que é o equivalente moderno.
2. **Painel visual de Kill Chain** no dashboard (engine existe, UI dedicada não).
3. **Heatmap de risco por host** (dados existem em `engine/risk_engine.py`, falta painel).
4. **Fila assíncrona Redis** (suportada como dep, mas ingestão hoje é threading).
5. **Documentação** desta arquitetura — esse arquivo é o passo 1.

## Fluxo de dados (high-level)

```
                          ┌────────────────────────┐
   ENDPOINT (Win/Linux)   │ agent/agent.py         │
   • processos            │ • coleta processos,    │
   • net connections      │   conexões, logins,    │
   • file changes         │   file changes         │
   • login attempts       │ • envia via HTTPS+API  │
                          │   key → /api/agent/    │
                          │   events               │
                          └────────────┬───────────┘
                                       │
                                       ▼
   ┌───────────────────────────────────────────────────────────────┐
   │ INGESTÃO  (app.py + server/ingestion.py)                       │
   │ • valida tenant + signature                                    │
   │ • normaliza schema                                             │
   │ • escreve em event_repository                                  │
   └───────────────────────────────┬───────────────────────────────┘
                                   │
                  ┌────────────────┼────────────────┐
                  ▼                ▼                ▼
   ┌───────────────────┐ ┌─────────────────┐ ┌─────────────────────┐
   │ DETECTION         │ │ XDR PIPELINE    │ │ ENRICHMENT          │
   │ engine/detection_ │ │ xdr/pipeline.py │ │ engine/enrichment.  │
   │ engine.py         │ │ + xdr/correla-  │ │ py + threat_intel_  │
   │ + ids_engine.py   │ │ tion.py         │ │ feed + virustotal   │
   │ • signature       │ │ • weak signals  │ │ • IP/hash/domain    │
   │ • YARA            │ │ • behavior      │ │   reputation        │
   │ • Sigma-like YAML │ │   chains        │ │                     │
   │ • ML baseline     │ │                 │ │                     │
   └─────────┬─────────┘ └────────┬────────┘ └─────────────────────┘
             │                    │
             └──────────┬─────────┘
                        ▼
   ┌────────────────────────────────────────────────────┐
   │ CORRELATION                                         │
   │ • engine/correlation_engine.py (v1)                 │
   │ • engine/correlation_engine_v2.py (v2)              │
   │ • engine/soc_correlator.py                          │
   │ • engine/attack_timeline.py                         │
   │ • engine/lateral_movement.py                        │
   │ • engine/mitre_engine.py + mitre_mapper.py          │
   │ • killchain.py (kill-chain progression by IP)       │
   └─────────────────────┬──────────────────────────────┘
                         ▼
   ┌────────────────────────────────────────────────────┐
   │ RISK SCORING (per host, 0-100)                      │
   │ • engine/risk_engine.py    (CrowdStrike-inspired)   │
   │ • engine/soc_risk_scorer.py                         │
   │ • engine/severity_classifier.py                     │
   │ • xdr/severity.py                                   │
   └─────────────────────┬──────────────────────────────┘
                         ▼
   ┌────────────────────────────────────────────────────┐
   │ INCIDENT MANAGEMENT                                 │
   │ • engine/incident_engine.py                         │
   │ • engine/playbook_engine.py (auto playbooks)        │
   │ • storage/incident_repository.py                    │
   └─────────────────────┬──────────────────────────────┘
                         ▼
   ┌────────────────────────────────────────────────────┐
   │ ACTIVE RESPONSE                                     │
   │ • engine/auto_block.py (Windows Firewall netsh)     │
   │ • engine/remediation_engine.py                      │
   │ • fail2ban_engine.py (brute-force ban)              │
   │ • agent/actions.py (server → agent dispatch):       │
   │     - kill_process       (signed policy)            │
   │     - isolate_host       (signed policy)            │
   │     - block_ip           (signed policy)            │
   │     - delete_file        (signed policy)            │
   │     - collect_diagnostics                           │
   │     - flush_buffer       / ping                     │
   └─────────────────────┬──────────────────────────────┘
                         ▼
   ┌────────────────────────────────────────────────────┐
   │ DASHBOARD                                           │
   │ • templates/soc/* (operações)                       │
   │ • dashboard.html (legacy command center)            │
   │ • templates/host_triage.html                        │
   │ • templates/operator_inbox.html                     │
   │ • admin.html (god view multi-tenant)                │
   └────────────────────────────────────────────────────┘
```

## Mapeamento plano → módulos existentes

### 1. Kill Chain Engine

**Plan:** mapear eventos em estágios Reconnaissance → Delivery → Exploitation → Installation → C2 → Actions on Objectives.

**Onde está:**
- `killchain.py` — correlator full por source_ip ao longo do tempo, gera incident reports completos no formato MITRE ATT&CK Navigator. Substitui 2-4h de SOC L1/L2 manual.
- `engine/attack_timeline.py` — timeline visual de ataques.
- `engine/mitre_engine.py` + `engine/mitre_mapper.py` — mapeia eventos para tactics/techniques MITRE.
- `xdr/correlation.py` — weak-signal correlation chains.

**Estágios usados (MITRE ATT&CK 14 tactics):**
```
reconnaissance → resource_development → initial_access → execution →
persistence → privilege_escalation → defense_evasion → credential_access →
discovery → lateral_movement → collection → command_and_control →
exfiltration → impact
```

**Mapeamento Lockheed Cyber Kill Chain (6) → MITRE (14):**
```
Reconnaissance        ↔ reconnaissance + resource_development
Delivery              ↔ initial_access
Exploitation          ↔ execution + privilege_escalation
Installation          ↔ persistence + defense_evasion
Command & Control     ↔ command_and_control + credential_access + discovery
Actions on Objectives ↔ lateral_movement + collection + exfiltration + impact
```

**Gap:** essa view de 6 fases não existe explicitamente. Engine pode ser adicionada como wrapper sobre MITRE existente.

### 2. Threat Scoring

**Plan:** severity = base_score + correlation_bonus + threat_intel_score.

**Onde está:**
- `engine/risk_engine.py` (320 lines) — Risk Score per host (0-100), CrowdStrike/Defender/Elastic style. Já considera severidade, quantidade de eventos, MITRE tactics, kill chain progression, contexto (processo/rede/web).
- `engine/soc_risk_scorer.py` — scorer SOC-specific.
- `engine/severity_classifier.py` — classifica eventos.
- `xdr/severity.py` — `severity_weight()`, `clamp_risk()`, `risk_level()`.

**Níveis usados (xdr/severity.py):**
```
low      < 30
medium   30-60
high     60-85
critical 85-100
```
Mesmo do plano.

### 3. Response Engine

**Plan:** Block IP, Kill Process, Disable User, Quarantine Host.

**Onde está:**
- `engine/auto_block.py` (315 lines) — Windows Firewall via `netsh advfirewall`, com TTL e whitelist.
- `engine/remediation_engine.py` (367 lines) — playbooks de remediação.
- `engine/playbook_engine.py` (403 lines) — incident response playbooks (brute_force, web_attack, malware, exfiltration, ransomware, apt_lateral, generic_critical).
- `fail2ban_engine.py` — ban automático por brute force.
- `agent/actions.py` (314 lines) — server → agent dispatch com **signed policy + nonce + expiry**:
    - `kill_process`
    - `isolate_host`
    - `block_ip`
    - `delete_file`

Trigger automático já existe via `engine/playbook_engine.py auto_trigger()`.

### 4. Endpoint Agent

**Plan:** coletar processos, conexões, file changes, logins, enviar via API.

**Onde está:**
- `agent/agent.py` (548 lines) — runtime principal.
- `agent/host_identity.py` — identidade persistente do host.
- `agent/sender.py` — envio para `/api/agent/events`.
- `agent/actions.py` — polling de ações de resposta.
- `agent/__main__.py` — CLI entrypoint.
- `agent/agent.spec` — PyInstaller para `agent.exe`.

Suporte: Windows + Linux (`platform_utils.py`).

### 5. Threat Intelligence

**Plan:** IP/Hash/Domain reputation via public feeds.

**Onde está:**
- `engine/threat_intel_feed.py` (457 lines) — Feodo, ThreatFox, URLhaus, custom feeds.
- `engine/virustotal.py` — VirusTotal API integration.
- `engine/enrichment.py` — enrichment pipeline.
- `engine/ioc_manager.py` — Indicators of Compromise.

### 6. Incident Management

**Plan:** create incident on multiple correlated events + high risk; store id, timeline, hosts, status, severity.

**Onde está:**
- `engine/incident_engine.py` (205 lines) — backed by repository.
- `storage/incident_repository.py` — SQLite + Postgres.
- `engine/playbook_engine.py` — auto-trigger de incident playbook na detecção.

Estrutura armazenada (matches plan):
```python
{
  "incident_id": str,
  "playbook":    str,    # brute_force, web_attack, etc
  "trigger_event": dict,
  "severity":    str,
  "status":      str,    # open, in_progress, contained, resolved, false_positive
  "opened_at":   datetime,
  "updated_at":  datetime,
  "tenant_id":   str,
  "assignee":    str,
  "notes":       str,
  "steps":       [...]   # auto-generated playbook steps
}
```

### 7. Dashboard EDR

**Plan:** threat timeline, kill chain visualization, top attackers, active incidents, risk heatmap. CrowdStrike Falcon-inspired.

**Onde está:**
- `templates/soc/overview.html` — KPIs + active incidents.
- `templates/soc/incidents.html` — fila de incidentes operacional.
- `templates/soc/hosts.html` — top hosts at risk.
- `templates/soc/host_detail.html` — host triage com timeline + risk breakdown.
- `templates/operator_inbox.html` — inbox cross-tenant ranqueado por urgência.
- `templates/host_triage.html` — risk + next-action + timeline + MITRE context.
- `dashboard.html` (9k+ linhas) — legacy command grid.
- `admin.html` — god view multi-tenant.

UI já passou por redesign Apple Pro nesta sessão (dia/noite, champagne accent, hairlines).

**Gap visualização Kill Chain dedicada:** os dados estão em `killchain.py` mas não há um painel dedicado mostrando "host X chegou em estágio Y, próximo provável Z". Heatmap também ausente.

### 8. API Layer

**Plan:** /events, /incidents, /threats, /response/actions.

**Onde está (em `app.py`):**
- `/api/events` — ingestion
- `/api/agent/events` — agent ingestion
- `/api/agent/actions` — agent action polling + dispatch
- `/api/agent/hosts/<host_id>/actions` — admin dispatch
- `/api/incidents` — listar/criar
- `/api/admin/inbox` — operator inbox
- `/api/risk/host/<host_id>` — host risk score
- `/api/risk/hosts` — top hosts
- `/api/playbooks` — list/run playbooks
- `/api/threats/iocs` — IoCs management
- `/api/admin/audit` — audit log
- `/api/xdr/events` (ingest) + `/api/xdr/summary` (read)
- `/api/admin/stream` — SSE para live updates

### 9. Performance

**Plan:** async processing, queue (Redis optional).

**Onde está:**
- Threading + locks por tenant em `app.py` e engines.
- Redis dep declarada (`requirements.txt: redis==5.0.8`).
- Rate limit shared via Redis configurável (`IDS_API_RL_BACKEND=redis`).
- SWR (stale-while-revalidate) cache em endpoints SOC.
- Lazy singletons com invalidação (corrigido state-leak nesta sessão em `engine/playbook_engine.py`).

**Gap:** ingestão direta hoje é síncrona threading. Pra escala, faltaria fila Redis explícita (RQ ou Celery).

### 10. Security Hardening

**Plan:** Auth (JWT), rate limit, log integrity.

**Onde está (em `auth.py` + `security.py`):**
- API tokens com `nga_*` prefix + signing key (`TOKEN_SIGNING_SECRET`)
- Hash HMAC-SHA256 dos tokens em DB
- Session cookie + CSRF token (TOTP)
- Rate limit per-route (modular API + admin)
- Flask-Talisman para CSP/HSTS/etc
- Audit log estruturado (`engine/edr_sentinel.py` usa append-only)
- TOTP 2FA opcional
- Tenant isolation enforcing
- Action policy: signed nonce + expiry + max-TTL = 300s
- Sensitive data redaction filter em logs

## Gaps reais — priorizados por impacto/esforço

| # | Gap | Impacto | Esforço | Prioridade |
|---|---|---|---|---|
| 1 | View Cyber Kill Chain (Lockheed 6 fases) sobre MITRE existente | Médio (visual/clareza para CISO) | Baixo (~200 LOC + painel) | **Alta** |
| 2 | Painel Kill Chain visual no dashboard SOC | Alto (analyst UX) | Médio (HTML/CSS + JS de render) | **Alta** |
| 3 | Heatmap de risco multi-host | Alto (visão de god view) | Médio (componente novo) | **Alta** |
| 4 | Fila Redis explícita | Médio (escala 100+ agents) | Médio | Média |
| 5 | Async processing pipeline (asyncio) | Baixo (threading já basta < 1k events/s) | Alto | Baixa |
| 6 | JWT além do API token | Baixo (API token já é signed) | Baixo | Baixa |
| 7 | Cobertura de teste de threat_intel | Médio | Baixo | Média |

## Recomendação de próximo passo

**Build incremental 1:** Adicionar view Lockheed Cyber Kill Chain como wrapper sobre MITRE.
- Novo módulo `engine/kill_chain_lockheed.py` (~200 LOC) que mapeia tactics MITRE → 6 fases.
- Endpoint `/api/risk/host/<id>/kill_chain` retornando estado atual do host nas 6 fases.
- Adicionar painel no `templates/soc/host_detail.html` mostrando os 6 quadrados com indicador de fase atingida.

**Build incremental 2:** Heatmap multi-host.
- Componente novo no overview SOC: grid de hosts × fases Kill Chain, célula colorida por intensidade.

Cada build é 1 commit pequeno, sem mexer no que funciona, com testes próprios.

## Onde buscar quando tiver dúvida

- "Onde está a detecção sigma-like?" → `engine/detection_engine.py` + `rules/yaml_loader.py`
- "Como o agente envia dados?" → `agent/sender.py` → `/api/agent/events`
- "Onde está o motor de risco por host?" → `engine/risk_engine.py`
- "Como funciona o polling de ações no agente?" → `agent/actions.py` (signed policy required for guarded actions)
- "Onde plugar nova fonte de IoC?" → `engine/threat_intel_feed.py` (custom feed registration)
- "Onde está a UI de incidentes?" → `templates/soc/incidents.html`
- "Onde edito playbooks?" → `engine/playbook_engine.py` `PLAYBOOKS` dict
- "Onde está a tela do operador?" → `templates/operator_inbox.html` + `/admin/inbox`
- "Como adicionar nova action server→agent?" → adicionar em `SAFE_ACTION_TYPES` ou `GUARDED_ACTION_TYPES` em `agent/actions.py`, executor em agent runtime.
