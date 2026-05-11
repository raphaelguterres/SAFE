# SAFE Security Intelligence Layer — auditoria + plano

> Auditoria do plano "SAFE SECURITY INTELLIGENCE LAYER" contra o que já existe
> no diretório `xdr/` e `engine/`. Veredicto: **~80% implementado**, gaps reais
> concentrados em **Identity Risk** (inexistente), **Security Graph navegável**,
> **Detection Quality Center UI** e classificação de **Asset Intelligence**.

## Inventário do que já existe em `xdr/` (49 módulos)

```
action_signing.py         alert_context_engine.py    attack_timeline.py
audit_integrity.py        audit_pipeline.py          behavior_engine.py
case_management.py        correlation.py             correlation_engine.py  ← campaigns
dedup_engine.py           detection.py               disaster_recovery.py
event_bus.py              evidence_store.py          executive_summary_engine.py
explainability_engine.py  export_engine.py           fp_reduction_engine.py  ← FP/noise
health_engine.py          heartbeat_engine.py        host_defense_engine.py  ← host state
ingestion_pipeline.py     investigation_assistant.py ioc_manager.py
killchain_engine.py       observability.py           orchestration_engine.py
performance_metrics.py    pipeline.py                playbook_engine.py     ← KB tactical
playbook_executor.py      policy_engine.py           posture_engine.py
prioritization_engine.py  priority_engine.py         progression_predictor.py
queue_manager.py          realtime_stream.py         recovery_engine.py
reporting_engine.py       response.py                rule_catalog.py
schema.py                 severity.py                soc_metrics.py
story_engine.py           threat_hunting.py          threat_intel.py
workflow_engine.py
```

## Mapeamento item-a-item do plano → existente

### 1. Asset Intelligence Engine

**Plano:** classificar (workstation/server/DC/etc) + criticality_score + owner + environment + tags + sensitivity.

**Existente:**
- `engine/risk_engine.py` — per-host scoring 0-100 (CrowdStrike-inspired)
- `xdr/host_defense_engine.py` — host protection state
- `agent/host_identity.py` — identidade persistente do host
- `storage/host_repository.py` — armazenamento

**Falta (gap real):**
- Campo `asset_class` (workstation/server/domain_controller/database/dev_machine/executive_device/critical_asset)
- Campo `criticality_score` separado do risk_score (risco = ameaça; criticality = valor do ativo)
- Campos `business_impact`, `owner`, `environment` (prod/staging/dev), `tags`, `sensitivity`
- API pra atribuir/listar/filtrar por classificação

**Esforço:** ~250 LOC + migração schema + 10 testes.

### 2. Identity Risk Engine

**Plano:** monitorar auth anomalies, privilege escalation, impossible travel, login chaining, brute force, unusual access. `IdentityRiskProfile`.

**Existente:** **nada específico de identity**. O projeto rastreia hosts, não usuários.

**Falta (gap real):**
- Modelo `IdentityRiskProfile` (user_id, risk_score, privilege_level, anomalies, affected_hosts)
- Coletores no agente pra eventos de logon (Windows Event 4624/4625, sudo, su, ssh)
- Correlators: brute force, impossible travel (geo + timing), privilege escalation
- Storage `storage/identity_repository.py`
- UI dedicada

**Esforço:** ~600 LOC + 20 testes + UI nova. **Maior gap real do plano**.

### 3. Security Graph Engine

**Plano:** relacionamentos hosts/users/IOCs/incidents/detections/domains/IPs/processes/campaigns + attack path tracing.

**Existente:**
- `xdr/correlation_engine.py:IncidentCorrelationV2` — correlaciona por IP, infra compartilhada, progressão temporal. Gera `CampaignCorrelation` objects.
- `engine/lateral_movement.py` — detecta lateral movement (já é graph-like)
- `engine/soc_correlator.py` — correlator generalista

**Falta (gap real):**
- Modelo de grafo formal (nodes/edges) navegável
- API `/api/graph/host/<id>?depth=N` retornando subgrafo
- Persistência (SQLite tabela `graph_edges` ou similar)
- Algoritmo de attack path tracing (shortest path por edges de "execution_chain", "credential_reuse", etc)

**Esforço:** ~400 LOC + 15 testes.

### 4. Attack Graph Visualization

**Plano:** `/soc/attack-graph` com host relationships, attack propagation, IOC reuse, lateral movement chains, credential paths, process chains.

**Existente:** **nada visual**. `attack_timeline` é linear (não grafo).

**Falta (gap real):**
- Página `/soc/attack-graph` (Jinja template + JS)
- Renderer SVG/Canvas (preferência SVG nativo, sem dep externa; ou D3.js força graph)
- Layout force-directed simples

**Esforço:** ~500 LOC HTML/CSS/JS + tests E2E manuais.

### 5. Detection Lifecycle Management

**Plano:** rule staging, canary detections, suppression rules, noisy detection tracking, rule confidence tuning, FP feedback, health scoring.

**Existente:**
- `xdr/fp_reduction_engine.py` — FP reduction com proteções pra alerts críticos
- `rules/yaml_loader.py` — carrega regras YAML
- `engine/rule_executor.py`

**Falta (gap real):**
- Staging area (regras em "shadow mode" antes de promover)
- Canary detections (regras com tag `canary` que só logam, não disparam)
- Suppression rules persistentes (por host/IP/user/técnica)
- Métricas de "rule health" (FP ratio, last_trigger, mean_severity)
- Feedback loop (analyst marca FP → score da regra cai)

**Esforço:** ~350 LOC + 15 testes.

### 6. Campaign Intelligence Engine

**Plano:** agrupar same-infra, same-MITRE, repeated chains, IOC clusters, recurring behavior. `CampaignProfile`.

**Existente:** **JÁ EXISTE** em `xdr/correlation_engine.py`.
```python
class CampaignCorrelation:
    correlation_type: str  # "repeated_attacker_infrastructure" | "temporal_attack_progression"
    campaign_id: str
    confidence: int
    affected_hosts: list
    attacker_infrastructure: list
    ...

class IncidentCorrelationV2:
    def correlate(self, ...) -> list[CampaignCorrelation]:
        ...
```
- `app.py:_build_campaign_context()` alimenta o overview com campanhas
- `templates/soc/overview.html` mostra "Attack Campaigns" panel

**Falta (gap real opcional):**
- Mais tipos de correlação além das 2 atuais (process_chain, credential_reuse, command_pattern)
- `likely_objective` (hoje não preenche)
- `progression_pattern` (qual fase Lockheed a campanha está atacando)

**Esforço:** ~200 LOC pra expansão. Base já funciona.

### 7. Prioritization V3

**Plano:** considerar asset criticality, user privilege, attack progression, persistence, campaign linkage, lateral movement, exec exposure, prod impact.

**Existente:**
- `xdr/prioritization_engine.py` (110 LOC) + `xdr/priority_engine.py` (154 LOC)
- `xdr/progression_predictor.py` — predição de progressão

**Falta (gap real):**
- Asset criticality como feature (depende do item 1)
- User privilege como feature (depende do item 2)
- Campaign linkage como boost (depende do item 6 expandido)
- Re-rank após cada novo signal

**Esforço:** ~150 LOC + 10 testes. **Depende dos itens 1 e 2 estarem prontos.**

### 8. Detection Quality Center

**Plano:** `/soc/detection-quality` mostrando noisy rules, suppression candidates, FP ratio, top detections, low-confidence, disabled, tuning suggestions.

**Existente:** dados parcialmente disponíveis em `fp_reduction_engine.py`, mas **sem UI**.

**Falta (gap real):**
- Página `/soc/detection-quality`
- Tabela de regras com health columns
- Endpoint `/api/detection-quality/rules` agregando métricas

**Esforço:** ~300 LOC + 8 testes.

### 9. Identity + Host Timeline

**Plano:** combinar host activity + user activity + auth + process + attack progression + response actions.

**Existente:**
- Host timeline em `templates/host_triage.html` (já refinada nos builds anteriores)

**Falta (gap real):**
- Camada user activity (depende do item 2)
- Auth events trackings

**Esforço:** depende do item 2. ~200 LOC adicional.

### 10. Security Knowledge Base

**Plano:** MITRE techniques + playbooks + response guidance + analyst notes + investigation refs + recurring patterns.

**Existente:**
- `engine/playbook_engine.py` — playbooks (brute_force, web_attack, malware, exfil, ransomware, apt_lateral, generic_critical)
- `engine/mitre_engine.py` + `mitre_mapper.py`
- `xdr/investigation_assistant.py` — investigation refs

**Falta (gap real):**
- Página `/soc/knowledge` unificando tudo
- Endpoint `/api/knowledge/techniques/<id>` retornando playbook + investigation refs + recurring patterns

**Esforço:** ~200 LOC. **Mais cosmético/UX do que funcional**.

### 11. Tests

**Falta:** todos os 5 arquivos solicitados.

### 12. Documentation

**Falta:** este arquivo (já está sendo gerado).

## Gaps reais — priorizados

| # | Gap | Impacto | Esforço | Prioridade | Dependências |
|---|---|---|---|---|---|
| 1 | **Identity Risk Engine completo** | Muito alto (lacuna estrutural) | Muito alto (~600 LOC + 20 testes + UI) | **Alta** | — |
| 2 | **Asset Intelligence enrichment** (classification + criticality) | Alto | Médio (~250 LOC) | **Alta** | — |
| 3 | **Security Graph + tracing** | Alto | Médio (~400 LOC + 15 testes) | **Alta** | — |
| 4 | **Attack Graph UI** | Alto (visual impact) | Alto (~500 LOC HTML/CSS/JS) | Média | Depende #3 |
| 5 | **Detection Quality Center UI** | Médio | Médio (~300 LOC) | Média | — |
| 6 | **Detection Lifecycle**: staging, canary, FP feedback | Médio | Médio (~350 LOC) | Média | — |
| 7 | **Prioritization V3** (asset + identity boost) | Médio | Baixo (~150 LOC) | Baixa | Depende #1 e #2 |
| 8 | **Campaign expansion** (likely_objective, progression_pattern) | Baixo | Baixo (~200 LOC) | Baixa | — |
| 9 | **Knowledge Base unificado UI** | Baixo | Baixo (~200 LOC) | Baixa | — |
| 10 | **Identity+Host timeline merge** | Médio | Médio (~200 LOC) | Baixa | Depende #1 |

## Recomendação de sequência de builds

Cada build = 1 commit pequeno, testes próprios, sem mexer no que existe.

**Build 8 — Asset Intelligence enrichment**
- Novo módulo `xdr/asset_intelligence.py` com schema + classification rules + criticality
- Migração leve em `storage/host_repository.py`
- 10 testes
- Endpoint `/api/assets/<host_id>` (já existe risk/host; adicionar asset_class + criticality_score)

**Build 9 — Security Graph (sem UI)**
- `xdr/security_graph.py`: nodes (host/user/ip/domain/ioc) + edges (saw, attacked, executed_on)
- Storage `graph_edges` table
- API `/api/graph/host/<id>?depth=N`
- 15 testes

**Build 10 — Identity Risk Engine**
- `xdr/identity_engine.py`: IdentityRiskProfile
- Coletores básicos (auth events)
- Detectores: brute force, impossible travel (geo via GeoLite2 já carregado)
- 20 testes

**Build 11 — Detection Quality Center UI**
- Template `/soc/detection-quality`
- Endpoint `/api/detection/health`
- 8 testes

**Build 12 — Attack Graph Visualization**
- `/soc/attack-graph` page
- Force-directed SVG (sem D3)
- Drilldown integrado com Graph API do build 9

## Sensação final

Quando todos os 5 builds (8–12) estiverem entregues, o SAFE terá os 4 pilares que tornam plataformas como CrowdStrike Falcon e Microsoft Defender XDR sensoriais:

1. **Asset awareness** ← build 8
2. **Identity awareness** ← build 10
3. **Graph intelligence** ← builds 9 + 12
4. **Detection lifecycle/quality** ← build 11

Cada um é um commit standalone. Posso começar pelo **8 (Asset Intelligence)** que é o menor e desbloqueia o **7 (Prioritization V3)**, ou pelo **10 (Identity Risk)** que é o gap estrutural maior.
