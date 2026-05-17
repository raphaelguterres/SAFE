# SAFE — Information Architecture proposta

> Audit do roteamento atual e plano para separar **três perfis** de uso —
> **Admin (SOC operator/MSSP)**, **Usuário (cliente final)** e **Produção
> (plataforma/ops)** — com links coerentes entre eles.

## Hoje: rotas misturadas (sem perfil claro)

Há ~40 rotas HTML servindo audiências diferentes sem distinção visual ou estrutural:

```
/                          marketing
/pricing                   marketing
/contact                   marketing
/login                     auth
/welcome                   onboarding
/trial, /trial/<token>     onboarding

/client/overview           USER · Executive view
/client/dashboard          USER · Technical view
/client                    USER (legacy redirect)

/dashboard                 LEGACY · Command Center monolítico (9k linhas)
/executive                 USER · Executive summary

/soc                       ADMIN · SOC overview
/soc/overview              ADMIN
/soc/incidents             ADMIN · Incidents queue
/soc/hosts                 ADMIN · Hosts list
/soc/campaigns             ADMIN · Attack campaigns
/soc/identities            ADMIN · Identity risk view
/soc/hunts                 ADMIN · Threat hunts
/soc/approvals             ADMIN · Action approval queue
/soc/response-center       ADMIN · Active response panel
/soc/live-response         ADMIN
/soc/detection-packs       ADMIN · Sigma-like rule packs
/soc/copilot               ADMIN · AI assistant
/soc/case/<id>             ADMIN · Case detail
/soc/search                ADMIN · IOC search
/soc/metrics               ADMIN · SOC KPIs

/admin                     PROD/ADMIN · God view multi-tenant
/admin/inbox               ADMIN · Operator inbox cross-tenant
/admin/host/<tid>/<hid>    ADMIN · Host triage
/admin/view/<tid>          ADMIN · Drill-down de tenant
/admin/observability       PROD · Platform health
/admin/performance         PROD · Performance metrics
/admin/performance-live    PROD · Performance live stream

/health, /metrics          PROD · Health/Prometheus endpoints
/demo, /demo/reset         PROD · Demo seed
```

**Problemas:**
1. Cliente final que abrir `/admin/observability` vê coisas internas de plataforma.
2. SOC analyst que abrir `/client/overview` vê dados resumidos demais (não consegue agir).
3. Não há topbar/sidebar declarando em qual perfil você está agora.
4. Algumas views são duplicadas (`/dashboard` legacy vs `/soc` moderno).

## Proposta: separação em 3 áreas

### `/app/` — PARTE USUÁRIO (Cliente final)
Quem contratou SAFE. Vê só o tenant dele.

```
/app/overview           → Executive Posture (atual /client/overview)
/app/dashboard          → Technical view (atual /client/dashboard)
/app/assets             → seus hosts (filtrado pelo tenant)
/app/incidents          → seus incidentes
/app/reports            → exportar PDF/CSV
/app/settings/agent     → config do agente
/app/settings/tenant    → integrações, webhooks, billing
```

Marketing & onboarding ficam **fora do app** mas linkam pra ele:
```
/                       marketing
/pricing                marketing
/contact                marketing
/login                  → após login redireciona pra /app/overview
/welcome                onboarding pós signup
/trial, /trial/<token>  free trial flow
```

### `/soc/` — PARTE ADMIN (Analyst/MSSP Operator)
Quem opera o SAFE em nome do cliente. Pode ver vários tenants.

```
/soc                       → overview operacional (já existe)
/soc/incidents             → fila de incidentes
/soc/hosts                 → hosts at risk
/soc/identities            → identity risk (do Build 10)
/soc/campaigns             → attack campaigns
/soc/hunts                 → threat hunts
/soc/approvals             → ações pendentes
/soc/response-center       → active response
/soc/live-response         → live response actions
/soc/detection-packs       → sigma packs
/soc/copilot               → AI assistant
/soc/search                → IOC search
/soc/metrics               → SOC KPIs
/soc/case/<id>             → case detail
/soc/host/<tid>/<hid>      → host triage (renomeia /admin/host/...)
/soc/inbox                 → operator inbox (renomeia /admin/inbox)
```

### `/platform/` — PARTE PRODUÇÃO (Platform Owner/Ops)
Quem mantém o SAFE rodando.

```
/platform                  → god view de tenants
/platform/tenants          → lista + drilldown
/platform/tenants/<tid>    → ver tenant
/platform/observability    → platform health
/platform/performance      → performance metrics
/platform/performance-live → live perf stream
/platform/trials           → trial admin
/platform/auth             → rotate-admin-token, TOTP setup
/platform/audit            → audit log integrity
/platform/config           → IDS_HTTPS, autoblock config, etc

/health, /metrics          → Prometheus/health (técnico)
```

## Topbar / Sidebar consistente por perfil

| Perfil | Cor | Topbar mostra |
|---|---|---|
| `/app/*` | branco/cinza claro (light-first) | Logo + tenant_name + theme toggle + avatar |
| `/soc/*` | navy + champanhe (dark default) | Logo + tenant switcher + analyst name + alerts |
| `/platform/*` | preto + accent ciano | Logo + "PLATFORM" badge + total tenants/health summary |

Cores distintas comunicam "você está em outro contexto" sem precisar ler.

## Links cruzados (drill-up / drill-down)

```
/app/overview     —[botão "Open SOC"]→            /soc                (cliente vê SOC do MSSP dele)
/app/overview     —[botão "Open Technical"]→     /app/dashboard       (cliente vê detalhes)
/soc/host/.../... —[link "Owner tenant"]→        /platform/tenants    (admin sobe pra produção)
/platform/tenants —[link "Open SOC"]→            /soc?tenant=<tid>    (prod desce pra SOC)
/soc              —[link discreto "Platform"]→  /platform            (top-right, só visível pra superadmin)
```

## Migração — fases

### Fase 1 — Aliases (sem quebrar nada)
Adicionar rotas novas que redirecionam pra atuais:
- `/app/overview` → `/client/overview`
- `/platform/observability` → `/admin/observability`
- `/soc/host/<tid>/<hid>` → `/admin/host/<tid>/<hid>`

Atualizar TODOS os links visíveis pros caminhos novos. Antigos viram `301 Moved` mas continuam funcionando.

### Fase 2 — Visual unification por perfil
Cada perfil ganha seu próprio CSS base:
- `safe-app.css` (USER) — base light, accent champanhe sutil
- `safe-soc.css` (ADMIN) — dark default, alta densidade
- `safe-platform.css` (PROD) — dark extra, mais técnico

### Fase 3 — Topbar/sidebar partials
Três partials Jinja:
- `templates/_partials/app_topbar.html`
- `templates/_partials/soc_topbar.html` (já existe parcial em `templates/soc/partials/topbar.html`)
- `templates/_partials/platform_topbar.html`

Cada um declara seu perfil visualmente.

### Fase 4 — Remover legacy
Depois de N semanas de aliases funcionando, remove rotas `/admin/*` antigas (mantém só `/platform/*`) e `/client/*` (mantém só `/app/*`).

## Auth / permissões

| Rota | Permissão necessária |
|---|---|
| `/app/*` | session ativa do cliente (tenant_id resolvido do JWT/cookie) |
| `/soc/*` | role `analyst` ou `mssp_operator` |
| `/platform/*` | role `superadmin` (token de admin do `.safe_token` OU role com privilege escalation explicito) |

Token de tenant SaaS (`ng_xxx`) NUNCA acessa `/platform/*` nem `/soc/*` de outros tenants.

## Resultado esperado

Quando um cliente abre o produto, vê `/app/overview` — claro, Apple-clean, light theme, sem termos técnicos confusos.

Quando um analyst SOC abre, vê `/soc` — dark dense, MITRE, kill chain, ações guardadas.

Quando o owner da plataforma abre, vê `/platform` — extra dark, health overall, billing, integrações.

Cada um sabe onde está pela **cor da topbar, pelo logo badge, pelo título da página**.

Nenhum dos três acessa por engano o painel do outro.

---

## Próximos passos

Posso fazer um build de cada vez (cada commit ≤ 300 LOC):

1. **Build A — Fase 1 (aliases + links cruzados).** Não-quebrante. ~150 LOC. Tests: novos pro redirect + smoke nas 3 áreas.
2. **Build B — Topbar partials separados.** Renderiza topbar diferente por área. ~200 LOC + 3 templates novos.
3. **Build C — CSS bases por perfil.** Três stylesheets, cada um carrega só na sua área. ~400 LOC CSS.
4. **Build D — Bug fixes pontuais.** Inclui o fix do client overview que acabei de fazer.

Me diga por qual quer começar.

## Status de execução

- Build A aplicado: aliases `/app/*`, `/soc/inbox`, `/soc/host/*` e `/platform/*` adicionados como redirects 301 sem remover rotas antigas.
- Links visíveis principais atualizados para a nova information architecture.
- Testes adicionados em `tests/test_information_architecture_aliases.py`.
- Build B parcial aplicado: `/app/overview` virou rota principal do cliente, `/client/overview` virou redirect legacy, e topbars parciais de `/app` e `/platform` foram criadas.
