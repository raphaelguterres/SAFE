# ============================================================
# NetGuard IDS - commit + push das mudancas
# Uso: powershell -ExecutionPolicy Bypass -File .\PUSH.ps1
# ============================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  NetGuard - git commit + push" -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

if (Test-Path ".git/index.lock") {
    Remove-Item ".git/index.lock" -Force
    Write-Host ">> lock removido" -ForegroundColor DarkGray
}

$branch = git rev-parse --abbrev-ref HEAD
Write-Host ">> branch: $branch" -ForegroundColor Cyan

Write-Host ">> arquivos modificados:" -ForegroundColor Cyan
git status --short | Select-Object -First 30

git add -A

$staged = git diff --cached --shortstat
if (-not $staged) {
    Write-Host ">> nada a commitar." -ForegroundColor Yellow
    exit 0
}
Write-Host ">> staged: $staged" -ForegroundColor Green

$msg = @"
edr: Lockheed Cyber Kill Chain views + multi-host fleet timeline

Novos modulos / endpoints / paineis sobre o motor MITRE ATT&CK existente.
Nenhuma quebra nos 855 testes pre-existentes; 94 testes novos no modulo.

engine/kill_chain_lockheed.py (novo)
  - PHASES / PHASE_LABELS / MITRE_TO_LOCKHEED (mapping 14 tactics -> 6 fases)
  - map_tactic(tactic)
  - derive_host_state(host_id, items) -> HostKillChainState
  - derive_progression_timeline(host_id, items, *, bucket_minutes,
    window_hours, include_events, max_events_per_bucket) -> dict
  - build_heatmap(hosts_data, *, tenant_id, phase, min_progression_pct,
    limit) -> dict
  - build_fleet_timeline(hosts_data, *, bucket_minutes, window_hours,
    tenant_id) -> dict (stacked area data)
  - _summarize_event(item, ts, phase) normalizer

app.py endpoints novos
  - GET /api/risk/host/<id>/kill_chain
  - GET /api/risk/host/<id>/kill_chain/timeline?window,bucket,include_events
  - GET /api/risk/heatmap (alias /api/risk/kill_chain/heatmap)
    + filters: tenant, phase, min_progression, limit
  - GET /api/risk/kill_chain/fleet_timeline?window,bucket,tenant

UI
  - templates/host_triage.html: painel de 6 fases + timeline SVG (24h)
    com drill-down de events por bucket ao clicar nos dots
  - templates/soc/overview.html: fleet stacked area + heatmap multi-host
    com filtros (tenant input, phase select, min_progression select,
    botao Limpar). Cores por fase: verde Recon -> vermelho Actions.

tests/test_kill_chain_lockheed.py
  - 94 testes cobrindo:
    - mapping table (14 tactics)
    - normalizacao de input (case, dashes, espacos)
    - derivacao de estado (empty, deepest wins, progression, etc)
    - build_heatmap (filtros, sort, intensity normalization)
    - timeline (bucketing, deepest cumulativo, include_events)
    - fleet_timeline (stack multi-host, tenant filter)

EDR_ARCHITECTURE.md
  - Mapeamento do plano EDR original contra modulos existentes
  - Diagrama de fluxo Endpoint -> Ingest -> Detect -> Correl -> Risk
    -> Incident -> Response -> Dashboard
  - Lista de gaps reais priorizados
"@

git commit -m $msg
if ($LASTEXITCODE -ne 0) {
    Write-Host ">> commit falhou" -ForegroundColor Red
    exit 1
}
Write-Host ">> commit ok" -ForegroundColor Green

Write-Host ">> push origin $branch ..." -ForegroundColor Cyan
git push origin $branch
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "  PUSHED com sucesso." -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
} else {
    Write-Host ">> push falhou. Verifique credenciais GitHub." -ForegroundColor Red
    exit 1
}
