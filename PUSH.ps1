# ============================================================
# SAFE Build 8 — Asset Intelligence Enrichment — commit + push
# Uso: powershell -ExecutionPolicy Bypass -File .\PUSH.ps1
# ============================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  SAFE - Build 8: Asset Intelligence" -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host ""

if (Test-Path ".git/index.lock") {
    Remove-Item ".git/index.lock" -Force
    Write-Host ">> lock removido" -ForegroundColor DarkGray
}

$branch = git rev-parse --abbrev-ref HEAD
Write-Host ">> branch: $branch" -ForegroundColor Cyan
git status --short | Select-Object -First 30

git add -A
$staged = git diff --cached --shortstat
if (-not $staged) { Write-Host ">> nada a commitar." -ForegroundColor Yellow; exit 0 }
Write-Host ">> staged: $staged" -ForegroundColor Green

$msg = @"
xdr: Asset Intelligence Engine (build 8)

Adiciona enrichment de host com classificacao + criticality_score separado
do risk_score. Risk = quao ameacado; criticality = quao valioso o ativo e.

xdr/asset_intelligence.py (novo, 297 LOC)
  - AssetClass enum: workstation, server, domain_controller, database,
    dev_machine, executive_device, critical_asset, unknown
  - Sensitivity (1-4) + Environment (prod/staging/dev/unknown)
  - AssetProfile dataclass com to_dict() JSON-safe
  - classify_asset(hint): heuristica em 3 niveis
      1. tag override (critical-asset, dc, executive, etc)
      2. role/asset_class field direto
      3. regex no hostname (WIN-DC-01, db-prod-mysql, ceo-laptop, etc)
  - detect_environment(hint): tags / hostname / explicit field
  - score_criticality(profile) -> 0..100
      base por class * environment_multiplier + sensitivity_bump
  - business_impact_label(score) -> low|medium|high|critical
  - enrich_host(record) -> AssetProfile (nao muta input)

app.py endpoints novos
  - GET /api/assets/<host_id>: AssetProfile do host
  - GET /api/assets?class=&env=&min_crit=: lista com filtros + sort
    por criticality desc

tests/test_asset_intelligence.py (novo, 36 testes)
  - classify_asset cobre todas as 7 classes + tag override + role field
  - detect_environment via tag/hostname/explicit
  - score_criticality: bounds, env multiplier, sensitivity bump, clamp 100
  - business_impact_label: parametrizado nos 4 buckets
  - enrich_host: input nao mutado, non-dict safe, JSON serializavel

Sem mexer em risk_engine, sem migracao de schema. Enrichment puro:
o enrichment e calculado on-read a partir de campos ja existentes no
host record (hostname, tags, role, environment, sensitivity, owner).

Total: ~370 LOC + 36 testes. Zero impacto nos testes pre-existentes.
"@

git commit -m $msg
if ($LASTEXITCODE -ne 0) { Write-Host ">> commit falhou" -ForegroundColor Red; exit 1 }
Write-Host ">> commit ok" -ForegroundColor Green

Write-Host ">> push origin $branch ..." -ForegroundColor Cyan
git push origin $branch
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "  Build 8 PUSHED." -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
} else {
    Write-Host ">> push falhou. Verifique credenciais GitHub." -ForegroundColor Red
    exit 1
}
