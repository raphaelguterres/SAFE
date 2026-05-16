# ============================================================
# SAFE branding cleanup — 3 commits separados
# Uso: powershell -ExecutionPolicy Bypass -File .\PUSH.ps1
# ============================================================

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host ""
Write-Host "==============================================" -ForegroundColor Yellow
Write-Host "  SAFE branding cleanup (3 commits)" -ForegroundColor Yellow
Write-Host "==============================================" -ForegroundColor Yellow

if (Test-Path ".git/index.lock") {
    Remove-Item ".git/index.lock" -Force
}

$branch = git rev-parse --abbrev-ref HEAD
Write-Host ">> branch: $branch" -ForegroundColor Cyan

# Commit 1: CSS rename
Write-Host ""
Write-Host ">> Commit 1/3: rename netguard.css -> safe.css" -ForegroundColor Green
git add static/css/safe.css
git add static/enterprise.css
git add templates/*.html templates/soc/*.html admin.html dashboard.html dashboard/templates_html.py
git add tests/test_safe_rebrand.py tests/test_ui_enterprise_refactor.py
$msg1 = @"
ui: rename netguard.css -> safe.css (alias mantido)

Cria static/css/safe.css como copia canonica do legacy netguard.css.
Templates e codigo Python passam a referenciar safe.css. O arquivo
netguard.css continua presente como alias durante a transicao.

Arquivos atualizados (19 no total):
  static/css/safe.css (novo, copia de netguard.css)
  static/enterprise.css
  templates/admin_dashboard.html
  templates/client_overview.html
  templates/executive.html
  templates/host_triage.html
  templates/landing.html
  templates/login.html
  templates/observability.html
  templates/operator_inbox.html
  templates/performance.html
  templates/performance_live.html
  templates/pricing.html
  templates/welcome.html
  templates/soc/base.html
  admin.html
  dashboard.html
  dashboard/templates_html.py
  tests/test_safe_rebrand.py
  tests/test_ui_enterprise_refactor.py

netguard.css mantido pra deploys legados. Sem mudancas de regra CSS.
"@
git commit -m $msg1
if ($LASTEXITCODE -ne 0) { Write-Host ">> commit 1 falhou" -ForegroundColor Red; exit 1 }

# Commit 2: JS rename
Write-Host ""
Write-Host ">> Commit 2/3: rename netguard-ui.js -> safe-ui.js" -ForegroundColor Green
git add static/js/safe-ui.js
git add templates/*.html templates/soc/*.html admin.html dashboard.html dashboard/templates_html.py
$msg2 = @"
ui: rename netguard-ui.js -> safe-ui.js (alias mantido)

Cria static/js/safe-ui.js como copia canonica do legacy netguard-ui.js.
Templates passam a referenciar safe-ui.js. netguard-ui.js mantido
como alias durante a transicao.

Arquivos atualizados: ~13 templates + scripts/*
"@
git commit -m $msg2
if ($LASTEXITCODE -ne 0) { Write-Host ">> commit 2 falhou" -ForegroundColor Red; exit 1 }

# Commit 3: Token files migration
Write-Host ""
Write-Host ">> Commit 3/3: migrate .netguard_token -> .safe_token (fallback)" -ForegroundColor Green
git add .gitignore auth.py admin.html scripts/security_self_check.py templates/welcome.html
$msg3 = @"
auth: migrate .netguard_token / .netguard_totp -> .safe_*

auth.py agora usa .safe_token e .safe_totp como caminhos canonicos.
Leitura cai pra .netguard_token / .netguard_totp como fallback quando
o caminho SAFE nao existe. Na primeira leitura, conteudo legacy e
copiado pro caminho SAFE.

Mudancas:
  - auth.py:
      TOKEN_FILE         = _BASE_DIR / .safe_token
      TOKEN_FILE_LEGACY  = _BASE_DIR / .netguard_token
      TOTP_FILE          = _BASE_DIR / .safe_totp
      TOTP_FILE_LEGACY   = _BASE_DIR / .netguard_totp
      _read_token_with_fallback() / _read_totp_with_fallback()
      rotate_admin_token() atualiza ambos quando legacy existe
      totp_disable() remove ambos
  - admin.html: texto visivel cita .safe_* primeiro, .netguard_* como legacy
  - scripts/security_self_check.py: checa todos 4 paths
  - templates/welcome.html: comando safe-agent prefere SAFE_TOKEN/SAFE_SERVER
  - .gitignore: ignora .safe_token/.safe_totp e chaves/certs locais SAFE

Sem breaking changes: deploys com .netguard_token continuam funcionando.
"@
git commit -m $msg3
if ($LASTEXITCODE -ne 0) { Write-Host ">> commit 3 falhou" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host ">> push origin $branch ..." -ForegroundColor Cyan
git push origin $branch
if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "==============================================" -ForegroundColor Green
    Write-Host "  3 commits PUSHED." -ForegroundColor Green
    Write-Host "==============================================" -ForegroundColor Green
} else {
    Write-Host ">> push falhou. Verifique credenciais." -ForegroundColor Red
    exit 1
}
