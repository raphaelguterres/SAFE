param(
    [switch]$SkipInstall,
    [switch]$QuickCheck
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "SAFE bootstrap: validating Python..."
$python = Get-Command python -ErrorAction Stop
$version = & $python.Source -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ([version]$version -lt [version]"3.11") {
    throw "Python 3.11+ is required. Found $version"
}

if (!(Test-Path ".venv")) {
    Write-Host "Creating .venv..."
    & $python.Source -m venv .venv
}

$venvPython = Join-Path $Root ".venv\Scripts\python.exe"
if (!$SkipInstall) {
    Write-Host "Installing requirements..."
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install -r requirements.txt
}

if (!(Test-Path ".env.example")) {
    throw ".env.example is missing"
}

Write-Host "Running SAFE quick release checks..."
if ($QuickCheck) {
    & $venvPython scripts\release_check.py --quick
} else {
    & $venvPython scripts\release_check.py --quick
    & $venvPython scripts\template_check.py
    & $venvPython scripts\branding_check.py
}

Write-Host "SAFE dev environment is ready."
