<#
.SYNOPSIS
  One-time setup of AEGIS on Windows: backend venv + pinned dependencies, frontend dependencies and build,
  a local .env with a generated secret key. There are no default credentials: on first start, AEGIS asks you in the
  browser to create your own administrator account, using a one-time setup code shown in the server window.

.PARAMETER Dev
  Also install backend development/test dependencies.
.PARAMETER Admin
  Optional: create the first administrator from the terminal instead of in the browser (password is prompted).
#>
param([switch]$Dev, [string]$Admin)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

Write-Host "== Backend ==" -ForegroundColor Cyan
if ($Dev) { & "$PSScriptRoot\setup_backend.ps1" -Dev } else { & "$PSScriptRoot\setup_backend.ps1" }

Write-Host "== Frontend ==" -ForegroundColor Cyan
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { throw "Node.js (npm) is required: https://nodejs.org" }
Push-Location (Join-Path $root "frontend")
try {
    npm ci --no-fund --no-audit
    if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }
} finally { Pop-Location }

Write-Host "== Configuration ==" -ForegroundColor Cyan
$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) {
    $py = Join-Path $root "backend\.venv\Scripts\python.exe"
    $secret = (& $py -c "import secrets; print(secrets.token_urlsafe(48))").Trim()
    (Get-Content (Join-Path $root ".env.example")) -replace '^AEGIS_SECRET_KEY=.*$', "AEGIS_SECRET_KEY=$secret" |
        Set-Content -Encoding utf8 $envFile
    Write-Host "Created .env with a generated AEGIS_SECRET_KEY (keep this file private)."
} else {
    Write-Host ".env already exists; left unchanged."
}

if ($Admin) {
    Push-Location (Join-Path $root "backend")
    try { & .\.venv\Scripts\python.exe -m app.cli create-user $Admin --role admin } finally { Pop-Location }
}
Write-Host "Done. Start AEGIS with: powershell -ExecutionPolicy Bypass -File scripts\run_backend.ps1" -ForegroundColor Green
Write-Host "Then open http://127.0.0.1:8000 and create your administrator account with the setup code shown in the server window."
