<#
.SYNOPSIS
  Starts the AEGIS backend (single process, loopback only).

.PARAMETER Reload
  Auto-reload on code changes (development only; uses extra CPU for file watching).

.NOTES
  Uses `python -m uvicorn` rather than `uvicorn.exe`: Windows Smart App Control blocks pip's
  unsigned console-script launchers on this machine.
#>
param([switch]$Reload, [int]$Port = 8000)
$ErrorActionPreference = "Stop"

$backend = Join-Path (Split-Path -Parent $PSScriptRoot) "backend"
$py = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Virtual environment missing. Run scripts\setup_backend.ps1 first." }

$uvArgs = @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$Port")
if ($Reload) { $uvArgs += @("--reload", "--reload-dir", "app") }

Push-Location $backend
try { & $py @uvArgs } finally { Pop-Location }
