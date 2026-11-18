<#
.SYNOPSIS
  Creates the AEGIS backend virtual environment and installs pinned dependencies.
  Runs as a normal user. It changes nothing outside backend\.venv.

.PARAMETER Dev
  Also install development/test dependencies (requirements-dev.txt).
#>
param([switch]$Dev)
$ErrorActionPreference = "Stop"

$root    = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$venv    = Join-Path $backend ".venv"
$py      = Join-Path $venv "Scripts\python.exe"

# Prefer the python.org 3.12 build; the Microsoft Store build has AppData path redirection.
if (-not (Test-Path $py)) {
    Write-Host "Creating virtual environment with Python 3.12..."
    & py -3.12 -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw "Python 3.12 not found. Install it from python.org (per-user) and retry." }
}

$req = if ($Dev) { "requirements-dev.txt" } else { "requirements.txt" }
Write-Host "Installing $req ..."
& $py -m pip install -q --disable-pip-version-check -r (Join-Path $backend $req)
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

# Windows Smart App Control can block SQLAlchemy's unsigned Cython extensions.
# If that happens, reinstall the same version as pure Python (identical API, slightly slower).
# Probe in a child process. In Windows PowerShell 5.1, native stderr under
# ErrorActionPreference=Stop would otherwise become a terminating error.
function Test-SqlAlchemyImport {
    $prev = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    & $py -c "import sqlalchemy.util" 2>&1 | Out-Null
    $ok = ($LASTEXITCODE -eq 0)
    $ErrorActionPreference = $prev
    return $ok
}
if (-not (Test-SqlAlchemyImport)) {
    Write-Warning "SQLAlchemy native extension blocked (likely Smart App Control). Reinstalling pure-Python build."
    $ver = (& $py -c "import importlib.metadata as m; print(m.version('SQLAlchemy'))").Trim()
    $env:DISABLE_SQLALCHEMY_CEXT = "1"
    & $py -m pip install -q --disable-pip-version-check --force-reinstall --no-deps --no-binary sqlalchemy "SQLAlchemy==$ver"
    Remove-Item Env:\DISABLE_SQLALCHEMY_CEXT
    if (-not (Test-SqlAlchemyImport)) { throw "SQLAlchemy still fails to import." }
    Write-Host "SQLAlchemy $ver reinstalled as pure Python."
}

& $py -m pip check
Write-Host "Backend environment ready: $venv"
