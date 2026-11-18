<#
.SYNOPSIS
  Imports the synthetic sample datasets (corp-small, corp-small-v2) and analyses them, so every page of the
  UI has data to show. Everything created is clearly marked as sample data.
#>
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location (Join-Path $root "backend")
try {
    $py = ".\.venv\Scripts\python.exe"
    foreach ($name in @("corp-small", "corp-small-v2")) {
        $out = & $py -m app.cli create-snapshot "Sample: $name" --sample
        if ($LASTEXITCODE -ne 0) { throw "could not create snapshot" }
        $id = ($out | Select-String -Pattern "Created snapshot (\d+)").Matches[0].Groups[1].Value
        & $py -m app.cli import $id "..\sample_data\$name\$name.zip" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "import of $name failed" }
        & $py -m app.cli analyze $id --top 3
    }
} finally { Pop-Location }
