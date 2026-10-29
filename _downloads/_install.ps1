# Extracts every verified archive from manifest.json into its "dest" folder.
#   - single top-level folder inside a zip is flattened away (dest = tool root)
#   - .jar entries are simply copied
# paths come from $PSScriptRoot; run from this folder.
# usage: powershell -ExecutionPolicy Bypass -File _install.ps1
$ErrorActionPreference = 'Continue'
$base = $PSScriptRoot
$root = Split-Path -Parent $base
$log = Join-Path $base '_install.log'
$m = Get-Content (Join-Path $base 'manifest.json') -Raw | ConvertFrom-Json

function Log($s) { Add-Content -LiteralPath $log -Value $s; Write-Output $s }
if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
Log ('=== install ' + (Get-Date -Format s))

foreach ($e in $m) {
    $zip = Join-Path $base $e.name
    $dest = Join-Path $root ($e.dest -replace '/', '\')
    if (-not (Test-Path -LiteralPath $zip)) { Log ('MISSING archive ' + $e.name); continue }
    $actual = (Get-Item -LiteralPath $zip).Length
    if ($actual -ne $e.size) { Log ('SKIP ' + $e.name + ' (incomplete ' + $actual + '/' + $e.size + ')'); continue }

    New-Item -ItemType Directory -Force -Path $dest | Out-Null

    if ($e.name -like '*.jar') {
        Copy-Item -LiteralPath $zip -Destination (Join-Path $dest $e.name) -Force
        Log ('COPY ' + $e.name + ' -> ' + $e.dest)
        continue
    }

    $stage = Join-Path $base ('_stage_' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    try {
        Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force -ErrorAction Stop
    }
    catch {
        Log ('FAIL expand ' + $e.name + ': ' + $_.Exception.Message)
        Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
        continue
    }
    $top = @(Get-ChildItem -LiteralPath $stage -Force)
    $src = if ($top.Count -eq 1 -and $top[0].PSIsContainer) { $top[0].FullName } else { $stage }
    Get-ChildItem -LiteralPath $src -Force | Move-Item -Destination $dest -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
    $n = @(Get-ChildItem -LiteralPath $dest -Recurse -File).Count
    Log ('EXTRACT ' + $e.name + ' -> ' + $e.dest + ' (' + $n + ' files)')
}
Log 'INSTALL-FINISHED'
