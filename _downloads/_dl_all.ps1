# Runs _dl_one.ps1 for several entries at once (one process per file) and reports.
#   usage: powershell -File _dl_all.ps1                 (all manifest entries)
#          powershell -File _dl_all.ps1 -Max 6          (at most 6 concurrent)
param([int]$Max = 6, [string[]]$Only)

$ErrorActionPreference = 'Continue'
$base = $PSScriptRoot
$log = Join-Path $base '_dl.log'
$m = Get-Content (Join-Path $base 'manifest.json') -Raw | ConvertFrom-Json
$Only = @($Only | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

function Test-Done($e) {
    $f = Join-Path $base $e.name
    if (-not (Test-Path -LiteralPath $f)) { return $false }
    if ((Get-Item -LiteralPath $f).Length -ne $e.size) { return $false }
    if ([string]::IsNullOrWhiteSpace($e.digest)) { return $true }
    $want = ($e.digest -replace '^sha256:', '').ToLower()
    return ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower() -eq $want)
}

$todo = @()
foreach ($e in $m) {
    if ($Only) {
        $match = $false
        foreach ($f in $Only) {
            if ($e.name -like ('*' + $f + '*') -or $e.repo -like ('*' + $f + '*')) { $match = $true }
        }
        if (-not $match) { continue }
    }
    if (-not (Test-Done $e)) { $todo += $e }
}

Add-Content -LiteralPath $log -Value ('=== parallel start ' + (Get-Date -Format s) + ' files=' + $todo.Count)
$running = New-Object System.Collections.ArrayList
foreach ($e in $todo) {
    while (@($running | Where-Object { -not $_.HasExited }).Count -ge $Max) {
        Start-Sleep -Milliseconds 700
        $running = @($running | Where-Object { -not $_.HasExited })
    }
    $p = Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -PassThru `
        -ArgumentList '-ExecutionPolicy', 'Bypass', '-NoProfile', '-File', (Join-Path $base '_dl_one.ps1'), '-Name', $e.name
    [void]$running.Add($p)
}
while (@($running | Where-Object { -not $_.HasExited }).Count -gt 0) { Start-Sleep -Seconds 5 }

foreach ($e in $m) {
    $state = if (Test-Done $e) { 'OK  ' } else { 'MISS' }
    Add-Content -LiteralPath $log -Value ($state + ' ' + $e.name)
}
Add-Content -LiteralPath $log -Value 'ALL-FINISHED'
Get-Content -LiteralPath $log | Select-Object -Last 20
