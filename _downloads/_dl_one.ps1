# Downloads ONE manifest entry, trying mirrors in order, resuming partial files.
#   usage: powershell -File _dl_one.ps1 -Name imhex-1.38.1-Windows-Portable-x86_64.zip
#   log:   _dl_<name>.log   (called in parallel by _dl_all.ps1)
param([Parameter(Mandatory = $true)][string]$Name)

$ErrorActionPreference = 'Continue'
$base = $PSScriptRoot
$log = Join-Path $base ('_dl_' + ($Name -replace '[^\w\.\-]', '_') + '.log')
$m = Get-Content (Join-Path $base 'manifest.json') -Raw | ConvertFrom-Json
$e = $m | Where-Object { $_.name -eq $Name } | Select-Object -First 1
if (-not $e) { Add-Content -LiteralPath $log -Value ('no manifest entry for ' + $Name); exit 1 }

$mirrors = @('https://ghfast.top/', 'https://ghproxy.net/', 'https://gh-proxy.com/', '')
$dest = Join-Path $base $e.name

function Log($s) { Add-Content -LiteralPath $log -Value $s }

function Test-Ok($entry, $file) {
    if (-not (Test-Path -LiteralPath $file)) { return $false }
    if ((Get-Item -LiteralPath $file).Length -ne $entry.size) { return $false }
    if ([string]::IsNullOrWhiteSpace($entry.digest)) { return $true }
    $want = ($entry.digest -replace '^sha256:', '').ToLower()
    $got = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLower()
    return ($got -eq $want)
}

if (Test-Ok $e $dest) { Log ('SKIP ' + $e.name + ' (already verified)'); exit 0 }
Log ('=== ' + $e.name + ' size=' + $e.size + ' start ' + (Get-Date -Format HH:mm:ss))

$ok = $false
foreach ($mi in $mirrors) {
    $label = if ($mi) { $mi -replace '^https://', '' } else { 'github-direct' }
    for ($try = 1; $try -le 3 -and -not $ok; $try++) {
        $resume = @()
        $before = 0
        if (Test-Path -LiteralPath $dest) { $before = (Get-Item -LiteralPath $dest).Length }
        if ($before -gt 0) { $resume = @('-C', '-') }
        $t0 = Get-Date
        $err = & curl.exe -L --retry 2 --retry-delay 2 --connect-timeout 15 --speed-time 30 --speed-limit 2048 -sS @resume -o $dest ($mi + $e.url) 2>&1
        $after = if (Test-Path -LiteralPath $dest) { (Get-Item -LiteralPath $dest).Length } else { 0 }
        $secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
        Log ('  ' + $label + ' try' + $try + ' exit=' + $LASTEXITCODE + ' ' + $secs + 's ' + [math]::Round($before / 1MB, 1) + '->' + [math]::Round($after / 1MB, 1) + 'MB ' + (($err | Out-String).Trim()))
        if (Test-Ok $e $dest) { $ok = $true }
        elseif ($after -le $before) { break }   # no progress from this mirror, move on
    }
    if ($ok) { break }
}
if ($ok) { Log ('DONE ' + $e.name + ' verified'); exit 0 }
$have = if (Test-Path -LiteralPath $dest) { (Get-Item -LiteralPath $dest).Length } else { 0 }
Log ('FAIL ' + $e.name + ' have=' + $have)
exit 2
