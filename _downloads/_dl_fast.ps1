# Block-parallel downloader for ONE manifest entry.
# Mirrors (ghfast.top & friends) hand out roughly 4 MB per connection at full
# speed and then throttle to ~40 KB/s, so we chop the file into small blocks
# (~3 MB), pull them from a rotating pool of connections, stitch, and verify.
# Blocks already on disk are reused, so re-running resumes instead of restarting.
#   usage: powershell -File _dl_fast.ps1 -Name floss-v3.2.0-windows.zip
#          powershell -File _dl_fast.ps1 -Name X.zip -BlockMB 3 -Parallel 10
#   log:   _dl_<name>.log   (same file _dl_one.ps1 writes, so _dl.log stays in sync)
param(
    [Parameter(Mandatory = $true)][string]$Name,
    [int]$BlockMB = 3,
    [int]$Parallel = 10,
    [int]$MaxRounds = 4,
    [string[]]$Mirrors = @('https://ghfast.top/', 'https://ghproxy.net/', 'https://gh-proxy.com/', ''),
    [int]$DeadlineSec = 1800
)

$ErrorActionPreference = 'Continue'
$base = $PSScriptRoot
$log = Join-Path $base ('_dl_' + ($Name -replace '[^\w\.\-]', '_') + '.log')
$m = Get-Content (Join-Path $base 'manifest.json') -Raw | ConvertFrom-Json
$e = $m | Where-Object { $_.name -eq $Name } | Select-Object -First 1
if (-not $e) { Add-Content -LiteralPath $log -Value ('no manifest entry for ' + $Name); exit 1 }

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

$size = [long]$e.size
$block = [long]$BlockMB * 1MB
$n = [int][math]::Ceiling($size / $block)
$tag = ($e.name -replace '[^\w\.\-]', '_')
$parts = @()
for ($i = 0; $i -lt $n; $i++) {
    $s = [long]$i * $block
    $en = [math]::Min($s + $block - 1, $size - 1)
    $parts += [pscustomobject]@{
        Index = $i; Start = $s; End = $en; Want = ($en - $s + 1)
        File  = (Join-Path $base ('_blk_' + $i + '_' + $tag))
    }
}

function Get-Have($p) { if (Test-Path -LiteralPath $p.File) { (Get-Item -LiteralPath $p.File).Length } else { 0 } }
# note the leading comma: it stops PowerShell from unrolling a 1-element array,
# which would make .Count return $null and silently break the pending checks
function Get-Pending { , @($parts | Where-Object { (Get-Have $_) -ne $_.Want }) }

Log ('=== FAST ' + $e.name + ' size=' + $size + ' blocks=' + $n + ' x' + $BlockMB + 'MB parallel=' + $Parallel + ' start ' + (Get-Date -Format HH:mm:ss))


$ok = $false
foreach ($mi in $Mirrors) {
    $label = if ($mi) { $mi -replace '^https://', '' } else { 'github-direct' }
    $url = $mi + $e.url
    $t0 = Get-Date
    for ($round = 1; $round -le $MaxRounds; $round++) {
        $pending = Get-Pending
        if ($pending.Count -eq 0) { break }
        Log ('  ' + $label + ' round' + $round + ' pending=' + $pending.Count + '/' + $n)
        $queue = New-Object System.Collections.Queue
        $pending | ForEach-Object { $queue.Enqueue($_) }
        $running = @{}
        $lastLog = Get-Date
        while ($queue.Count -gt 0 -or $running.Count -gt 0) {
            while ($running.Count -lt $Parallel -and $queue.Count -gt 0) {
                $p = $queue.Dequeue()
                $have = Get-Have $p
                if ($have -eq $p.Want) { continue }
                if ($have -gt $p.Want) { Remove-Item -LiteralPath $p.File -Force -EA SilentlyContinue; $have = 0 }
                # resume inside the block: fetch only the missing tail, then append
                $from = $p.Start + $have
                $tmp = $p.File + '.tmp'
                Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue
                $cargs = @('-f', '-L', '--retry', '2', '--retry-delay', '1', '--connect-timeout', '10',
                    '--speed-limit', '16384', '--speed-time', '15', '--max-time', '300', '-sS',
                    '-r', ($from.ToString() + '-' + $p.End.ToString()), '-o', $tmp, $url)
                $pr = Start-Process -FilePath 'curl.exe' -ArgumentList $cargs -PassThru -WindowStyle Hidden
                $running[$pr.Id] = [pscustomobject]@{ Part = $p; Tmp = $tmp; From = $from }
            }
            if ($running.Count -eq 0) { break }
            Start-Sleep -Milliseconds 400
            foreach ($id in @($running.Keys)) {
                if ($null -eq (Get-Process -Id $id -ErrorAction SilentlyContinue)) {
                    $job = $running[$id]
                    $expect = $job.Part.End - $job.From + 1
                    $got = if (Test-Path -LiteralPath $job.Tmp) { (Get-Item -LiteralPath $job.Tmp).Length } else { 0 }
                    if ($got -gt 0 -and $got -le $expect) {
                        # curl -f only writes real body bytes, so anything here is data
                        $fs = [System.IO.File]::Open($job.Part.File, 'Append', 'Write')
                        $ins = [System.IO.File]::OpenRead($job.Tmp)
                        $ins.CopyTo($fs, 1048576)
                        $ins.Close(); $fs.Close()
                    }
                    elseif ($got -gt $expect) {
                        # server ignored the range and sent more than we asked for: start over
                        Remove-Item -LiteralPath $job.Part.File -Force -EA SilentlyContinue
                    }
                    Remove-Item -LiteralPath $job.Tmp -Force -EA SilentlyContinue
                    $running.Remove($id)
                }
            }
            if (((Get-Date) - $lastLog).TotalSeconds -ge 20) {
                $lastLog = Get-Date
                $have = 0; foreach ($p in $parts) { $have += (Get-Have $p) }
                $el = ((Get-Date) - $t0).TotalSeconds
                Log ('  ' + $label + ' ' + [math]::Round($have / 1MB, 1) + '/' + [math]::Round($size / 1MB, 1) + 'MB ' +
                    [math]::Round($have / $el / 1KB, 0) + 'KB/s open=' + $running.Count)
            }
            if (((Get-Date) - $t0).TotalSeconds -gt $DeadlineSec) { break }
        }
        $pc = (Get-Pending).Count
        if ($pc -eq 0) { break }
        if (((Get-Date) - $t0).TotalSeconds -gt $DeadlineSec) { Log ('  ' + $label + ' deadline hit, pending=' + $pc); break }
    }

    if ((Get-Pending).Count -ne 0) { Log ('  ' + $label + ' incomplete, next mirror'); continue }

    # ---- stitch ------------------------------------------------------------
    Remove-Item -LiteralPath $dest -Force -EA SilentlyContinue
    $out = [System.IO.File]::Open($dest, 'Create', 'Write')
    foreach ($p in $parts) {
        $in = [System.IO.File]::OpenRead($p.File)
        $in.CopyTo($out, 1048576)
        $in.Close()
    }
    $out.Close()
    Remove-Item -LiteralPath ($parts | ForEach-Object { $_.File }) -Force -EA SilentlyContinue

    $secs = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    if (Test-Ok $e $dest) { Log ('  ' + $label + ' stitched in ' + $secs + 's, verified'); $ok = $true; break }
    Log ('  ' + $label + ' stitched in ' + $secs + 's but verify FAILED (corrupt/partial data)')
    Remove-Item -LiteralPath $dest -Force -EA SilentlyContinue
    Remove-Item -LiteralPath ($parts | ForEach-Object { $_.File }) -Force -EA SilentlyContinue
}

if ($ok) { Log ('DONE ' + $e.name + ' verified'); exit 0 }
Log ('FAIL ' + $e.name + ' (all mirrors)')
exit 2
