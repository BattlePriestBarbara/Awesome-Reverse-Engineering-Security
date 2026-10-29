# Builds the shared Python reverse-engineering environment in .venv
#   packages: pefile, oletools, capstone, unicorn, keystone-engine, lief,
#             pyelftools, objection (frida-based mobile runtime RE), mitmproxy
# paths come from $PSScriptRoot, so the non-ASCII toolkit root needs no literal.
# usage: powershell -ExecutionPolicy Bypass -File setup-pyenv.ps1
$ErrorActionPreference = 'Continue'
$here = $PSScriptRoot
$venv = Join-Path $here '.venv'
$log = Join-Path $here 'setup-pyenv.log'

function Log($s) { Add-Content -LiteralPath $log -Value $s; Write-Output $s }

if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
Log ('=== setup ' + (Get-Date -Format s))

$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) { Log 'FATAL: py launcher not found'; exit 1 }

if (-not (Test-Path -LiteralPath (Join-Path $venv 'Scripts\python.exe'))) {
    & py -3.12 -m venv $venv 2>&1 | ForEach-Object { Log $_ }
}
$vp = Join-Path $venv 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $vp)) { Log 'FATAL: venv python missing'; exit 1 }
Log ('python: ' + (& $vp -c "import sys;print(sys.version.split()[0])"))

& $vp -m pip install --disable-pip-version-check --quiet --upgrade pip 2>&1 | ForEach-Object { Log $_ }

$pkgs = @('pefile', 'oletools', 'capstone', 'unicorn', 'keystone-engine', 'lief', 'pyelftools', 'objection', 'mitmproxy')
# PyPI's CDN sometimes stalls on larger Windows wheels; on failure retry via TUNA.
$mirror = 'https://pypi.tuna.tsinghua.edu.cn/simple'
foreach ($p in $pkgs) {
    Log ('--- pip install ' + $p)
    $out = & $vp -m pip install --disable-pip-version-check --quiet $p 2>&1
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        Log ('    pypi exit=' + $code + ', retrying via mirror')
        $out = & $vp -m pip install --disable-pip-version-check --quiet --index-url $mirror $p 2>&1
        $code = $LASTEXITCODE
    }
    if ($code -ne 0) { Log ('    FAILED exit=' + $code + ' ' + (($out | Out-String).Trim())) }
    else { Log '    ok' }
}

Log '--- import check'
$probe = @'
mods = ["pefile", "oletools", "capstone", "unicorn", "keystone", "lief", "elftools"]
for m in mods:
    try:
        mod = __import__(m)
        print("OK   {:<10} {}".format(m, getattr(mod, "__version__", "")))
    except Exception as exc:
        print("FAIL {:<10} {}".format(m, exc))
'@
$probeFile = Join-Path $here '_probe.py'
Set-Content -LiteralPath $probeFile -Value $probe -Encoding UTF8
& $vp $probeFile 2>&1 | ForEach-Object { Log $_ }
Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue

& $vp -m pip freeze | Out-File -FilePath (Join-Path $here 'requirements-lock.txt') -Encoding utf8
Log 'SETUP-FINISHED'
