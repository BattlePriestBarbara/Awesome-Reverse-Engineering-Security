# 把「要提交 git 的文件」单向镜像到独立的文档仓库目录，默认不提交。
#
#   powershell -ExecutionPolicy Bypass -File _sync_git.ps1              # 同步 + 显示 diff
#   powershell -ExecutionPolicy Bypass -File _sync_git.ps1 -Commit      # 同步 + 提交
#   powershell -ExecutionPolicy Bypass -File _sync_git.ps1 -Include "05-Cases\报告.md" -Commit
#
# 仓库位置默认是同级目录 "<本目录名>-git"：D:\逆向工具网络安全汇总-git
# 收哪些文件由白名单 _git_files.txt 决定（一行一个相对路径，# 开头为注释），
# 再并上仓库已有的 git ls-files 与 -Include 追加项。
param(
    [switch]$Commit,
    [string]$Message = 'docs: 同步文档与脚本',
    [string[]]$Include
)

$ErrorActionPreference = 'Stop'

$src = $PSScriptRoot
$repo = Join-Path (Split-Path $src -Parent) ((Split-Path $src -Leaf) + '-git')
$listFile = Join-Path $src '_git_files.txt'

if (-not (Test-Path -LiteralPath $repo)) {
    New-Item -ItemType Directory -Force -Path $repo | Out-Null
    "已创建仓库目录：$repo"
}

$base = @()
if (Test-Path -LiteralPath $listFile) {
    $base = @(Get-Content -LiteralPath $listFile -Encoding UTF8 |
              Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith('#') } |
              ForEach-Object { $_.Trim() })
} else {
    Write-Warning "白名单不存在：$listFile"
}

$tracked = @()
if (Test-Path -LiteralPath (Join-Path $repo '.git')) {
    $tracked = @(git -C $repo ls-files)
}

$all = @(@($base) + @($tracked) + @($Include | Where-Object { $_ }) |
         ForEach-Object { ($_ -replace '/', '\').Trim() } |
         Where-Object { $_ } |
         Select-Object -Unique)

$copied = 0
$missing = 0
foreach ($rel in $all) {
    $s = Join-Path $src $rel
    if (-not (Test-Path -LiteralPath $s)) {
        # 只有白名单要求的文件缺失才告警；仓库里有、工具目录没有的
        # （例如仓库自己的 .gitignore）属正常，静默跳过。
        if ($base -contains $rel) {
            Write-Warning "白名单里的源文件不存在，跳过：$rel"
            $missing++
        }
        continue
    }
    $t = Join-Path $repo $rel
    New-Item -ItemType Directory -Force -Path (Split-Path -LiteralPath $t) | Out-Null
    Copy-Item -LiteralPath $s -Destination $t -Force
    $copied++
}

$sum = (Get-ChildItem -LiteralPath $repo -Recurse -File |
        Where-Object { $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar).git$([IO.Path]::DirectorySeparatorChar)*" } |
        Measure-Object -Property Length -Sum).Sum
"同步完成：$copied 个文件 → $repo（内容约 $([math]::Round($sum / 1KB)) KB，源缺失 $missing 个）"
"summary: copied=$copied missing=$missing size_kb=$([math]::Round($sum / 1KB)) repo=$repo"

if (-not (Test-Path -LiteralPath (Join-Path $repo '.git'))) {
    "仓库还没初始化：cd /d `"$repo`" && git init && git add -A && git commit -m `"$Message`""
    return
}

git -C $repo add -A
$status = @(git -C $repo status --porcelain)
if ($status.Count -eq 0) {
    '仓库无变化，无需提交。'
    return
}

$status | ForEach-Object { "  $_" }
if ($Commit) {
    git -C $repo commit -q -m $Message
    git -C $repo log --oneline -1
} else {
    '（仅同步，未提交；加 -Commit 自动提交）'
}
