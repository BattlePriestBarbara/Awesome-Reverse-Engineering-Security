# Convert 逆向工具使用手册.docx -> legacy .doc (Word 97-2003) and refresh the TOC.
# Run: powershell -ExecutionPolicy Bypass -File _docx2doc.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot                 # 脚本所在目录（= 工具集根目录）
if ([string]::IsNullOrWhiteSpace($root)) { $root = 'D:\逆向工具网络安全汇总' }
$src = Join-Path $root '逆向工具使用手册.docx'
$dst = Join-Path $root '逆向工具使用手册.doc'

if (-not (Test-Path -LiteralPath $src)) { throw "missing $src" }

$word = New-Object -ComObject Word.Application
$word.Visible = $false
$word.DisplayAlerts = 0
try {
    $doc = $word.Documents.Open($src, $false, $false)
    foreach ($toc in $doc.TablesOfContents) { $toc.Update() }
    $doc.Fields.Update() | Out-Null
    $doc.Repaginate()
    $pages = $doc.ComputeStatistics(2)   # wdStatisticPages
    $words = $doc.ComputeStatistics(0)   # wdStatisticWords
    $doc.Save()                          # 先把填好页码的 TOC 存回 .docx
    # Word 2007 的 SaveAs 声明为 Variant 引用参数，用 [ref] 传变量在 -File 模式下
    # 会抛 "Value does not fall within the expected range"，直接按位置传参即可。
    $doc.SaveAs($dst, 0)                 # 0 = wdFormatDocument (.doc)
    $doc.Close(0)
    "pages=$pages words=$words"
}
finally {
    # Word 2007 在关掉最后一个文档后可能已自行退出，此时 Quit/Release 会报
    # "RPC server is unavailable (0x800706BA)"，属正常现象，不应算失败。
    try { $word.Quit() } catch { }
    try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($word) } catch { }
}

$len = (Get-Item -LiteralPath $dst).Length
"doc written: $dst  $len bytes"
