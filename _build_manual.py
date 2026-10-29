# -*- coding: utf-8 -*-
"""Build 《逆向工具使用手册》 as .docx, then convert to legacy .doc via Word COM.

Every version / path / command in this document was collected from this machine
(see _inventory.json, _help.txt, _facts.txt, _demo.txt) instead of being guessed.

    .venv\\Scripts\\python.exe _build_manual.py
    powershell -ExecutionPolicy Bypass -File _docx2doc.ps1
"""
import os

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

R = r"D:\逆向工具网络安全汇总"
DOCX = os.path.join(R, "逆向工具使用手册.docx")

CN_BODY = "宋体"
CN_HEAD = "黑体"
EN_BODY = "Segoe UI"
MONO = "Consolas"
C_H1 = RGBColor(0x1F, 0x38, 0x64)
C_H2 = RGBColor(0x2E, 0x5C, 0x8A)
C_H3 = RGBColor(0x33, 0x33, 0x33)
C_NOTE = RGBColor(0x7F, 0x3F, 0x00)
C_CODE_BG = "F4F4F4"
C_TBL_HEAD = "DCE6F1"


# --------------------------------------------------------------------------- #
# low level helpers
# --------------------------------------------------------------------------- #
def run_font(run, size=None, bold=None, color=None, mono=False, cn=CN_BODY, en=None):
    name = MONO if mono else (en or EN_BODY)
    run.font.name = name
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    rfonts.set(qn("w:ascii"), name)
    rfonts.set(qn("w:hAnsi"), name)
    rfonts.set(qn("w:eastAsia"), cn)
    if size is not None:
        run.font.size = Pt(size)
    if bold is not None:
        run.font.bold = bold
    if color is not None:
        run.font.color.rgb = color
    return run


def shade(element, hex_fill):
    """Apply background shading to a paragraph or a table cell."""
    if hasattr(element, "_p"):
        pr = element._p.get_or_add_pPr()
    elif hasattr(element, "_tc"):
        pr = element._tc.get_or_add_tcPr()
    else:  # a raw oxml element
        pr = element
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    pr.append(shd)


def field(paragraph, instr, placeholder=""):
    """Insert a Word field (TOC / PAGE / NUMPAGES)."""
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    txt = OxmlElement("w:instrText")
    txt.set(qn("xml:space"), "preserve")
    txt.text = instr
    sep = OxmlElement("w:fldChar")
    sep.set(qn("w:fldCharType"), "separate")
    body = OxmlElement("w:t")
    body.text = placeholder
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    for node in (begin, txt, sep, body, end):
        run._r.append(node)
    return run


def p_border(paragraph, side="left", color="BFBFBF", size=18):
    pr = paragraph._p.get_or_add_pPr()
    bdr = pr.find(qn("w:pBdr"))
    if bdr is None:
        bdr = OxmlElement("w:pBdr")
        pr.append(bdr)
    el = OxmlElement("w:" + side)
    el.set(qn("w:val"), "single")
    el.set(qn("w:sz"), str(size))
    el.set(qn("w:space"), "4")
    el.set(qn("w:color"), color)
    bdr.append(el)


def h1(doc, text):
    p = doc.add_paragraph(style="Heading 1")
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after = Pt(10)
    p.paragraph_format.keep_with_next = True
    run_font(p.add_run(text), 17, True, C_H1, cn=CN_HEAD)
    p_border(p, "bottom", "1F3864", 8)
    return p


def h2(doc, text):
    p = doc.add_paragraph(style="Heading 2")
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after = Pt(5)
    p.paragraph_format.keep_with_next = True
    run_font(p.add_run(text), 13, True, C_H2, cn=CN_HEAD)
    return p


def h3(doc, text):
    p = doc.add_paragraph(style="Heading 3")
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    run_font(p.add_run(text), 11, True, C_H3, cn=CN_HEAD)
    return p


def text_runs(paragraph, text, size, bold=False, color=None, mono=False, cn=CN_BODY):
    """Write text into a paragraph, honouring **bold** and `mono` inline markers."""
    import re as _re
    for token in _re.split(r"(\*\*.+?\*\*|`[^`]+`)", text):
        if not token:
            continue
        if token.startswith("**") and token.endswith("**") and len(token) > 4:
            run_font(paragraph.add_run(token[2:-2]), size, True, color, mono=mono, cn=cn)
        elif token.startswith("`") and token.endswith("`") and len(token) > 2:
            run_font(paragraph.add_run(token[1:-1]), size - 0.5, bold, color, mono=True, cn=cn)
        else:
            run_font(paragraph.add_run(token), size, bold, color, mono=mono, cn=cn)


def para(doc, text, size=10.5, bold=False, italic=False, color=None,
         align=None, space_after=4, indent=None):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.28
    if indent is not None:
        p.paragraph_format.first_line_indent = Cm(indent)
    if align == "center":
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    elif align == "right":
        p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    text_runs(p, text, size, bold=bold, color=color)
    if italic:
        for run in p.runs:
            run.font.italic = True
    return p


def rich(doc, parts, size=10.5, space_after=4):
    """parts = [(text, {'mono':True,'bold':True,'color':RGB}), ...]"""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(space_after)
    p.paragraph_format.line_spacing = 1.28
    for text, opt in parts:
        run = p.add_run(text)
        run_font(run, opt.get("size", size), opt.get("bold"), opt.get("color"),
                 mono=opt.get("mono", False), cn=opt.get("cn", CN_BODY))
        if opt.get("italic"):
            run.font.italic = True
    return p


def bullets(doc, items, style="List Bullet", size=10.5):
    for it in items:
        p = doc.add_paragraph(style=style)
        p.paragraph_format.space_after = Pt(2)
        p.paragraph_format.line_spacing = 1.24
        if isinstance(it, tuple):
            run = p.add_run(it[0])
            run_font(run, size, True)
            run2 = p.add_run(it[1])
            run_font(run2, size)
        else:
            run_font(p.add_run(it), size)


def code(doc, text, size=8.5):
    p = doc.add_paragraph()
    fmt = p.paragraph_format
    fmt.space_before = Pt(3)
    fmt.space_after = Pt(7)
    fmt.line_spacing = 1.06
    fmt.left_indent = Cm(0.25)
    fmt.right_indent = Cm(0.1)
    shade(p, C_CODE_BG)
    p_border(p, "left", "7F9DB9", 18)
    lines = text.strip("\n").split("\n")
    for i, line in enumerate(lines):
        run = p.add_run(line)
        run_font(run, size, mono=True)
        if i != len(lines) - 1:
            run.add_break()
    return p


def note(doc, text, label="注意"):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(3)
    p.paragraph_format.space_after = Pt(7)
    p.paragraph_format.left_indent = Cm(0.25)
    shade(p, "FFF6E5")
    p_border(p, "left", "E0A040", 18)
    run_font(p.add_run(label + "："), 9.5, True, C_NOTE, cn=CN_HEAD)
    run_font(p.add_run(text), 9.5, False, C_NOTE)
    return p


def table(doc, header, rows, widths=None, size=9, mono_first=False, caption=None):
    if caption:
        cp = doc.add_paragraph()
        cp.paragraph_format.space_before = Pt(6)
        cp.paragraph_format.space_after = Pt(2)
        cp.paragraph_format.keep_with_next = True
        run_font(cp.add_run(caption), 9, True, C_H2, cn=CN_HEAD)
    tbl = doc.add_table(rows=1, cols=len(header))
    tbl.style = "Table Grid"
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.autofit = True
    hdr = tbl.rows[0].cells
    for i, text in enumerate(header):
        hdr[i].text = ""
        p = hdr[i].paragraphs[0]
        p.paragraph_format.space_after = Pt(1)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run_font(p.add_run(text), size, True, C_H1, cn=CN_HEAD)
        shade(hdr[i], C_TBL_HEAD)
    for row in rows:
        cells = tbl.add_row().cells
        for i, text in enumerate(row):
            cells[i].text = ""
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.line_spacing = 1.1
            txt = str(text)
            if not txt:
                continue
            if i == 0 and mono_first:
                run_font(p.add_run(txt), size - 0.5, mono=True)
            else:
                text_runs(p, txt, size)
    if widths:
        for i, w in enumerate(widths):
            for row in tbl.rows:
                row.cells[i].width = Cm(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return tbl


def setup_page(doc):
    s = doc.sections[0]
    s.orientation = WD_ORIENT.PORTRAIT
    s.page_width = Cm(21.0)
    s.page_height = Cm(29.7)
    s.top_margin = Cm(2.2)
    s.bottom_margin = Cm(2.0)
    s.left_margin = Cm(2.3)
    s.right_margin = Cm(2.0)
    s.header_distance = Cm(1.2)
    s.footer_distance = Cm(1.0)


def setup_styles(doc):
    normal = doc.styles["Normal"]
    normal.font.name = EN_BODY
    normal.font.size = Pt(10.5)
    npr = normal.element.get_or_add_rPr()
    nrfonts = npr.find(qn("w:rFonts"))
    if nrfonts is None:
        nrfonts = OxmlElement("w:rFonts")
        npr.insert(0, nrfonts)
    nrfonts.set(qn("w:eastAsia"), CN_BODY)
    for name, size, color in (("Heading 1", 17, C_H1), ("Heading 2", 13, C_H2),
                              ("Heading 3", 11, C_H3)):
        st = doc.styles[name]
        st.font.name = EN_BODY
        st.font.size = Pt(size)
        st.font.bold = True
        st.font.color.rgb = color
        rpr = st.element.get_or_add_rPr()
        rfonts = rpr.find(qn("w:rFonts"))
        if rfonts is None:
            rfonts = OxmlElement("w:rFonts")
            rpr.insert(0, rfonts)
        rfonts.set(qn("w:eastAsia"), CN_HEAD)


def header_footer(doc):
    sec = doc.sections[0]
    hp = sec.header.paragraphs[0]
    hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run_font(hp.add_run("逆向工具使用手册　|　D:\\逆向工具网络安全汇总"), 8.5, False,
             RGBColor(0x80, 0x80, 0x80))
    p_border(hp, "bottom", "BFBFBF", 6)

    fp = sec.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_font(fp.add_run("第 "), 8.5)
    field(fp, "PAGE", "1")
    run_font(fp.add_run(" 页 / 共 "), 8.5)
    field(fp, "NUMPAGES", "1")
    run_font(fp.add_run(" 页"), 8.5)


def cover(doc):
    for _ in range(3):
        para(doc, "", size=10)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(2)
    run_font(p.add_run("逆向工具使用手册"), 34, True, C_H1, cn=CN_HEAD)

    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.space_after = Pt(18)
    run_font(p.add_run("新增 12 件工具实操指南 · 全工具链速查 · 5 条端到端流程"), 12.5,
             False, C_H2)

    para(doc, "", size=8)
    table(doc,
          ["项目", "内容"],
          [["适用目录", "D:\\逆向工具网络安全汇总"],
           ["文档版本", "v1.0（2026-10-29）"],
           ["覆盖范围", "01 – 09 全部目录共 28 件工具 / 工程"],
           ["新增重点", "ImHex · PE-bear · ILSpy · SystemInformer · ScyllaHide · Apktool · "
                        "GDA · Il2CppDumper · capa · FLOSS · YARA · CyberChef"],
           ["事实来源", "全部命令、版本号、路径均为本机实测；原始采集见 _inventory.json / "
                        "_help.txt / _facts.txt / _demo.txt"],
           ["配套文档", "README.md（目录与安装说明）、逆向工具与方案汇总.doc（选型与 SOP）"],
           ["适用前提", "仅用于自有或已获书面授权的目标；文档内所有动态能力默认关闭，"
                        "需在授权范围内显式开启"]],
          widths=[3.0, 13.0], size=9.5)

    para(doc, "", size=8)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_font(p.add_run("— 本页之后请先看目录，再按「第 1 章 三分钟路线图」定位自己的场景 —"),
             9, False, RGBColor(0x80, 0x80, 0x80))
    doc.add_page_break()


def toc(doc):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(10)
    run_font(p.add_run("目　录"), 18, True, C_H1, cn=CN_HEAD)
    field(doc.add_paragraph(), 'TOC \\o "1-3" \\h \\z \\u',
          "（目录将在 Word 中自动生成：全选后按 F9，或右键「更新域」）")
    doc.add_page_break()


def ch1(doc):
    h1(doc, "第 1 章　这份手册怎么用")
    para(doc, "这不是一份「工具清单」，而是一份「拿到文件后手往哪放」的操作手册。全书分三层："
              "第 1–2 章解决环境与选型，第 3–10 章是一件工具一节的精讲（含可直接复制的命令与实测输出），"
              "第 11 章把工具串成 5 条端到端流程，第 12–14 章是排障、上传 git 与合规。")

    h2(doc, "1.1　三分钟路线图：先看目标，再看工具")
    table(doc,
          ["你手上的东西 / 你的目标", "第一件工具", "第一条命令（在本目录下执行）"],
          [["一个陌生文件，想 3 秒知道它是什么",
            "DIE", "`RE-Toolkit\\Start-DIE.cmd`　或 `diec -j <文件>`"],
           ["想看 PE 头、节表、导入导出、资源、改一个字段",
            "PE-bear / ImHex", "`RE-Toolkit\\Start-PE-bear.cmd`　`RE-Toolkit\\Start-ImHex.cmd`"],
           ["要反汇编、看函数树、跟交叉引用",
            "Cutter / Ghidra", "`RE-Toolkit\\Start-Cutter.cmd`　`RE-Toolkit\\Start-Ghidra.cmd`"],
           ["要脚本化批量处理（CI、批扫）",
            "rizin 命令行", "`call RE-Toolkit\\Start-Rizin.cmd` 后 `rizin -q -c \"aa; afl\" <文件>`"],
           ["一个 .NET 的 exe/dll，想看 C# 源码",
            "dnSpy / ILSpy", "`RE-Toolkit\\Start-dnSpy.cmd` / `Start-ILSpy.cmd`"],
           [".NET 程序要改逻辑再跑",
            "dnSpy（可编辑 IL）", "dnSpy → 右键方法 → Edit Method → 编译 → Save Module"],
           ["要跑起来、下断点、看内存、过反调试",
            "x64dbg + ScyllaHide", "`RE-Toolkit\\Start-x64dbg.cmd`，插件菜单开 ScyllaHide"],
           ["要看进程/线程/句柄/驱动，确认有没有被注入",
            "SystemInformer", "`02-Dynamic-Instrumentation\\Start-SystemInformer.cmd`"],
           ["Android APK：反编译资源与 smali",
            "apktool / GDA", "`06-Android-Mobile-RE\\apktool.cmd d app.apk -o out`"],
           ["Unity 手游（il2cpp）要还原类与方法名",
            "Il2CppDumper", "`06-Android-Mobile-RE\\Start-Il2CppDumper.cmd libil2cpp.so global-metadata.dat out`"],
           ["要在真机/模拟器上 hook、脱壳、抓参数",
            "Frida", "`call 02-Dynamic-Instrumentation\\frida\\env.cmd` 后 `frida -U -f <包名> -l hook.js`"],
           ["样本是恶意软件，要判断「能干什么」",
            "capa → FLOSS → YARA", "`call 07-Malware-Forensics\\env.cmd` 后 `capa.exe <样本>`"],
           ["一堆编码/加密数据要还原",
            "CyberChef", "`09-Data-Crypto-Tools\\Start-CyberChef.cmd`（浏览器打开 127.0.0.1:8765）"],
           ["要批量处理二进制字段、解析自定义格式",
            "Python 共享 venv", "`08-Python-RE-Toolchain\\.venv\\Scripts\\python.exe`（pefile / lief / capstone）"]],
          widths=[5.4, 3.6, 7.4], size=9)

    h2(doc, "1.2　全工具入口一览（版本号均为本机实测）")
    table(doc,
          ["工具 / 工程", "版本", "入口", "一句话用途"],
          [["DIE（Detect It Easy）", "3.21", "`RE-Toolkit\\Start-DIE.cmd`", "壳/编译器/链接器识别，任何样本的第一步"],
           ["ImHex", "1.38.1", "`RE-Toolkit\\Start-ImHex.cmd`", "Hex 编辑器 + .hexpat 结构化解析 + 一批 CLI 子命令"],
           ["PE-bear", "0.7.2", "`RE-Toolkit\\Start-PE-bear.cmd`", "PE 结构可视化，可改字段并回存"],
           ["Cutter", "2.5.0", "`RE-Toolkit\\Start-Cutter.cmd`", "rizin 的 GUI，反汇编 / 函数图 / 反编译视图"],
           ["rizin", "0.9.1（静态）", "`RE-Toolkit\\Start-Rizin.cmd`", "命令行反汇编 + 12 个 rz-* 工具，可脚本化"],
           ["Ghidra", "12.1.3 PUBLIC", "`RE-Toolkit\\Start-Ghidra.cmd`", "全量反编译 + 类型恢复，headless 可批处理"],
           ["dnSpyEx", "6.6.0", "`RE-Toolkit\\Start-dnSpy.cmd`", ".NET 反编译 + 编辑 IL + 回写程序集"],
           ["ILSpy", "11.2（self-contained）", "`RE-Toolkit\\Start-ILSpy.cmd`", ".NET 只读反编译，导出工程最省事"],
           ["x64dbg / x32dbg", "snapshot 2026-05-27", "`RE-Toolkit\\Start-x64dbg.cmd`", "用户态调试器；另有 headless.exe 可脚本调试"],
           ["ScyllaHide", "v1.4（2023-03-24）", "x64dbg「插件」菜单", "反反调试（已装进 x64dbg 的插件目录）"],
           ["SystemInformer", "4.0.26241.138", "`02-Dynamic-Instrumentation\\Start-SystemInformer.cmd`", "进程/线程/句柄/模块/内核对象查看"],
           ["Frida + frida-tools", "17.18.0 / 14.10.4", "`02-Dynamic-Instrumentation\\frida\\env.cmd`", "动态插桩：hook、脱壳、内存 dump"],
           ["unidbg", "0.9.10-SNAPSHOT", "`02-Dynamic-Instrumentation\\unidbg\\mvnw.cmd`", "无设备跑 Android ARM64 so"],
           ["LSPosed / Vector", "1.9.2 / 2.2", "Magisk / KernelSU 刷入", "Zygisk 注入框架，反检测与模块化改写"],
           ["Apktool", "3.0.3", "`06-Android-Mobile-RE\\apktool.cmd`", "APK 解包 / 重打包（自带 jdk25，不依赖系统 Java）"],
           ["GDA", "4.12", "`06-Android-Mobile-RE\\Start-GDA.cmd`", "免 Java 的 DEX 反编译（jadx 的替代）"],
           ["Il2CppDumper", "6.7.46", "`06-Android-Mobile-RE\\Start-Il2CppDumper.cmd`", "Unity il2cpp 元数据还原（dump.cs / il2cpp.h）"],
           ["capa", "10.0.0", "`07-Malware-Forensics\\env.cmd` → `capa.exe`", "能力识别 + ATT&CK 映射（内置规则库）"],
           ["FLOSS", "3.2.0", "同上 → `floss.exe`", "提取静态/栈/紧缩/解码字符串"],
           ["YARA", "4.6.0", "同上 → `yara64.exe` / `yarac64.exe`", "规则匹配，家族归类与批量筛查"],
           ["CyberChef", "11.5.0", "`09-Data-Crypto-Tools\\Start-CyberChef.cmd`", "编码/解码/加解密/解析的一条龙流水线"],
           ["Python 共享 venv", "3.12.10", "`08-Python-RE-Toolchain\\.venv\\Scripts\\python.exe`", "pefile / oletools / capstone / unicorn / keystone / lief / pyelftools"],
           ["ghidra-mcp / frida-mcp", "pyghidra 3.1.0", "MCP 服务（见 9.5）", "把 Ghidra / 设备操作暴露成工具调用"],
           ["REA / RevLab / rev.exe", "rea-agents 6.4.0 / 0.2.x / 0.1.0", "`03-Automation-Agents\\`", "证据账本、编排、自动化流水线"],
           ["Node.js / JDK", "24.16.0 / 25.0.4.1", "`04-Runtimes\\`", "REA 与 Ghidra 的运行时依赖"]],
          widths=[3.5, 3.0, 6.0, 4.2], size=8.5)

    h2(doc, "1.3　三条铁律（违反其中一条，工具就会静默失效）")
    bullets(doc, [
        ("别拆开搬单文件。", "ILSpy 是 self-contained 包，单独拷 ILSpy.exe 一定起不来；capa / FLOSS 是 "
                          "PyInstaller 单文件，但运行时会解包到 %TEMP%。搬动请整目录搬。"),
        ("别删三个 ASCII 联接。", "D:\\RE-JDK（Ghidra 找 JDK）、D:\\unidbg、D:\\Palantir_Research\\tools\\unidbg。"
                             "中文路径会让 Ghidra 的 java_home.save 解析成乱码。"),
        ("别在中文路径下自定义 hook 目录。", "本目录名含中文，实测 Qt / rizin / DIE / Python / Node 均无碍；"
                                 "但 Frida 脚本里若硬编码路径，请用 %TEMP% 或纯 ASCII 目录。"),
    ])


def ch2(doc):
    h1(doc, "第 2 章　环境准备（做一次，长期有效）")
    para(doc, "本目录刻意做成「便携式」：所有启动器都用 %~dp0 相对路径，双击即可，不需要改系统环境变量。"
              "只有命令行工具需要临时把目录塞进 PATH，共 3 个 env.cmd 入口。")

    h2(doc, "2.1　三个 PATH 入口")
    table(doc,
          ["入口脚本", "加进 PATH 的内容", "之后可直接使用的命令"],
          [["`07-Malware-Forensics\\env.cmd`", "capa\\ · FLOSS\\ · YARA\\",
            "`capa.exe`　`floss.exe`　`yara64.exe`　`yarac64.exe`"],
           ["`02-Dynamic-Instrumentation\\frida\\env.cmd`", "frida\\.venv\\Scripts · frida\\platform-tools",
            "`frida`　`frida-ps`　`frida-trace`　`frida-apk`　`adb`　`fastboot`　`sqlite3`"],
           ["`06-Android-Mobile-RE\\apktool.cmd`", "无需设置（脚本内部固定用 jdk25）",
            "`apktool.cmd d|b|if ...`"]],
          widths=[6.2, 5.0, 5.6], size=9)
    note(doc, "env.cmd 只影响「当前这个命令行窗口」。新开窗口要重新 call 一次；想永久生效请自己加到用户 PATH，"
              "但那样每次升级工具版本都要再改一次，不推荐。")

    h2(doc, "2.2　共享 Python venv（08-Python-RE-Toolchain）")
    para(doc, "一个 venv 供全部脚本使用，避免每个工具各自拉一份 numpy/pip 依赖。重建或修复都只跑一条命令：")
    code(doc, r"""powershell -ExecutionPolicy Bypass -File 08-Python-RE-Toolchain\setup-pyenv.ps1""")
    para(doc, "脚本会：建 .venv（Python 3.12.10）→ 安装下列库 → 逐个 import 自检（输出 7/7 imports OK 与 "
              "SETUP-FINISHED）→ 把 pip freeze 写入 requirements-lock.txt。PyPI 大 wheel 卡住时自动换清华镜像重试。")
    table(doc,
          ["库", "版本", "在逆向里干什么"],
          [["pefile", "2024.8.26", "解析 PE 头/节/导入导出/资源，批量扫描的骨架"],
           ["oletools", "—", "解析 OLE / VBA 宏（Office 恶意文档）"],
           ["capstone", "5.0.7", "反汇编引擎（x86/ARM/ARM64 全覆盖）"],
           ["unicorn", "2.1.4", "CPU 模拟执行，跑单段算法或解密函数"],
           ["keystone", "0.9.2", "汇编引擎，把补丁写成机器码"],
           ["lief", "1.0.0-d05b3499b", "PE/ELF/Mach-O 结构读写与重写（改节、加导入）"],
           ["pyelftools", "0.33", "ELF 段表/符号表/重定位读取（so 分析必备）"],
           ["objection", "1.12.5", "Frida 之上的自动化命令集（脱壳、SSL unpin）"],
           ["mitmproxy", "12.3.1", "PC 侧抓包/改包（配合设备代理）"]],
          widths=[2.6, 3.0, 11.2], size=9)
    note(doc, "08 的 venv 里也装了 frida（供 PC 侧写脚本用）。设备侧的 frida-server 与 02-Dynamic-Instrumentation\\frida "
              "里的 17.18.0 是严格配对的，做脱壳/hook 请统一用 02 那一套；只写 PC 侧小工具时才用 08 的。")

    h2(doc, "2.3　运行时（04-Runtimes）")
    bullets(doc, [
        ("Node.js v24.16.0", "——REA / 部分 MCP 服务依赖。注意该目录子项 ACL 属主为 SYSTEM，npm -g 全局安装可能因"
                          "写权限失败，装包请用项目内 node_modules。"),
        ("Temurin JDK 25.0.4.1", "——Ghidra 要求 ≥21；apktool.cmd 也用这份 JDK 跑 jar，所以本机不需要另装 Java。"),
        ("系统 JAVA_HOME 是脏值", "（指向已不存在的 C:\\Java\\jdk1.8.0_201）。Ghidra 不读它，apktool.cmd 也不读它，"
                             "不影响使用；但如果你要在命令行手动跑 jar，请显式指定 "
                             "04-Runtimes\\jdk25\\bin\\java.exe。"),
    ])

    h2(doc, "2.4　五分钟自检（换机器 / 搬家之后跑一遍）")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
> call 07-Malware-Forensics\env.cmd
> capa.exe -h | findstr /i "capa"        :: 期望看到 capa.exe [-h] ... 的 usage
> floss.exe --version                     :: 3.2.0
> yara64.exe --version                    :: 4.6.0

> call 02-Dynamic-Instrumentation\frida\env.cmd
> frida --version                         :: 17.18.0
> adb version                             :: Android Debug Bridge 1.0.41

> 06-Android-Mobile-RE\apktool.cmd if <任意.apk>   :: 期望打印 apktool / framework 版本
> 08-Python-RE-Toolchain\.venv\Scripts\python.exe -c "import pefile,capstone,unicorn,keystone,lief,elftools,oletools;print('venv ok')"
> 04-Runtimes\jdk25\bin\java.exe -version          :: openjdk 25.0.4.1
> RE-Toolkit\Start-Ghidra.cmd                      :: 能进 GUI 即说明 JDK 解析正常""")
    note(doc, "如果第 8 条（Ghidra）报 “JDK 21+ (64-bit) could not be found”，99% 是 D:\\RE-JDK 联接被删了，"
              "用 mklink /J 重建即可，不要去装 JDK。")


def ch3(doc):
    h1(doc, "第 3 章　静态分析：先看清文件长什么样")
    para(doc, "顺序永远是「先识别、再看结构、最后才反汇编」。跳过前两步直接上 Ghidra，是把时间浪费在"
              "早就写在文件头里的信息上。")

    # ---------------- DIE ----------------
    h2(doc, "3.1　DIE 3.21 — 三秒钟定性")
    para(doc, "任何文件的第一步。GUI 用法：`RE-Toolkit\\Start-DIE.cmd` → 把文件拖进窗口 → 左侧列出的 "
              "filetype / compiler / linker / tool / packer 就是结论。批量和脚本化用命令行：")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总\01-Disassembly-Debug\RE-Toolkit\DIE
> diec.exe -j  <样本>            :: JSON，最适合喂给脚本
> diec.exe -e  <样本>            :: 附带每个节区的熵
> diec.exe -i  <样本>            :: 附带文件信息
> diec.exe -d  -u <样本>         :: 深度扫描 + 启发式（加壳判断更准，但更慢）
> diec.exe -r  <目录>            :: 递归扫一整个目录
> diec.exe -S Hash#MD5 <样本>    :: 只要某一个结构字段""")
    para(doc, "-j 的输出结构固定，脚本里直接取三个位置就够：")
    code(doc, r"""{
  "detects": [{
    "filetype": "PE64",                     <- 是什么格式
    "values": [
      { "type": "linker",   "string": "Linker: Microsoft Linker(14.27.29120)" },
      { "type": "compiler", "string": "Compiler: Microsoft Visual C/C++(19.30.30795)[C]" },
      { "type": "tool",     "string": "Tool: Microsoft Visual Studio(2019, 16.7-16.8)" },
      { "type": "debug data","string": "Debug data: Records[codeview]" }
    ]}]}""")
    para(doc, "上面这段是 ScyllaHide 自带的 ScyllaTest_x64.exe 的真实输出，可以直接拿来对照自己的输出是否正常："
              "有 linker + compiler + VS 版本 + codeview 调试记录，说明是正常编译产物、未加壳。")
    para(doc, "熵怎么读（-e 的真实输出）：")
    code(doc, r"""Total 6.28667: not packed
  1|Section (1) [".text"]|1024|124416|6.53734: packed""")
    note(doc, "别被 .text 那行 “packed” 吓到。代码段本身熵就高（6.5 左右很常见），DIE 的判断是逐节的工具提示；"
              "真正要看的是 Total 一行的结论，以及「.text/.rdata 熵接近 8.0 且节名异常（UPX0/UPX1/.boom）」这类组合。")

    # ---------------- ImHex ----------------
    h2(doc, "3.2　ImHex 1.38.1 — Hex 编辑器 + 结构化解析")
    para(doc, "GUI：`RE-Toolkit\\Start-ImHex.cmd`（或直接 `ImHex\\imhex-gui.exe <文件>`）。它不是单纯的 010 Editor 替代品，"
              "三个功能最值钱：")
    bullets(doc, [
        ("Pattern Language（.hexpat）", "：把任意二进制格式写成结构体脚本，右侧实时显示解析结果。"
                                    "改文件格式、算偏移、批量提取字段全靠它。"),
        ("Data Inspector / 数据处理器", "：任意偏移处按 int/float/时间戳/编码解读；内置 XOR、Base64、ROT、"
                                "Gzip 等变换链。"),
        ("批量修补与差异", "：块选择、填充、复制粘贴十六进制，配合 Bookmarks 记录每处修改。"),
    ])
    para(doc, "它同时提供了一批 CLI 子命令（本机实测可用，直接替代临时写 python 脚本）：")
    table(doc,
          ["子命令", "用途", "实测示例与输出"],
          [["`--hash <算法> <文件>`", "md5/sha1/sha256/sha384/sha512",
            "`sha256(...) = 14BB3A9CD3BF047D228DF45D91A2D92F9367B44E6138F7E787BF902F4840FFBE`"],
           ["`--hexdump <文件> <off> <size>`", "指定区间生成 hexdump",
            "`--hexdump PE-bear.exe 0 64` → `00000000  4D 5A 90 00 ... MZ..............`"],
           ["`--calc \"<表达式>\"`", "进制/算术换算", "`--calc 0x30*2` → `96`"],
           ["`--encode base64|hex <串>`", "编码", "`--encode base64 hello` → `aGVsbG8=`"],
           ["`--decode base64|hex <串>`", "解码", "同参数"],
           ["`--demangle <符号>`", "C++ 符号还原", "`--demangle _Z3fooi` → `foo(int)`"],
           ["`--magic mime|desc <文件>`", "按 libmagic 猜类型", "**本机不可用**，见下方注意"],
           ["`--pl format|run|docs|info`", "命令行跑 .hexpat 脚本", "`imhex --pl -h` 看子命令"]],
          widths=[5.0, 4.4, 7.4], size=8.5)
    note(doc, "本机 `--magic` 报 “Failed to compile magic database!”（portable 包未带 magic 库）。"
              "判断文件类型请直接用 DIE 或 PE-bear，不要在这上面耗时间。")

    # ---------------- PE-bear ----------------
    h2(doc, "3.3　PE-bear 0.7.2 — PE 结构专用放大镜")
    para(doc, "启动：`RE-Toolkit\\Start-PE-bear.cmd`。左侧树按 PE 的真实层级排列，双击节点即跳到对应偏移：")
    table(doc,
          ["节点", "看什么", "典型问题"],
          [["DOS Header / File Header", "Machine、NumberOfSections、TimeDateStamp、Characteristics",
            "时间戳可疑、节数异常（>10）"],
           ["Optional Header", "AddressOfEntryPoint、ImageBase、Subsystem、DllCharacteristics",
            "入口点落在最后一个节（加壳）"],
           ["Data Directories", "导入表 / 重定位 / TLS / 资源 / 延迟导入的大小与 RVA",
            "导入表被抹掉但函数还在用"],
           ["Sections", "RawSize vs VirtualSize、熵、权限（RWX）", "RWX 节、RawSize=0（运行期解压）"],
           ["Imports / Exports", "函数名与所在 DLL", "只有 LoadLibrary/GetProcAddress 两个导入"],
           ["Resources / Manifest", "图标、版本信息、清单", "伪装成合法软件的版本信息"],
           ["Debug / TLS / Load Config", "PDB 路径、TLS 回调、CFG", "TLS 回调里藏 shellcode"]],
          widths=[4.2, 7.6, 5.0], size=9)
    para(doc, "PE-bear 支持直接编辑字段：改完按 Ctrl+S 存盘（建议另存为目标副本）。常用于「把 "
              "Characteristics 里的 DLL 位去掉」「修 RawSize 让节被正确映射」这类小手术；"
              "更复杂的改写（加节、改导入表）交给 Python + lief。")
    para(doc, "PE-bear 还自带 sig 库（`PE-bear\\SIG.txt`）与 YARA 式特征，可用来辅助判断编译器/加壳器，作用与 DIE 重叠，"
              "二选一即可。")


def ch4(doc):
    h1(doc, "第 4 章　反汇编层：Cutter / rizin / Ghidra")
    para(doc, "三者是同一件事的三种形态：Cutter 是 rizin 的 GUI，rizin 是命令行，Ghidra 是"
              "自带反编译器的重型平台。日常选择：看结构与快速定位用 Cutter，批处理与管道用 rizin，"
              "要「伪 C 代码」时上 Ghidra。")

    # ---------------- Cutter ----------------
    h2(doc, "4.1　Cutter 2.5.0 — 打开就能用的图形反汇编")
    para(doc, "启动：`RE-Toolkit\\Start-Cutter.cmd`（内部已带 rizin 0.9.1，无需另装）。打开文件后先让分析跑完"
              "（右下角进度条结束），再开始看。界面四个区域：")
    table(doc,
          ["区域", "内容", "怎么用"],
          [["左侧面板", "Functions / Symbols / Imports / Strings / Sections",
            "双击跳转；搜索框支持函数名与字符串过滤"],
           ["中间 Disassembly", "指令列表 + 注释", "右键可得 Xrefs（谁引用我）、Rename、Add Comment"],
           ["右侧 Graph", "函数控制流图", "空格或视图切换按钮在「列表 ↔ 图」间切换"],
           ["底部 Console", "rizin 命令直接输入", "所有 GUI 操作都能在这里用命令复现（可复制进脚本）"]],
          widths=[3.6, 6.2, 7.0], size=9)
    bullets(doc, [
        ("推荐顺序：", "Sections 看有没有异常节 → Imports 看是否只有 LoadLibrary/GetProcAddress → "
                    "Strings 搜域名/路径/错误信息 → 从 main 或 WinMain 顺着往下看。"),
        ("想保存工作成果：", "File → Save Project，得到一个 .rzdb 工程，下次直接打开，注释与命名都在。"),
        ("需要伪 C：", "Cutter 的 Decompiler 面板依赖额外插件，本机未装；要伪 C 请直接用 Ghidra（4.3）。"),
    ])

    # ---------------- rizin ----------------
    h2(doc, "4.2　rizin 0.9.1 — 全部可脚本化")
    para(doc, "`RE-Toolkit\\Start-Rizin.cmd` 会把 `Rizin\\bin` 加进 PATH，之后 `rizin`、`rz-bin`、`rz-asm` 等 12 个工具直接可用：")
    code(doc, r"""rz-bin, rz-ar, rz-asm, rz-ax, rz-bin, rz-diff, rz-find, rz-gg,
rz-hash, rz-run, rz-sign, rz-test          (Rizin\bin 下的全部可执行文件)""")
    h3(doc, "4.2.1　rz-bin：不开分析引擎的「只看结构」")
    code(doc, r"""> rz-bin -I   <文件>        :: 基本信息（arch/bits/os/compiler/stripped/overlay…）
> rz-bin -i   <文件>        :: 导入表
> rz-bin -S   <文件>        :: 节表
> rz-bin -z   <文件>        :: 数据段字符串
> rz-bin -zz  <文件>        :: 全文件原始字符串（加壳样本用这个）
> rz-bin -K sha256 <文件>   :: 只要哈希
> rz-bin -j -z -N 6:120 <文件>   :: JSON + 只留 6~120 字符的串（喂脚本最稳）""")
    para(doc, "-I 的真实输出（节选）能一次性回答「这是什么、多大、有没有符号、是否 stripped」：")
    code(doc, r"""arch  x86        bits  64        bintype pe      class PE32+
baddr 0x140000000  binsz 0x00032600 compiler Linker 14.27
os    windows      subsys Windows GUI  stripped false   havecode true
overlay false      dbg_file ScyllaTest_x64.pdb""")
    h3(doc, "4.2.2　rizin：交互 + 一行命令出结果")
    code(doc, r"""> rizin -q -c "aa; afl" <文件>                      :: 分析 + 列全部函数
> rizin -q -c "aa; s sym.main; pdf" <文件>           :: main 的反汇编
> rizin -A -q -c "iz~http" <文件>                    :: 分析后过滤含 http 的字符串
> rizin -q -c "s 0x140001000; px 64" <文件>          :: 指定地址看 64 字节
> rizin <文件>                                       :: 进交互模式，命令同上""")
    bullets(doc, [
        ("aa / aaa", "——基础分析 / 更激进的分析（慢但函数更全）。"),
        ("afl / afll", "——函数列表 / 带更多列的列表。"),
        ("pdf / pdc", "——函数反汇编 / 函数伪反编译（pdc 输出较粗糙，正式用 Ghidra）。"),
        ("axt / axf", "——谁调用我 / 我调用谁（交叉引用）。"),
        ("i / ii / iz / is", "——文件信息 / 导入 / 字符串 / 符号。"),
    ])
    h3(doc, "4.2.3　其余 rz-* 工具（都在 Rizin\\bin）")
    table(doc,
          ["工具", "用途", "示例"],
          [["`rz-asm`", "汇编 / 反汇编单段字节", "`rz-asm -a x86 -b 64 -d 554889e5`（-d = 反汇编 hexpairs）"],
           ["`rz-hash`", "批量算哈希", "`rz-hash -a sha256 -a md5 <文件>`"],
           ["`rz-find`", "二进制搜索", "`rz-find -x 4d5a <文件>`（-x = 十六进制串）"],
           ["`rz-diff`", "两个文件/函数的差异", "`rz-diff -C <a> <b>`"],
           ["`rz-sign`", "生成 FLIRT 签名（识别库函数）", "`rz-sign -h` 看参数"],
           ["`rz-gg`", "shellcode 生成与编码", "`rz-gg -h` 看参数"],
           ["`rz-ax`", "进制转换（命令行计算器）", "`rz-ax 0x10` / `rz-ax -s hello`"],
           ["`rz-run`", "带环境/重定向跑程序", "调试前的启动条件复现"]],
          widths=[2.4, 6.4, 8.0], size=8.8)
    note(doc, "本机实测 `rizin.exe --version` 会挂住（等标准输入），脚本里判断版本请用 `rz-bin -v`，"
              "输出为 `rz-bin 0.9.1 @ windows-x86-64` + commit id。")

    # ---------------- Ghidra ----------------
    h2(doc, "4.3　Ghidra 12.1.3 PUBLIC — 要伪 C 就用它")
    para(doc, "GUI：`RE-Toolkit\\Start-Ghidra.cmd` → New Project（非共享）→ 拖入文件 → 弹出 Auto Analyze 选 Yes（默认选项即可）。"
              "分析完成后双击函数，右侧就是 Decompiler 视图。")
    bullets(doc, [
        ("改类型/改名：", "Decompiler 里对变量按右键 → Retype / Rename，反编译结果会立刻变清晰，这是 Ghidra 最值钱的操作。"),
        ("找引用：", "指令上右键 → References → Show References to，等价于 IDA 的 X。"),
        ("导出：", "File → Export Program，可选 C header / ASCIItable 等；伪 C 直接 Ctrl+A 复制。"),
    ])
    para(doc, "批处理（无界面、可写进流水线）：")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总\01-Disassembly-Debug\Ghidra\support
> analyzeHeadless.bat D:\ghidra_proj MyProj -import <目标文件> ^
      -postScript <脚本.java> -scriptPath <脚本目录> -deleteProject
:: 只想先入库、不跑脚本：去掉 -postScript/
:: 追加分析已入库的文件：-process <程序名> -noanalysis""")
    note(doc, "Ghidra 找 JDK 走的是 %APPDATA%\\ghidra\\ghidra_12.1.3_PUBLIC\\java_home.save（按平台编码读），"
              "所以启动脚本里指向的是 ASCII 联接 D:\\RE-JDK。若报 “JDK 21+ (64-bit) could not be found”，"
              "重建 D:\\RE-JDK 联接即可，不要改 JAVA_HOME。")
    para(doc, "本机已有工程可直接打开：`05-Cases\\GhidraProjects\\lki`。")


def ch5(doc):
    h1(doc, "第 5 章　.NET 逆向：dnSpy 与 ILSpy 的分工")
    para(doc, "两个工具都能把 .NET 程序集反编译成 C#，区别只有一句话：**ILSpy 只读，dnSpy 能改**。"
              "先判断目标是不是 .NET：DIE 会给出 `PE64 .NET` 之类的结论，或看导入表里有没有 `mscoree.dll` / `_CorExeMain`。")

    h2(doc, "5.1　怎么选")
    table(doc,
          ["需求", "用哪个", "理由"],
          [["只想读懂逻辑、做代码审计", "ILSpy 11.2", "反编译质量高，可一键导出完整 .csproj 工程，便于全局搜索"],
           ["要改一行判断、去掉校验、换掉密钥", "dnSpy 6.6.0", "能直接编辑方法体（C# 或 IL）并写回程序集"],
           ["要下断点跟运行时", "dnSpy 6.6.0", "自带调试器，可对 IL 单步（对反调试弱的 .NET 程序很好用）"],
           ["要对比两个版本的差异", "ILSpy + 导出工程 + git diff", "dnSpy 不擅长做差异"]],
          widths=[5.6, 3.4, 7.8], size=9)

    h2(doc, "5.2　dnSpy 6.6.0：改逻辑的完整流程")
    para(doc, "启动：`RE-Toolkit\\Start-dnSpy.cmd`（也可 `dnSpy.exe <目标.exe>` 直接打开）。")
    code(doc, r"""① File → Open        打开 exe/dll（同目录的依赖会自动进 Assembly Explorer）
② 左侧树             程序集 → 命名空间 → 类型 → 方法，单击任意方法右侧立即出 C#
③ 定位关键逻辑        底部 Search：搜字符串 / 方法名 / 数字常量（"License"、"Trial"、0x1C 等）
④ 改代码              右键方法 → Edit Method (C#) 或 Edit Method (IL)
⑤ 编译并保存          编辑器里点 Compile（失败会在下方列出错误行）
⑥ File → Save Module 另存为新文件；默认写回原文件名，请先备份原件""")
    bullets(doc, [
        ("改 C# 报错时：", "切到 Edit Method (IL) 直接改指令，改 IL 的容错率更高。"),
        ("强名称问题：", "带强名称的程序集改完可能加载失败。分析验证用没问题；要在生产环境长期使用，"
                    "需要重新签名（本机未装 .NET SDK，可用另一台机器上的 sn.exe 处理）。"),
        ("混淆过的程序集：", "类名/方法名是乱码时，先用 ILSpy 看字符串与调用关系，再回 dnSpy 精改；"
                      "本目录没有 de4dot，需要自动去混淆要另装。"),
        ("只想知道某个值怎么算：", "不必改程序，用 dnSpy 的调试器在目标方法下断点，改寄存器/局部变量更快。"),
    ])

    h2(doc, "5.3　ILSpy 11.2：只读审计与导出工程")
    para(doc, "启动：`RE-Toolkit\\Start-ILSpy.cmd`。注意这是 **self-contained 版本**（自带 .NET 运行时，约 55 MB），"
              "本机没装 .NET 也能跑；单独拷 `ILSpy.exe` 到别处一定失败。")
    code(doc, r"""① File → Open            选 exe/dll（或把文件拖进窗口）
② 左上角视图切换         C# / IL / ReadyToRun 三种视图，排查「编译器优化后实际执行什么」看 IL
③ 定位                  顶部搜索框支持类型、方法、字符串、常量
④ 导出                  右键程序集 → Save Code，生成可直接 dotnet build 的 .csproj 工程
⑤ 审计                  导出的工程丢进 IDE / git，全局搜索 + 差异对比都在这里做""")
    note(doc, "ILSpy 的这个 release 包只有 GUI（`ILSpy.exe`），没有 `ilspycmd` 命令行版本。要批量化反编译，"
              "请用 Python + `dnlib`/`Mono.Cecil` 另写脚本，或直接用 ILSpy 的 Save Code 导出后批量 grep。")


def ch6(doc):
    h1(doc, "第 6 章　动态调试与反反调试")
    para(doc, "静态分析回答「代码长什么样」，动态分析回答「它实际做了什么」。本章三件工具配合使用："
              "x64dbg 负责停下来看，ScyllaHide 负责让程序「以为没人看」，SystemInformer 负责看全系统。")

    h2(doc, "6.1　x64dbg / x32dbg：用户态调试器")
    para(doc, "启动：`RE-Toolkit\\Start-x64dbg.cmd` 或 `Start-x32dbg.cmd`（32 位目标必须用 x32dbg，"
              "否则插件与调用约定都会错）。File → Open 载入目标，或直接把 exe 拖进窗口。")
    table(doc,
          ["操作", "键 / 入口", "说明"],
          [["运行 / 暂停", "F9", "从入口点开始跑；再次按下会在暂停处停"],
           ["下断点", "F2（光标所在指令）", "或用底部命令框 `bp <模块>.<函数名>` / `bp <地址>`"],
           ["单步进入 / 跳过", "F7 / F8", "跟 call 进函数用 F7，只想越过用 F8"],
           ["执行到返回", "Ctrl+F9", "从一个函数里快速回到调用者"],
           ["看/改内存", "右键 → Follow in Dump；命令 `db <地址>` / `dump <地址>`",
            "改数据用 `eb <地址> <字节>`，改寄存器在右侧 Registers 面板双击"],
           ["看调用栈", "Call Stack 面板", "判断当前处于哪条执行路径最快的方式"],
           ["看模块/句柄/线程", "顶部对应面板", "查注入 DLL、异常线程最直接"]],
          widths=[3.6, 6.6, 6.6], size=9)
    bullets(doc, [
        ("无界面脚本调试：", "`release\\x64\\headless.exe` 与 `release\\x32\\headless.exe` 可以在不开窗口的情况下"
                       "加载程序与脚本，适合放进自动化流水线。"),
        ("符号：", "`release\\x64\\pdb\\` 里有约 19 个 PDB（含 ntdll/kernel32 等），能直接看到系统 API 名字；"
                "目标自带的 PDB 放到目标同目录即可自动加载。"),
        ("载入即退出/直接崩：", "九成是反调试或 TLS 回调。先在「插件 → ScyllaHide」里开一套 profile，再重新载入。"),
    ])

    h2(doc, "6.2　ScyllaHide v1.4：反反调试")
    para(doc, "它已经装进 x64dbg（三个文件复制到了 `RE-Toolkit\\x64dbg\\release\\x{64,32}\\plugins\\`）：")
    code(doc, r"""release\x64\plugins\ScyllaHideX64DBGPlugin.dp64
release\x64\plugins\HookLibraryx64.dll
release\x64\plugins\scylla_hide.ini""")
    code(doc, r"""① x64dbg 菜单「插件」→ ScyllaHide → Options
② Profile 下拉框选目标对应的保护方案（VMProtect / Themida / 通用 …），或逐项勾选
   （常见需要：PEB.BeingDebugged / NtQueryInformationProcess / NtSetInformationThread /
     NtQuerySystemInformation / OutputDebugString / 时间戳控制 / DRx 清寄存器）
③ 确定后重新「File → Open」载入目标（设置只对之后启动/附加的进程生效）""")
    para(doc, "对**已经在跑**的进程注入（不需要 x64dbg 介入）：")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总\02-Dynamic-Instrumentation\ScyllaHide
> InjectorCLIx64.exe            :: 不带参数运行会打印用法
> InjectorCLIx64.exe pid:<PID>  :: 按 ScyllaHide.ini 里的配置注入指定进程""")
    note(doc, "注入要在进程「刚起来、还没检测」时完成；如果目标已经退出，说明检测发生在更早的 TLS 回调里，"
              "改用 x64dbg 在入口点前断下（Options → Events 勾选 TLS Callbacks）。")
    para(doc, "ScyllaHide 目录里还有 `IDA\\`、`Olly1\\`、`Olly2\\`、`TitanEngine\\`、`Generic\\` 五套插件与 "
              "`ScyllaTest_x64.exe` / `ScyllaTest_x86.exe` 两个自检样本——后者是**验证反反调试是否生效**最快的办法："
              "开着 ScyllaHide 跑 ScyllaTest，若它能正常启动就说明配置有效。")

    h2(doc, "6.3　SystemInformer 4.0.26241.138：系统全貌")
    para(doc, "启动：`02-Dynamic-Instrumentation\\Start-SystemInformer.cmd`（**建议右键以管理员运行**，否则驱动与句柄信息不全）。"
              "它的定位是「任务管理器的完全体」：")
    table(doc,
          ["视图", "逆向里的用途"],
          [["Processes（树状）", "看父子关系与完整路径；高亮色标出新建/退出的进程，便于抓一闪而过的 loader"],
           ["进程属性 → Modules", "列出所有已加载 DLL，找**路径可疑 / 无签名 / 从内存加载**的模块"],
           ["进程属性 → Threads", "看每个线程的起始地址；起始地址落在非模块区域＝典型的远程注入线程"],
           ["进程属性 → Handles", "看句柄表，判断进程在操作哪些文件、注册表键、互斥体"],
           ["进程属性 → Memory", "列出内存区域及其保护属性，RWX 且无映射文件＝可疑，可直接右键 dump"],
           ["Drivers / Kernel", "看内核驱动与服务，查 rootkit 常驻点（需驱动支持）"],
           ["Network", "把连接映射到进程，定位回连 C2"]],
          widths=[4.2, 12.2], size=9)
    para(doc, "与 x64dbg 的分工：先用 SystemInformer 判断「异常在哪个进程/线程/内存区域」，再决定把调试器附加到谁身上。"
              "它是排查注入、隐藏进程、可疑驱动最快的入口。")


def ch7(doc):
    h1(doc, "第 7 章　Android 代码层：apktool / GDA / Il2CppDumper")
    para(doc, "Android 逆向按「目标是什么」分两条完全不同的路：**Java/DEX 层**（apktool + GDA）和 "
              "**原生 il2cpp 层**（Il2CppDumper + Ghidra）。先确定目标属于哪一种：解包后看有没有 "
              "`lib/<abi>/libil2cpp.so` 和 `assets/bin/Data/Managed/Metadata/global-metadata.dat`。")

    h2(doc, "7.1　Apktool 3.0.3：解包、改、重打包")
    para(doc, "`06-Android-Mobile-RE\\apktool.cmd` 内部固定调用 `04-Runtimes\\jdk25\\bin\\java.exe`，"
              "所以本机不需要装 Java，也不用管 JAVA_HOME。三条命令覆盖全部日常：")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
> 06-Android-Mobile-RE\apktool.cmd if  app.apk                  :: 打印 apktool 与 framework 版本（自检用）
> 06-Android-Mobile-RE\apktool.cmd d   app.apk -o out -f       :: 解包到 out\（-f 覆盖已存在目录）
> 06-Android-Mobile-RE\apktool.cmd b   out -o patched.apk      :: 重新打包""")
    para(doc, "解包出来的目录结构（实测 manager.apk 的结果，可直接对照）：")
    code(doc, r"""out\
├─ AndroidManifest.xml      已解码成可读 XML（原包里是二进制 AXML）
├─ apktool.yml              重建所需的元信息（版本、是否 debug、so 处理方式）
├─ smali\                   classes.dex 反汇编成 smali（多 dex 会是 smali smali_classes2 …）
├─ res\                     资源（layout/drawable/values…，values 已反编译成 XML）
├─ assets\  original\       原样保留的资产与原始清单
└─ unknown\                 未知类型文件""")
    bullets(doc, [
        ("只想快速看代码（跳过资源）：", "`apktool.cmd d app.apk -o out -r` —— `-r`（--no-res）不解资源，"
                                  "速度快很多，也能绕开部分资源兼容问题。"),
        ("只要资源、不解 dex：", "`-s`（--no-src）。两个都加等于只抄一份原包，一般没意义。"),
        ("第一次解码报 framework 相关错误：", "删掉 `%LOCALAPPDATA%\\apktool\\framework\\1.apk` 让它重新生成。"),
        ("改完的 smali 要重签：", "`apktool b` 出来的 apk 是**未签名**的，必须签名后才能安装（见下）。"),
    ])
    para(doc, "签名（用 jdk25 自带的 keytool / jarsigner，不需要 Android SDK）：")
    code(doc, r"""> set JAVA=D:\逆向工具网络安全汇总\04-Runtimes\jdk25\bin
> %JAVA%\keytool -genkeypair -keystore re.jks -alias re -keyalg RSA -keysize 2048 ^
       -validity 10000 -storepass 123456 -keypass 123456 -dname "CN=re"
> %JAVA%\jarsigner -keystore re.jks -storepass 123456 -keypass 123456 patched.apk re""")
    note(doc, "jarsigner 只能做 **v1（JAR）签名**。Android 11 及以上要求 v2/v3 签名才能安装，"
              "所以 `b` 出来的包在真机上可能装不上。两种处理：① 静态分析到 smali 就够了，不必安装；"
              "② 需要真机验证时，用 Android SDK 的 `apksigner`（本目录未包含 build-tools）或 "
              "uber-apk-signer 重签，或者直接对**已安装的原版**用 Frida 附加。")

    h2(doc, "7.2　GDA 4.12：免 Java 的 DEX 反编译")
    para(doc, "启动：`06-Android-Mobile-RE\\Start-GDA.cmd`。它是原生 Windows 程序（不需要 Java），"
              "对加壳/异常 dex 的容忍度比 jadx 高，适合「先把代码看明白」。")
    bullets(doc, [
        ("打开：", "File → Open 选 apk/dex；也可以把 apk 拖进去。"),
        ("三视图：", "Java 源码视图（近似反编译）、smali 视图、清单视图，可随时切换对照。"),
        ("定位：", "左侧类树 + 全局搜索（字符串、方法名、类名）；找到后右键看「引用/被引用」。"),
        ("导出：", "菜单里可导出反编译源码或 smali，便于丢进编辑器全局搜索。"),
        ("so 文件：", "GDA 也能打开 so 看导出表与字符串，但正式分析请用 Ghidra/Cutter。"),
    ])

    h2(doc, "7.3　关于 jadx：本目录里是空目录")
    para(doc, "`01-Disassembly-Debug\\jadx` 目前**是空的**（未安装）。原因是 jadx 需要额外拉 zip 并配 JDK，"
              "而本目录已有 GDA 覆盖「DEX → Java」这一需求。要补装：下载 jadx 的 zip 解压到该目录，"
              "然后用 `04-Runtimes\\jdk25\\bin\\java.exe -cp jadx\\lib\\* jadx.cli.JadxCLI --version` 验证。"
              "在那之前，本文档里所有「看 Java 源码」的地方请用 GDA。")

    h2(doc, "7.4　Il2CppDumper 6.7.46：Unity il2cpp 符号还原")
    para(doc, "Unity 的 C# 代码在 il2cpp 模式下被 AOT 编译进 `libil2cpp.so`（Windows 上是 `GameAssembly.dll`），"
              "真正的类名/方法名被抽到 `global-metadata.dat`。Il2CppDumper 把两半合起来，恢复出 "
              "`dump.cs`（可读的类与方法签名）+ `il2cpp.h`（给反编译器用的结构体）。")
    para(doc, "**参数顺序是第一个坑**（实测 usage 输出）：")
    code(doc, r"""> 06-Android-Mobile-RE\Il2CppDumper\Il2CppDumper.exe <executable-file> <global-metadata> <output-directory>

:: 例：从自己解包出来的 apk 目录里取
> 06-Android-Mobile-RE\Start-Il2CppDumper.cmd ^
      out\lib\arm64-v8a\libil2cpp.so ^
      out\assets\bin\Data\Managed\Metadata\global-metadata.dat ^
      dump_out""")
    bullets(doc, [
        ("输出物：", "`dump.cs`（类/字段/方法签名与 RVA）、`il2cpp.h`、`script.json`、`stringliteral.json`、"
                 "`DummyDll\\`（可用 dnSpy/ILSpy 直接打开看类型结构）。"),
        ("接到 Ghidra：", "用 Il2CppDumper 自带的 `ghidra_with_struct.py`，在 Ghidra Script Manager 里加载，"
                     "指定 `script.json` 与 `il2cpp.h`，函数名与结构体就都恢复出来了。"),
        ("接到 IDA：", "同目录的 `ida_with_struct.py`，流程一致。"),
        ("32 位目标：", "包里的 `-x86` 版本用于 32 位 il2cpp（armeabi-v7a/x86）。"),
        ("拿不到 metadata：", "若 dumper 报 metadata 魔数错误，说明 metadata 被加密/加固，需要先在设备上"
                        "用 Frida 在 `il2cpp_init` 之后 dump 内存中的 metadata，再喂给 dumper。"),
    ])
    note(doc, "Start-Il2CppDumper.cmd 只是把参数转给 exe（`start \"\" Il2CppDumper.exe %*`），"
              "所以参数顺序必须以本文档为准；旧注释里写的顺序是错的，已在本版修正。")


def ch8(doc):
    h1(doc, "第 8 章　动态插桩：Frida / unidbg / LSPosed")
    para(doc, "这三件工具解决同一个问题的三种处境：**有设备**（Frida）、**不想/不能有设备**（unidbg）、"
              "**要在进程启动前就介入**（LSPosed）。")

    h2(doc, "8.1　Frida 17.18.0：最常用的那一个")
    para(doc, "先打开一个命令行窗口，把 frida 与 adb 放进 PATH：")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
> call 02-Dynamic-Instrumentation\frida\env.cmd
> adb devices                                   :: 看到设备号才继续
> frida-ps -U | findstr /i 目标关键字            :: 列出设备上的应用与进程""")
    h3(doc, "8.1.1　三条最常用的命令")
    code(doc, r""":: ① 以 spawn 方式启动应用并注入脚本（启动即 hook，关键调用不会被漏掉）
> frida -U -f com.example.app -l hooks\api_probe.js --no-pause

:: ② 附加到已在运行的进程（应用已启动、只关心后续行为）
> frida -U -n com.example.app -l hooks\trace_native.js

:: ③ 只跟踪某类调用，先看清楚再写脚本（-i 可重复，支持通配符）
> frida-trace -U -f com.example.app -i "open*" -i "recv*" -i "AES_*"
""")
    note(doc, "`--no-pause` 表示注入后立即恢复运行；省略它应用会停住，需要回终端按 Enter 或 `%resume` 才继续。"
              "第一次用建议不要加，停在注入点先确认脚本没报错。")
    h3(doc, "8.1.2　随附的 12 个 hook 脚本（frida\\hooks\\）")
    para(doc, "每个脚本只回答一个问题，先跑脚本看清现状，再决定要不要写自己的：")
    table(doc,
          ["脚本", "回答什么问题"],
          [["`api_probe.js`", "目标调用了哪些敏感 API（文件/网络/加密/反射）"],
           ["`anti_debug_probe.js`", "有没有反调试（ptrace、调试状态、时间差）"],
           ["`root_bypass_arm64.js`", "怎么绕过 root 检测（ARM64 主流检测点）"],
           ["`dump_dex.js` / `dump_dex_art.js` / `dump_dex_write.js`", "内存里已加载的 dex 怎么落盘（三条不同路线）"],
           ["`jni_boundary.js`", "Java 与 native 的边界在哪（JNI 调用参数/返回值）"],
           ["`module_map_probe.js`", "进程里加载了哪些模块、谁从内存加载"],
           ["`native_profile_arm64.js`", "native 层主要函数热度（先定位热点再细看）"],
           ["`trace_native.js`", "指定 native 函数的调用参数与返回值"],
           ["`arm_hook_probe.js`", "ARM/Thumb 指令级 hook 是否可用"],
           ["`sg_class_filter.js`", "只关注某些类的加载与初始化"]],
          widths=[6.4, 10.0], size=8.8, mono_first=True)
    h3(doc, "8.1.3　设备侧 frida-server（版本必须严格配对）")
    para(doc, "`frida\\server\\` 里备好了 17.18.0 的三个 ABI（arm / arm64 / x86_64，含 .xz 压缩包）。"
              "**PC 端 frida 与设备端 frida-server 版本必须一致**，否则会报 protocol 不兼容。推送与启动：")
    code(doc, r"""> adb shell getprop ro.product.cpu.abi        :: 确认 ABI（arm64-v8a 最常见）
> adb push server\frida-server-17.18.0-android-arm64 /data/local/tmp/fs
> adb shell "su -c 'chmod 755 /data/local/tmp/fs; /data/local/tmp/fs &'"
> frida-ps -U                                 :: 能列进程就说明通了""")
    bullets(doc, [
        ("模拟器 x86_64：", "推 `frida-server-17.18.0-android-x86_64`，注意模拟器多为 32 位用户态，必要时用 arm 版本。"),
        ("不想 root：", "可用 `frida-apk` / `frida-gadget` 的思路把 gadget 打进 apk，或直接走 LSPosed（8.3）。"),
        ("脱壳：", "先 `dump_dex_write.js`，再用 `dump_dex_art.js` 补漏，最后把 dump 出来的 dex 丢给 GDA/apktool 二次分析。"),
        ("PC 侧自动化：", "`frida\\frida_mcp.py` 把设备/注入/脚本生命周期包装成 MCP 工具（详见 8.4 与第 9 章）。"),
    ])

    h2(doc, "8.2　unidbg：没有设备也能跑 so")
    para(doc, "`02-Dynamic-Instrumentation\\unidbg` 是一个 Maven 工程（已构建过，`target/` 有产物）。"
              "它的价值只有一个：**确定性地执行 Android ARM/ARM64 so 里的单个函数**，参数与返回值完全可控，"
              "适合把「算法还原」从「靠猜」变成「可复现实验」。")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总\02-Dynamic-Instrumentation\unidbg
> mvnw.cmd -q -DskipTests package        :: 重新构建（第一次会比较慢）
:: 日常用法：在 unidbg-android\src\test\java\... 下写自己的 harness（继承 AbstractJni），然后
> mvnw.cmd -Dtest=<你的测试类名> test""")
    bullets(doc, [
        ("典型场景：", "加固 App 里用 native 实现的签名/加密函数，参数已知、想批量算输出。"),
        ("需要准备：", "目标 so + 它依赖的其他 so（一起放到 harness 的资源目录），以及调用处的参数类型。"),
        ("常见坑：", "JNI 环境缺失导致崩溃时，说明 harness 里要补 JNI stub；ARM 指令在 x86 上的模拟差异，"
                 "会导致部分依赖硬件特性的代码跑不通（见 12 章排障表）。"),
    ])

    h2(doc, "8.3　LSPosed 1.9.2 / Vector 2.2：启动前介入")
    para(doc, "`02-Dynamic-Instrumentation\\LSPosed\\` 里是两个 Zygisk 模块的 release 包（另有解包出来的 "
              "`_apk\\` 可用于静态研究）。它适合两类需求：")
    bullets(doc, [
        ("应用一启动就要改行为", "（Frida spawn 之前就已经做完检测的加固 App）。"),
        ("长期、稳定的修改", "：写一个模块 hook 目标方法，比每次手动跑 Frida 脚本更省事。"),
    ])
    para(doc, "刷入方式：Magisk / KernelSU 里「从本地安装」选 zip → 重启 → 在 LSPosed 管理器里启用模块并勾选作用域。"
              "本目录同时保留了官方 LSPosed 与 Vector 分支的版本，选型结论见 "
              "`LSPosed\\LSPosed-vs-Vector-Comparison.md`。")
    note(doc, "LSPosed 与 Frida 可以共存，但两者都改方法时容易互相干扰。排障时先只留一个，"
              "确认问题归属再加回另一个。")

    h2(doc, "8.4　MCP 桥：把设备与 Ghidra 变成「工具调用」")
    bullets(doc, [
        ("`02-...\\frida\\frida_mcp.py`", "：把「列设备 / 起 frida-server / spawn / attach / 跑脚本 / 收消息」"
                                    "包成 MCP 工具，配合 Cline 直接对话式操作设备。"),
        ("`01-...\\ghidra-mcp\\server.py`", "：基于 pyghidra，把 Ghidra 变成二十多个可调用工具（反编译、"
                                     "改名、交叉引用、导出），热 JVM 常驻，比每次开 GUI 快。"),
        ("`03-Automation-Agents\\REA`", "：容器层，负责证据账本与统一 Evidence Schema；它不实现分析能力，"
                                  "而是调用上面这些引擎。"),
    ])


def ch9(doc):
    h1(doc, "第 9 章　样本研判：capa / FLOSS / YARA")
    code(doc, r"""> call 07-Malware-Forensics\env.cmd        :: 三条命令都可用之后，再开始下面的步骤""")
    para(doc, "这三个工具的分工是固定的：**capa 说「它能干什么」，FLOSS 说「它藏了什么字符串」，"
              "YARA 说「它像不像已知的谁」。**顺序不要变：先能力、再线索、最后归类。")

    h2(doc, "9.1　capa 10.0.0：能力识别 + ATT&CK 映射")
    code(doc, r"""> capa.exe <样本>                 :: 人读报告（默认）
> capa.exe -v <样本>              :: 附匹配位置（函数地址）
> capa.exe -j <样本>              :: JSON，喂脚本
> capa.exe -t "anti-analysis" <样本>   :: 只看某个 tag 的规则
> capa.exe -r <规则目录> <样本>    :: 换用社区规则库（可选，默认用内置规则）""")
    para(doc, "真实输出长这样（ScyllaTest_x64.exe，节选）：")
    code(doc, r"""┌──────────┬──────────────────────────────────────────────────┐
│ md5      │ 7c0fff1c23d98bb8f0669a03b8fd776f                 │
│ sha256   │ 14bb3a9cd3bf047d228df45d91a2d92f9367b44e6138f7e7… │
│ analysis │ static      os windows      format pe   arch amd64│
└──────────┴──────────────────────────────────────────────────┘
┌────────────────────────────┬──────────────────────────────────┐
│ ATT&CK Tactic              │ ATT&CK Technique                 │
├────────────────────────────┼──────────────────────────────────┤
│ DISCOVERY                  │ File and Directory Discovery[T1083]│
│                            │ Process Discovery [T1057]        │
│                            │ Software Discovery [T1518]       │
│ EXECUTION                  │ Shared Modules [T1129]           │
└────────────────────────────┴──────────────────────────────────┘""")
    bullets(doc, [
        ("内置规则：", "exe 里打包了规则库，运行时解包到 `%TEMP%\\_MEIxxxxxx\\rules`（-j 的 "
                  "`meta.analysis.rules` 字段能看到实际路径）。所以**不联网也能用**，不必先 clone capa-rules。"),
        ("想用最新社区规则：", "把 `mandiant/capa-rules` 放到固定目录，用 `-r` 指过去即可（本目录未包含）。"),
        ("格式/后端：", "`-f` 指定输入格式（pe/dotnet/elf/sc32/sc64/cape/drakvuf/vmray…），"
                   "`-b` 指定分析后端（vivisect/pefile/ida/binja/ghidra/dotnet…）。默认 auto 基本够用，"
                   "可疑壳样本用 `-f pe -b vivisect` 更稳。"),
        ("首次运行慢：", "PyInstaller 单文件要先解包几秒，样本大时 vivisect 分析可能要几分钟；"
                    "期间不要重复点击。"),
    ])

    h2(doc, "9.2　FLOSS 3.2.0：把字符串逼出来")
    para(doc, "默认会同时提取四类字符串：static（静态可见）、stack（栈上拼）、tight（栈上紧邻构造）、"
              "decoded（函数内解码）。")
    code(doc, r"""> floss.exe <样本>                        :: 全都要（默认）
> floss.exe --no static -- <样本>         :: 跳过静态串，只看运行时解码出来的
> floss.exe --only stack tight -- <样本>   :: 只看栈相关（恶意 loader 常用）
> floss.exe -j <样本>                     :: JSON
> floss.exe -n 8 <样本>                   :: 只保留长度 ≥ 8 的串""")
    note(doc, "**`--no` / `--only` 后面必须加 `--` 再加样本路径**。这两个选项一次可以吃多个值，"
              "不加 `--` 时它会把样本路径当成下一个取值，报 "
              "`argument --only: invalid choice: '...\\sample.exe'`（本机实测踩过）。")

    h2(doc, "9.3　YARA 4.6.0：规则匹配")
    para(doc, "`YARA\\` 下有两个 exe：`yara64.exe`（扫描）与 `yarac64.exe`（预编译规则，批量扫描时更快）。"
              "先写一条最小规则（本机实测通过）：")
    code(doc, r"""/* demo.yar —— 判「MZ 开头且含 PE 签名」的典型 PE */
rule demo_mz_pe {
    meta:
        author = "manual"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}""")
    code(doc, r"""> yara64.exe -s -m demo.yar <样本>       :: -s 打印命中偏移，-m 打印 meta
> yara64.exe -r rules\ <目录>            :: 递归扫描整个目录
> yara64.exe -t family_unit42 <样本>     :: 只跑某个 tag 的规则
> yarac64.exe demo.yar demo.yarc         :: 预编译
> yara64.exe -C demo.yarc <样本>         :: 用预编译规则扫描""")
    para(doc, "实测输出（命中偏移一目了然，可直接用于定位代码）：")
    code(doc, r"""demo_mz_pe [author="manual"] ...\ScyllaTest_x64.exe
0x0:$mz: 4D 5A
0x100:$pe: 50 45 00 00
0x2f98:$pe: 50 45 00 00""")
    bullets(doc, [
        ("字符串转义：", "在 YARA 文本串里写 `\\0` 是非法的（本机实测报 illegal escape sequence），"
                   "二进制特征请用十六进制串 `{ 50 45 00 00 }` 或 `\\x00`。"),
        ("规则写不好的两个常见原因：", "条件太宽（只写 `{ 4D 5A }` 会命中所有 PE）与字符串太短（<4 字节无法作 atom）。"),
        ("批量筛查：", "`-p <线程数>` 并发、`-a <秒>` 超时、`-z <字节>` 跳过超大文件，扫整盘时才需要。"),
    ])

    h2(doc, "9.4　三者串起来（一条命令下去，三份证据）")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
> call 07-Malware-Forensics\env.cmd
> set S=<样本路径>
> capa.exe -j "%S%"  > out_capa.json
> floss.exe -j "%S%" > out_floss.json
> yara64.exe -s -r 07-Malware-Forensics\YARA "%S%" > out_yara.txt""")
    para(doc, "判读顺序：capa 里出现 `create process` / `persistence` / `anti-VM` 一类能力 → 用 FLOSS 的 "
              "decoded/stack 串找 C2、路径、互斥体 → 把这些串写成 YARA 规则做同族筛查。"
              "**三者都不需要运行样本**，这是它们的最大价值。")


def ch10(doc):
    h1(doc, "第 10 章　数据与密码：CyberChef + Python venv")

    h2(doc, "10.1　CyberChef 11.5.0：交互式还原")
    para(doc, "启动：`09-Data-Crypto-Tools\\Start-CyberChef.cmd`。它会用共享 venv 的 python 在 "
              "`127.0.0.1:8765` 起一个静态服务，然后自动开浏览器。")
    note(doc, "**不要用 file:// 直接打开 `CyberChef\\index.html`**。发行包里只有 `index.html.gz` / `.br`，"
              "且 CyberChef 的 Web Worker 在 file:// 下会被浏览器拒绝加载，页面会是空白的。启动脚本已经处理好了"
              "（先续起 HTTP 服务再打开），照它做即可。")
    code(doc, r"""① 左侧 Operations 搜索操作名 → 双击加进 Recipe（中间栏）
② 右上 Input 粘贴数据 → 下方 Output 实时出结果
③ Recipe 可以串联：e.g. From Base64 → XOR Brute Force → Regular expression
④ 顶部保存/分享会把整个 Recipe 编码进 URL，可以直接存档""")
    para(doc, "五个最常用的配方：")
    table(doc,
          ["场景", "Recipe", "说明"],
          [["判不出是什么编码", "Magic", "自动试一遍常见编码/加密，结果带置信度"],
           ["配置里的 base64 串", "From Base64 → To Hex", "先解出字节，再判断是不是压缩/加密"],
           ["单字节 XOR", "XOR Brute Force", "输出按可读性打分，一眼看出 key"],
           ["时间戳 / 整数", "From UNIX Timestamp / To Base", "日志与 token 里最常见的两种数字"],
           ["疑似压缩数据", "Zlib Inflate / Gunzip / Raw Inflate", "样本数据段里常见"]],
          widths=[4.0, 6.0, 6.4], size=9)
    python_line = ("CyberChef 适合「试」，不适合「批量」。一旦某个 Recipe 试通了，"
                   "立刻把它翻译成 Python，原因有二：可复现、可批处理。")
    para(doc, python_line)

    h2(doc, "10.2　Python 共享 venv：把试通的东西固定下来")
    para(doc, "只用一条路径：`08-Python-RE-Toolchain\\.venv\\Scripts\\python.exe`。下面是四段可直接运行的骨架，"
              "分别对应四类高频任务。")
    h3(doc, "10.2.1　PE 结构 + 节区熵（判壳）")
    code(doc, r"""import math, pefile
pe = pefile.PE(r"sample.exe")
for s in pe.sections:
    data = s.get_data()
    cnt = [0] * 256
    for b in data:
        cnt[b] += 1
    n = len(data) or 1
    ent = -sum((c / n) * math.log2(c / n) for c in cnt if c)
    print(s.Name.rstrip(b"\0").decode(errors="replace"), round(ent, 3))""")
    h3(doc, "10.2.2　反汇编一小段字节（capstone）")
    code(doc, r"""from capstone import Cs, CS_ARCH_X86, CS_MODE_64
code = bytes.fromhex("554889e5")          # push rbp; mov rbp, rsp
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(code, 0x1000):
    print(hex(ins.address), ins.mnemonic, ins.op_str)""")
    h3(doc, "10.2.3　读 / 改 PE（lief）")
    code(doc, r"""import lief
b = lief.parse(r"sample.exe")             # PE / ELF / Mach-O 同一个入口
print(hex(b.entrypoint), b.header.machine)
for sec in b.sections:
    print(sec.name, hex(sec.virtual_address), sec.size)
b.write(r"sample_patched.exe")""")
    h3(doc, "10.2.4　读 so 的节与符号（pyelftools）")
    code(doc, r"""from elftools.elf.elffile import ELFFile
with open(r"libtarget.so", "rb") as fh:
    elf = ELFFile(fh)
    print(elf.header.e_machine, elf.header.e_type)
    for sec in elf.iter_sections():
        print(sec.name, sec["sh_addr"], sec["sh_size"])
    symtab = elf.get_section_by_name(".dynsym")
    for sym in symtab.iter_symbols()[:20]:
        print(sym.name, hex(sym["st_value"]))""")
    para(doc, "要做「算法复现」的，组合是 **keystone（把汇编变机器码）+ unicorn（模拟执行）**："
              "在 unicorn 里造一块内存、把 so 里那段函数拷进去、按调用约定塞参数，就能拿到返回值，"
              "不必启动设备。unidbg（8.2）是同一思路的成品化实现，先试 unidbg，跑不动再自己用 unicorn 兜。")


def ch11(doc):
    h1(doc, "第 11 章　五条端到端流程（直接照抄）")
    para(doc, "下面五条流程是前面所有工具的真实组合方式。每条都给出「什么时候用」「命令顺序」「产物」，"
              "按顺序执行即可，不需要再回头翻章节。")


    h2(doc, "11.1　流程 A：陌生 Windows PE 样本快速研判")
    para(doc, "**适用**：拿到一个来路不明的 exe/dll，需要在一小时内说清「是什么、干什么、危险在哪」。")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
> call 07-Malware-Forensics\env.cmd

:: ① 定性（3 秒）
> 01-Disassembly-Debug\RE-Toolkit\Start-DIE.cmd        :: 拖入文件，看 filetype / packer
:: 或命令行：diec.exe -j -e 样本.exe

:: ② 结构（2 分钟）
> rz-bin -I 样本.exe            :: 架构/编译器/是否 stripped/有没有 overlay
> rz-bin -i 样本.exe            :: 导入表：只有 LoadLibrary/GetProcAddress 就要警惕

:: ③ 能力与线索（5~10 分钟）
> capa.exe -j 样本.exe  > capa.json
> floss.exe -j 样本.exe > floss.json
> yara64.exe -s -r 07-Malware-Forensics\YARA 样本.exe

:: ④ 代码（按需）
> 01-Disassembly-Debug\RE-Toolkit\Start-Cutter.cmd     :: 先看字符串与导入的调用点
> 01-Disassembly-Debug\RE-Toolkit\Start-Ghidra.cmd     :: 需要伪 C 时上 Ghidra

:: ⑤ 动态（可选，需隔离环境）
> 02-Dynamic-Instrumentation\Start-SystemInformer.cmd  :: 先看它起了什么进程/连了什么
> 01-Disassembly-Debug\RE-Toolkit\Start-x64dbg.cmd     :: 插件 → ScyllaHide → 选 profile → 重载""")
    para(doc, "**判读要点**：DIE 说「未加壳」→ 直接读代码效率最高；导入表异常少 + 熵接近 8 → "
              "先解决壳/解码器；capa 出现 persistence / anti-VM / create process → 进入行为分析。"
              "**产物**：capa.json、floss.json、out_yara.txt、结论段落。")


    h2(doc, "11.2　流程 B：.NET 程序改一处逻辑")
    para(doc, "**适用**：自有软件的授权/试用期判断需要调整，或 .NET 样本需要观察某个分支的行为。")
    code(doc, r"""① 确认是 .NET
   > diec.exe -j 目标.exe        :: filetype 里有 .NET；或导入表见 mscoree.dll
② 读懂
   > 01-Disassembly-Debug\RE-Toolkit\Start-ILSpy.cmd → 打开 → 搜 "License" / "Trial" / "expire"
③ 改
   > 01-Disassembly-Debug\RE-Toolkit\Start-dnSpy.cmd → 右键方法 → Edit Method (C#)
   > Compile → File → Save Module（先备份原文件）
④ 验证
   > 用 ILSpy 重新打开产物确认改动；再运行观察行为""")
    note(doc, "带强名称的程序集改完可能加载失败。分析/验证场景通常无碍；要在生产环境长期使用请重新签名"
              "（需要 .NET SDK 的 sn.exe，本目录未包含）。")

    h2(doc, "11.3　流程 C：APK 静态分析与改包")
    para(doc, "**适用**：分析自有 App 的清单/资源/smali，或改一处字符串、去掉一个客户端检查。")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
:: ① 解包
> 06-Android-Mobile-RE\apktool.cmd d app.apk -o out -f
:: ② 读
> notepad out\AndroidManifest.xml        :: 看权限 / exported 组件 / debuggable
> 06-Android-Mobile-RE\Start-GDA.cmd     :: 打开 app.apk 看 Java 视图并搜关键字符串
:: ③ 改（smali）
> notepad out\smali\com\xxx\Login.smali
:: ④ 重打包 + 签名（jarsigner 只有 v1，见 §7.1 注意）
> 06-Android-Mobile-RE\apktool.cmd b out -o patched.apk
> %JAVA%\jarsigner -keystore re.jks -storepass 123456 -keypass 123456 patched.apk re""")
    para(doc, "**装不上怎么办**：Android 11+ 要求 v2/v3 签名，jarsigner 不够。改用 Android SDK 的 "
              "`apksigner`，或干脆不安装——多数分析目的用 Frida 对已安装的原版直接观察即可（第 8 章）。")


    h2(doc, "11.4　流程 D：Unity IL2CPP 手游定位关键函数")
    para(doc, "**适用**：目标用 Unity il2cpp 编译（有 `libil2cpp.so` + `global-metadata.dat`），需要「看懂类结构、"
              "找到某个功能对应的函数」。")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
:: ① 拿到两个文件（自有 apk 或已授权样本）
> 06-Android-Mobile-RE\apktool.cmd d game.apk -o game -r      :: -r 只留需要的部分，速度快
:: ② 还原符号
> 06-Android-Mobile-RE\Start-Il2CppDumper.cmd ^
      game\lib\arm64-v8a\libil2cpp.so ^
      game\assets\bin\Data\Managed\Metadata\global-metadata.dat ^
      dump_out
:: ③ 看结构
> dir dump_out          :: dump.cs / il2cpp.h / script.json / stringliteral.json / DummyDll
> 用 dnSpy 或 ILSpy 打开 dump_out\DummyDll  :: 浏览类与方法（有名字、没实现）
:: ④ 接反编译器
> Ghidra 打开 libil2cpp.so → Script Manager → ghidra_with_struct.py
   指定 script.json 与 il2cpp.h → 函数名与结构体恢复
:: ⑤ 定位
> 在 dump.cs 里按关键字搜（"Coin"/"Damage"/"Verify"），拿到 RVA → 到 Ghidra 里地址跳转""")
    para(doc, "**判读要点**：`stringliteral.json` 里有全部字符串字面量，是定位功能最快的入口；"
              "`dump.cs` 里的 RVA 是**函数偏移**，定位时记得加上 so 的基址。")

    h2(doc, "11.5　流程 E：加固 App 的算法还原（抓参 → 复现 → 交叉验证）")
    para(doc, "**适用**：客户端有 native 签名/加密（常见于风控字段），需要把算法在 PC 上复现以便批量算。")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
> call 02-Dynamic-Instrumentation\frida\env.cmd
:: ① 先看边界：Java 侧把参数交给哪个 native 函数
> frida -U -f <包名> -l 02-Dynamic-Instrumentation\frida\hooks\jni_boundary.js
:: ② 看 native 热函数
> frida -U -f <包名> -l 02-Dynamic-Instrumentation\frida\hooks\native_profile_arm64.js
:: ③ 抓输入输出（写一个只 hook 目标函数的脚本）
> frida -U -f <包名> -l my_hook.js
:: ④ 若能拿到 so 且无重加固，用 unidbg 直接驱动该函数
> 02-Dynamic-Instrumentation\unidbg → 写 harness → mvnw.cmd -Dtest=MyTest test
:: ⑤ PC 侧复现
> 08-Python-RE-Toolchain\.venv\Scripts\python.exe my_algo.py
:: ⑥ 与现场数据交叉验证（编码/异或/哈希这类小步骤用 CyberChef 更快对）
> 09-Data-Crypto-Tools\Start-CyberChef.cmd""")
    para(doc, "**成功标准**：同一组输入，设备上抓到的输出与 PC 侧复现的输出**逐字节一致**。"
              "只对上一个 32 位哈希不够——先确认编码（hex/base64）、字节序、以及是否有随机盐参与。")


def ch12(doc):
    h1(doc, "第 12 章　排障速查（全部本机实测）")
    para(doc, "下表按「现象」查。凡是涉及路径的，都写的是本机绝对路径；搬目录后请自行替换前缀。")
    table(doc,
          ["现象", "原因", "处理"],
          [["`imhex.exe --magic` 报 Failed to compile magic database",
            "portable 包未随带 libmagic 数据库", "改用 `diec -j <文件>` 或 PE-bear 判断类型"],
           ["`rizin.exe --version` 长时间挂住", "它会等待标准输入，非交互环境会一直等",
            "脚本里判版本用 `rz-bin -v`（输出 `rz-bin 0.9.1 @ windows-x86-64`）"],
           ["`floss --only stack tight 样本.exe` 报 "
            "`argument --only: invalid choice`",
            "`--only/--no` 接受多个值，把样本路径也当成了取值",
            "加分隔符：`floss --only stack tight -- 样本.exe`"],
           ["`capa.exe` 第一次运行像卡死", "PyInstaller 单文件要先解包到 %TEMP%",
            "等 5~10 秒；确保 %TEMP% 可写、杀软没有拦截解包"],
           ["Ghidra 启动报 “JDK 21+ (64-bit) could not be found”",
            "`D:\\RE-JDK` 联接被删，或 java_home.save 指向失效路径",
            "`mklink /J D:\\RE-JDK \"D:\\逆向工具网络安全汇总\\04-Runtimes\\jdk25\"`，不要改 JAVA_HOME"],
           ["CyberChef 打开是空白页", "用 file:// 打开了 index.html，Web Worker 被拒",
            "只通过 `Start-CyberChef.cmd`（127.0.0.1:8765）访问"],
           ["把 ILSpy.exe 单独拷走就起不来", "它依赖同目录的运行时与依赖库",
            "整个 `01-Disassembly-Debug\\ILSpy` 目录一起搬"],
           ["apktool 解码报 framework / 资源错误",
            "`%LOCALAPPDATA%\\apktool\\framework\\1.apk` 损坏或版本不匹配",
            "删除该文件重试；或加 `-r` 完全不处理资源"],
           ["`apktool b` 出来的 apk 装不上", "jarsigner 只能 v1，Android 11+ 要 v2/v3",
            "用 Android SDK 的 `apksigner` 重签；或改为对已安装原版做 Frida 分析"],
           ["Il2CppDumper 报 metadata 魔数错误", "global-metadata.dat 被加密（加固/自校验）",
            "用 Frida 在 il2cpp_init 之后 dump 内存中的 metadata 再喂给 dumper"],
           ["YARA 规则写 `\"PE\\0\\0\"` 报 illegal escape sequence",
            "YARA 文本串不支持 \\0", "改用十六进制串 `{ 50 45 00 00 }` 或 `\\x00`"],
           ["x64dbg 载入目标就退出", "反调试 / TLS 回调在入口点前就做了检测",
            "插件 → ScyllaHide → 选 profile；并在 Options → Events 勾选 TLS Callbacks 先断下"],
           ["命令行里中文输出乱码", "控制台代码页（GBK）与文件编码（UTF-8）不一致",
            "`chcp 65001` 切 UTF-8；脚本读文件请统一用 Python 按 utf-8 打开"],
           ["`pip install` 大 wheel 卡在下载", "PyPI 直连不稳",
            "用 `-i https://pypi.tuna.tsinghua.edu.cn/simple`（`setup-pyenv.ps1` 已自动重试）"],
           ["unidbg harness 一跑就崩", "缺 JNI 实现，或 ARM 指令在 x86 上模拟差异",
            "补 AbstractJni 的 stub；实在跑不通就退回 Frida 在设备上取结果"]],
          widths=[5.6, 4.8, 6.0], size=8.6)


def ch13(doc):
    h1(doc, "第 13 章　上传 git：提交什么、别提交什么")
    para(doc, "先说结论：**这个目录约 6.3 GB、7.9 万个文件，不适合整目录塞进 Git。** 下面这张表是实测体积，"
              "看完就知道为什么。")
    table(doc,
          ["目录", "体积", "文件数", "建议"],
          [["01-Disassembly-Debug", "3245.6 MB", "17,285", "不提交（Ghidra/ImHex/Cutter 等二进制）"],
           ["02-Dynamic-Instrumentation", "1322.8 MB", "13,019", "不提交（含 frida-server、.venv）"],
           ["04-Runtimes", "389.3 MB", "2,371", "不提交（Node / JDK）"],
           ["_downloads", "381.3 MB", "50", "只提交 `manifest.json` 与 `*.ps1`，zip 不提交"],
           ["08-Python-RE-Toolchain", "370.6 MB", "7,244", "只提交 `setup-pyenv.ps1`、`requirements-lock.txt`，`.venv` 不提交"],
           ["03-Automation-Agents", "369.0 MB", "18,591", "按需：只提交源码，`dist/ build/ .venv*` 不提交"],
           ["09-Data-Crypto-Tools", "79.3 MB", "134", "不提交（CyberChef 发行包）"],
           ["07-Malware-Forensics", "71.5 MB", "5", "不提交（capa/FLOSS/YARA 单文件）"],
           ["06-Android-Mobile-RE", "45.6 MB", "16", "不提交（apktool jar / GDA / Il2CppDumper）"],
           ["05-Cases", "15.0 MB", "96", "**谨慎**：含案件证据与样本痕迹，一般不提交"],
           ["_manifest", "≈0 MB", "2", "可提交（搬迁记录，可回滚）"]],
          widths=[5.2, 2.6, 2.4, 6.4], size=9, mono_first=True)

    h2(doc, "13.1　做法：工具不进 git，文档单独一个目录")
    para(doc, "本机把「要提交的东西」镜像成**一个独立的小目录**，与 6.3 GB 工具包彻底分开，直接对它 `git init`：")
    table(doc,
          ["位置", "内容", "体积"],
          [["`D:\\逆向工具网络安全汇总`", "全部工具与运行时（01–09 各子目录、04-Runtimes、_downloads 里的 zip）",
            "≈6.3 GB / 7.9 万文件"],
           ["`D:\\逆向工具网络安全汇总-git`", "文档 + 启动器 + 清单 + 生成脚本，共 53 个文件（+ 仓库自己的 `.gitignore`）", "≈1.7 MB"]],
          widths=[5.6, 8.2, 3.2], size=9, mono_first=True)
    para(doc, "仓库里只有下面这些（清单来自实测，不是拍脑袋写的）：")
    bullets(doc, [
        ("文档", "：`README.md`、`逆向工具使用手册.doc / .docx`、`逆向工具与方案汇总.doc / .docx / .md`"),
        ("启动器", "：`Start-*.cmd`（10 个）、`frida\\env.cmd`、`07-Malware-Forensics\\env.cmd`、"
                 "`06-Android-Mobile-RE\\*.cmd`、`09-Data-Crypto-Tools\\Start-CyberChef.cmd`"),
        ("手写脚本", "：`frida\\hooks\\*.js`（12 个）、`setup-pyenv.ps1`、`_build_manual.py`、`_docx2doc.ps1`、"
                  "`_inventory.py`、`_probe_*.py`"),
        ("清单类", "：`_downloads\\manifest.json` + 4 个下载脚本、`requirements-lock.txt`、`_manifest\\*`"),
    ])
    para(doc, "**不在仓库里的**：所有 `.exe / .dll / .jar / .zip / .so`、`.venv`、`node_modules`、`05-Cases` 里的案件产物。"
              "它们靠 `manifest.json` 的 `repo + tag + SHA-256` 重建，比塞进 Git 更快、也更可验证（见 13.5）。")

    h2(doc, "13.2　首次建仓库（命令在本机跑过）")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总-git
> git init
> git add -A
> git status --short            :: 53 个白名单文件 + 仓库自己的 .gitignore
> git commit -m "docs: 逆向工具链文档与启动脚本"
> git remote add origin https://github.com/<你的账号>/<仓库名>.git
> git push -u origin main""")

    h2(doc, "13.3　日常同步：_sync_git.ps1（单向，不手拷）")
    para(doc, "改了工具目录里的文档或脚本后，跑一次同步脚本即可：它按**仓库里已跟踪的清单**把文件重新镜像过去，"
              "再让你决定是否提交（只同步不提交是默认行为）。")
    code(doc, r"""> cd /d D:\逆向工具网络安全汇总
> powershell -NoProfile -ExecutionPolicy Bypass -File _sync_git.ps1                 :: 只同步，看 diff
> powershell -NoProfile -ExecutionPolicy Bypass -File _sync_git.ps1 -Commit         :: 同步并提交
> powershell -NoProfile -ExecutionPolicy Bypass -File _sync_git.ps1 -Include "05-Cases\报告.md" -Commit""")
    note(doc, "同步方向固定为 **工具目录 → 仓库目录**。清单来自 `git -C <repo> ls-files`，所以新增文件要用 "
              "`-Include <相对路径>` 显式带一次，之后它就记在仓库清单里了。单向是故意的：避免两边同时改动时互相覆盖。")

    h2(doc, "13.4　仓库自带的 .gitignore（第二道防线）")
    code(doc, r"""# 仓库里只该出现文档与脚本；下面这些一律拒收，
# 防止哪天手滑把工具包 add 进来。
*.exe
*.dll
*.jar
*.zip
*.7z
*.so
*.dylib
*.pdb
*.bin
*.nupkg

# 运行时与缓存
**/.venv*/
**/node_modules/
**/__pycache__/

# 案件与样本
05-Cases/""")
    note(doc, "仓库目录里本来就只放了白名单文件，所以不需要「先忽略一切再逐个放行」那种复杂写法。"
              "核对：`git status --short` 不该出现任何二进制；万一手滑过，`git rm --cached <文件>` 移出索引再提交。"
              "顺带一提，`01-Disassembly-Debug\\ghidra-mcp` 等四个目录自带 `.git`（别人的仓库），"
              "在工具目录里对它们执行 `git add` 会产生 gitlink（mode `160000`）——这也是把仓库搬到独立目录的理由之一。")

    h2(doc, "13.5　确实要连工具一起版本化时")
    bullets(doc, [
        ("必须用 Git LFS", "：`git lfs install` + `git lfs track \"*.zip\" \"*.jar\" \"*.dll\" \"*.exe\"`，"
                     "否则单个 >100 MB 的文件会被 GitHub 直接拒绝。"),
        ("算清额度", "：GitHub 免费 LFS 存储 1 GB、月流量 1 GB；本目录 6.3 GB 明显超，"
                 "私有仓库自建 Gitea/GitLab 更现实。"),
        ("更省的做法", "：仓库里只放 `_downloads\\manifest.json`。它记录了每个包的 `repo / tag / size / digest / url`，"
                  "任何机器上重跑 `_dl_all.ps1` + `_install.ps1` 就能一模一样地重建工具链——"
                  "**这比把二进制塞进 Git 更快、更可验证**。"),
    ])


def ch14(doc):
    h1(doc, "第 14 章　合规红线")
    bullets(doc, [
        ("只碰有授权的目标。", "自有系统、客户书面授权、公开 CTF/靶场、明确允许分析的样本。"
                       "对第三方生产系统做动态分析（含网络拦截、注入、脱壳后的重打包）必须另行取得许可。"),
        ("动态能力默认关闭。", "本手册里所有 Frida / 注入 / 反调试绕过 / 重打包步骤，只在授权范围内显式开启；"
                        "不要写成「自动跑」的常驻脚本。"),
        ("证据要可复现。", "每个结论附：文件哈希（`diec -j` 或 ImHex `--hash`）、环境（工具版本见表）、"
                    "操作时间、命令原文。这条同时也是 03-Automation-Agents 里 Evidence Schema 的意义。"),
        ("样本与密钥不出圈。", "`05-Cases` 里的样本、密钥、账号信息不要提交到公开仓库（见 13.1）；"
                       "分享报告时先脱敏（域名/IP/账号/证书序列号）。"),
        ("遵守当地法律与平台条款。", "在国内主要对应《网络安全法》《数据安全法》《个人信息保护法》与《刑法》285/286 条；"
                             "对商业软件绕过的授权/加密保护，属于需要单独法律评估的行为，不属于「技术问题」。"),
    ])
    para(doc, "本章不构成法律意见。涉及真实业务系统时，请在动手前把授权范围写进书面（谁授权、哪些资产、"
              "什么时间、允许到什么程度），并留存。")


def appendix(doc):
    h1(doc, "附录 A　命令速查卡")
    table(doc,
          ["要做的事", "命令（在本目录下执行）"],
          [["识别任何文件", "`01-Disassembly-Debug\\RE-Toolkit\\DIE\\diec.exe -j -e <文件>`"],
           ["算哈希", "`imhex.exe --hash sha256 <文件>`　或　`rz-bin -K sha256 <文件>`"],
           ["看 PE 头/节/导入", "`rz-bin -I -S -i <文件>`　或 GUI 用 PE-bear"],
           ["看 64 字节十六进制", "`imhex.exe --hexdump <文件> 0 64`"],
           ["进制/表达式换算", "`imhex.exe --calc \"0x30*2\"`"],
           ["反汇编一段字节", "`rz-asm -a x86 -b 64 -d 554889e5`"],
           ["列出函数", "`rizin -q -c \"aa; afl\" <文件>`"],
           ["main 的反汇编", "`rizin -q -c \"aa; s sym.main; pdf\" <文件>`"],
           ["伪 C 代码", "Ghidra GUI / `analyzeHeadless.bat` + 脚本"],
           [".NET 反编译（只读）", "`01-Disassembly-Debug\\RE-Toolkit\\Start-ILSpy.cmd`"],
           [".NET 改 IL", "`01-Disassembly-Debug\\RE-Toolkit\\Start-dnSpy.cmd`"],
           ["调试 64 位目标", "`01-Disassembly-Debug\\RE-Toolkit\\Start-x64dbg.cmd`（先开 ScyllaHide）"],
           ["看注入/驱动", "`02-Dynamic-Instrumentation\\Start-SystemInformer.cmd`（管理员）"],
           ["列出手机 App", "`call 02-Dynamic-Instrumentation\\frida\\env.cmd` → `frida-ps -Ua`"],
           ["spawn + hook", "`frida -U -f <包名> -l hooks\\api_probe.js`"],
           ["APK 解包", "`06-Android-Mobile-RE\\apktool.cmd d app.apk -o out -f`"],
           ["APK 重打包", "`06-Android-Mobile-RE\\apktool.cmd b out -o patched.apk`"],
           ["il2cpp 还原", "`Il2CppDumper.exe <libil2cpp.so> <global-metadata.dat> <out>`"],
           ["能力识别", "`capa.exe <样本>`（`-j` 出 JSON）"],
           ["提取隐藏字符串", "`floss.exe <样本>`（`--only stack tight -- <样本>`）"],
           ["YARA 扫描", "`yara64.exe -s -m rules.yar <样本>`"],
           ["编码/加密还原", "`09-Data-Crypto-Tools\\Start-CyberChef.cmd`"],
           ["批量 PE/ELF 处理", "`08-Python-RE-Toolchain\\.venv\\Scripts\\python.exe <脚本>`"]],
          widths=[4.6, 11.8], size=8.8)


    h1(doc, "附录 B　版本清单与校验方式")
    para(doc, "下表摘自 `_downloads\\manifest.json`（新增工具）与实际运行输出（既有工具）。"
              "`SHA-256` 只列前 16 位，完整值见 manifest。")
    table(doc,
          ["工具", "版本", "来源 tag", "SHA-256（前 16 位）/ 校验"],
          [["ImHex", "1.38.1", "WerWolv/ImHex v1.38.1", "32520e57712894bc"],
           ["PE-bear", "0.7.2", "hasherezade/pe-bear v0.7.2", "d2b995b213d0e6b3"],
           ["ILSpy", "11.2.0.10050", "icsharpcode/ILSpy v11.2", "c30cda0e5a22435d"],
           ["SystemInformer", "4.0.26241.138", "winsiderss/systeminformer v4.0.26241.138", "3e12cc4f1ffa1cc3"],
           ["ScyllaHide", "v1.4（2023-03-24）", "x64dbg/ScyllaHide v1.4", "上游无 digest，按字节数 3,804,223 校验"],
           ["Apktool", "3.0.3", "iBotPeaches/Apktool v3.0.3", "dbf930b076c6b9be"],
           ["GDA", "4.12", "charles2gan/GDA-android-reversing-Tool GDA4.12", "510924aabfebfe49"],
           ["Il2CppDumper", "6.7.46", "Perfare/Il2CppDumper v6.7.46", "上游无 digest，按字节数 11,215,992 校验"],
           ["capa", "10.0.0", "mandiant/capa v10.0.0", "8712991044321dbb"],
           ["FLOSS", "3.2.0", "mandiant/flare-floss v3.2.0", "c0c73bb99d043fed"],
           ["YARA", "4.6.0", "VirusTotal/yara v4.6.0", "5e7124f173ed4424"],
           ["CyberChef", "11.5.0", "gchq/CyberChef v11.5.0", "f6478925d3eaa16e"],
           ["Cutter", "2.5.0", "（早于本批）", "cutter.exe 无版本资源，按目录记录"],
           ["rizin", "0.9.1", "随 Cutter 附带", "`rz-bin -v` 自检"],
           ["Ghidra", "12.1.3 PUBLIC", "（早于本批）", "`Ghidra\\Ghidra\\application.properties`"],
           ["dnSpyEx", "6.6.0", "（早于本批）", "PE FileVersion 6.6.0"],
           ["DIE", "3.21", "（早于本批）", "`diec.exe --version`"],
           ["Frida / frida-tools", "17.18.0 / 14.10.4", "（早于本批）", "`frida --version`"],
           ["x64dbg", "snapshot 2026-05-27", "（早于本批）", "`release\\commithash.txt`"],
           ["Python venv", "3.12.10", "本地构建", "`requirements-lock.txt`（78 行）"],
           ["Node.js / JDK", "24.16.0 / 25.0.4.1", "（早于本批）", "`node -v` / `java -version`"]],
          widths=[3.6, 3.2, 5.4, 4.2], size=8.5)


    h1(doc, "附录 C　文件与脚本索引")
    table(doc,
          ["路径", "作用"],
          [["`README.md`", "目录结构、联接说明、新增工具安装记录"],
           ["`逆向工具与方案汇总.doc`", "选型思路、SOP、已知坑（与本手册互补）"],
           ["`逆向工具使用手册.doc`", "本文件：逐工具实操 + 5 条端到端流程"],
           ["`_downloads\\manifest.json`", "12 个新增包的 repo/tag/size/digest/url/dest"],
           ["`_downloads\\_dl_all.ps1` 等四个脚本", "批量下载 / 单文件 / 分块并发 / 校验安装"],
           ["`01-Disassembly-Debug\\RE-Toolkit\\Start-*.cmd`", "Cutter · rizin · Ghidra · DIE · dnSpy · ILSpy · ImHex · PE-bear · x64dbg · x32dbg"],
           ["`02-Dynamic-Instrumentation\\frida\\env.cmd`", "frida 与 adb 进 PATH"],
           ["`02-Dynamic-Instrumentation\\frida\\hooks\\*.js`", "12 个单点探针脚本"],
           ["`02-Dynamic-Instrumentation\\Start-SystemInformer.cmd`", "系统全貌查看器"],
           ["`06-Android-Mobile-RE\\apktool.cmd`", "APK 解包 / 重打包（固定 jdk25）"],
           ["`06-Android-Mobile-RE\\Start-GDA.cmd` / `Start-Il2CppDumper.cmd`", "DEX 反编译 / il2cpp 还原"],
           ["`07-Malware-Forensics\\env.cmd`", "capa / floss / yara64 进 PATH"],
           ["`08-Python-RE-Toolchain\\setup-pyenv.ps1`", "重建共享 venv（含镜像重试与自检）"],
           ["`09-Data-Crypto-Tools\\Start-CyberChef.cmd`", "127.0.0.1:8765 起服务并开浏览器"],
           ["`_inventory.json` / `_help.txt` / `_facts.txt` / `_demo.txt`", "本手册所有事实的原始采集输出，可复现核对"],
           ["`_build_manual.py` / `_docx2doc.ps1`", "生成本文档的脚本，改内容后重跑即可"],
           ["`_sync_git.ps1`", "把仓库白名单文件单向镜像到 `D:\\逆向工具网络安全汇总-git`（见 13.3）"],
           ["`_git_files.txt`", "提交白名单：53 个相对路径，`_sync_git.ps1` 按它同步"],
           ["`D:\\逆向工具网络安全汇总-git`", "**独立的 git 仓库**：只含文档 + 启动器 + 清单，≈1.7 MB"]],
          widths=[8.0, 8.4], size=8.6, mono_first=True)
    doc.add_page_break()
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_font(p.add_run("— 手册结束 —"), 11, True, C_H2, cn=CN_HEAD)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_font(p.add_run("文档生成于 2026-10-29　·　所有版本号与命令均来自本机实测"), 9, False,
             RGBColor(0x80, 0x80, 0x80))


def main():
    doc = Document()
    setup_page(doc)
    setup_styles(doc)
    header_footer(doc)
    cover(doc)
    toc(doc)
    for chapter in (ch1, ch2, ch3, ch4, ch5, ch6, ch7, ch8, ch9, ch10, ch11,
                    ch12, ch13, ch14):
        chapter(doc)
        doc.add_page_break()
    appendix(doc)
    doc.save(DOCX)
    print("saved %s  %d bytes" % (DOCX, os.path.getsize(DOCX)))


if __name__ == "__main__":
    main()





















