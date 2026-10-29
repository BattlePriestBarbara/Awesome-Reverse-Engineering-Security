# 逆向工具网络安全汇总

D 盘逆向 / 安全工具的**统一收拢目录**。原先散落在 `D:\` 根下的 18 个目录已全部迁入本目录，
所有启动脚本、MCP 配置、环境变量均已同步改指向新位置，并通过实测。

## 文档

| 文件 | 内容 |
|---|---|
| **[逆向工具使用手册.doc](逆向工具使用手册.doc)**　/[.docx](逆向工具使用手册.docx) | **本目录的实操手册（35 页 / 1.7 万字）**：逐工具的命令、真实输出与坑，覆盖 01–09 下全部 28 个工具/项目；含 5 条端到端流程、命令速查卡、版本与校验清单、git 上传指引。 |
| [逆向工具与方案汇总.doc](逆向工具与方案汇总.doc)　/[.md](逆向工具与方案汇总.md) | 选型思路与总体方案（与手册互补：这边讲“为什么”，手册讲“怎么做”）。 |

手册由 `_build_manual.py`（python-docx）生成，`_docx2doc.ps1` 负责刷新目录页码并另存 `.doc`：

```bat
...\08-Python-RE-Toolchain\.venv\Scripts\python.exe _build_manual.py
powershell -NoProfile -ExecutionPolicy Bypass -File _docx2doc.ps1
```

手册里的每个版本号、路径、命令和输出都来自本机实测。采集脚本（`_inventory.py`、`_probe_*.py`）随仓库提交，
它们的原始输出（`_inventory.json`、`_help.txt`、`_help2.txt`、`_facts.txt`、`_demo.txt`）按白名单不入库——
需要复核时重新跑一遍脚本即可逐字复现。

### 提交到 git：只搬文档与脚本

工具包（约 6.3 GB）不进 git。要提交的内容由白名单 `_git_files.txt` 定义（53 项），
镜像到同级的独立仓库目录 **`D:\逆向工具网络安全汇总-git`**（约 1.7 MB），本目录本身不是 git 仓库：

```bat
:: 改了文档 / 脚本之后：单向同步（只同步不提交）
...\_sync_git.ps1

:: 同步并提交
powershell -NoProfile -ExecutionPolicy Bypass -File _sync_git.ps1 -Commit

:: 需要新增一个文件时（仓库的 git ls-files 会记住它，后续自动同步）
powershell -NoProfile -ExecutionPolicy Bypass -File _sync_git.ps1 -Include "05-Cases\报告.md"
```

细节见手册第 13 章。



```
D:\逆向工具网络安全汇总\
├─ 01-Disassembly-Debug\          静态分析 / 反汇编 / 调试
│  ├─ RE-Toolkit\                 Cutter 2.5.0 · rizin 0.9.1 · x64dbg/x32dbg · dnSpyEx 6.6.0 · DIE 3.21
│  │  └─ Start-*.cmd              各工具启动器（全部使用 %~dp0 相对路径）
│  ├─ ImHex\                      ImHex 1.38.1（hex 编辑器 + .hexpat 模式语言）
│  ├─ PE-bear\                    PE-bear 0.7.2（PE 结构查看/编辑）
│  ├─ ILSpy\                      ILSpy 11.2 self-contained（.NET 反编译）
│  ├─ Ghidra\                     Ghidra 12.1.3 PUBLIC（IDA/Hex-Rays 的开源替代）
│  └─ ghidra-mcp\                 Ghidra MCP 桥（pyghidra 3.1.0）
├─ 02-Dynamic-Instrumentation\    动态插桩 / 脱壳 / 模拟执行
│  ├─ frida\                      frida 17.18.0 + frida MCP + platform-tools(adb) + hooks\
│  ├─ unidbg\                     unidbg（Maven 工程，SO 模拟执行）
│  ├─ LSPosed\                    LSPosed v1.9.2 / Vector v2.2（Zygisk 注入框架）
│  ├─ SystemInformer\             SystemInformer 4.0.26241.138（进程/内核查看器）
│  └─ ScyllaHide\                 ScyllaHide v1.4（x64dbg 反反调试插件）
├─ 03-Automation-Agents\          自动化 / Agent 化逆向
│  ├─ REA\                        REA 运行时 + rea-agents（MCP 服务）
│  ├─ RevLab\                     逆向实验框架
│  ├─ RE_Automation_Framework\    自动化流水线（含 .venv-build / dist）
│  └─ AutoRev-Crypto\             自动化密码算法识别脚本集
├─ 04-Runtimes\                   上述工具共用的运行时
│  ├─ node\                       Node.js v24.16.0（npm 11.13.0）→ REA 依赖
│  └─ jdk25\                      Temurin JDK 25.0.4.1 → Ghidra(≥21) 依赖
├─ 05-Cases\                      案件产物 / 工程文件
│  ├─ USBHistory\                 USB 取证 PowerShell
│  ├─ QQ_RE_2026-10-15\           QQ 逆向证据
│  ├─ rev-phase1-check\  rev-phase1-frozen2\  rev-test-scratch\
│  └─ GhidraProjects\lki\         Ghidra 工程
├─ 06-Android-Mobile-RE\          安卓 APK / DEX / IL2CPP 逆向
│  ├─ Apktool\                    Apktool 3.0.3（jar + apktool.cmd，用 jdk25 跑）
│  ├─ GDA\                        GDA 4.12（原生二进制，免 Java）
│  └─ Il2CppDumper\               Il2CppDumper 6.7.46（Unity IL2CPP 符号还原）
├─ 07-Malware-Forensics\          恶意样本命令行分析
│  ├─ capa\                       capa 10.0.0（能力识别）
│  ├─ FLOSS\                      FLOSS 3.2.0（字符串/解码提取）
│  └─ YARA\                       YARA 4.6.0（yara64.exe 规则扫描）
├─ 08-Python-RE-Toolchain\        共享 Python venv（3.12.10）+ setup-pyenv.ps1
├─ 09-Data-Crypto-Tools\          数据 / 密码处理
│  └─ CyberChef\                  CyberChef 11.5.0（需经本地 HTTP 打开）
├─ _manifest\                     搬迁清单 + 日志（可回滚）
└─ _downloads\                    新增工具的下载缓存 / manifest.json / 安装日志
```

## 三个 ASCII 兼容锚点（重要，别删）

本目录名含中文。绝大多数工具（Qt/Cutter、rizin、DIE、x64dbg、dnSpy、Python、Node）
对中文路径没有障碍，已逐一实测。但存在两处硬约束，用**目录联接（junction，0 字节）** 兜住：

| 联接 | 指向 | 为什么必须存在 |
|---|---|---|
| `D:\RE-JDK` | `...\04-Runtimes\jdk25` | Ghidra 的 `launch.bat` 先用旧 JDK 引导，再读 `%APPDATA%\ghidra\ghidra_12.1.3_PUBLIC\java_home.save`。该文件按**平台编码**解析，中文路径会变乱码 → 报 `JDK 21+ (64-bit) could not be found`。改为纯 ASCII 路径后，GBK/UTF-8 字节一致，问题消失。 |
| `D:\unidbg` | `...\02-Dynamic-Instrumentation\unidbg` | 历史脚本里写死的便捷入口 |
| `D:\Palantir_Research\tools\unidbg` | 同上 | `run_unidbg.ps1` / `patch_jdk_module_ambiguity.ps1` 的默认 `$Repo`，避免改科研工程代码 |

删除任何一个都会让对应工具链失效。

另有一处**不在本目录内**、但同样依赖本目录的联接（搬迁后已重定向）：

```
C:\Users\<user>\.agents\skills\reverse-engineer-anything
      -> D:\逆向工具网络安全汇总\03-Automation-Agents\REA\skills\reverse-engineer-anything
```

Cline 通过它加载 `reverse-engineer-anything` 技能；若再移动 `03-Automation-Agents\REA`，
必须同步重建该联接，否则技能会静默失效。

## 启动方式

```bat
:: 静态分析（各自独立，双击即用）
...\01-Disassembly-Debug\RE-Toolkit\Start-Cutter.cmd
...\01-Disassembly-Debug\RE-Toolkit\Start-x64dbg.cmd
...\01-Disassembly-Debug\RE-Toolkit\Start-dnSpy.cmd
...\01-Disassembly-Debug\RE-Toolkit\Start-DIE.cmd
...\01-Disassembly-Debug\RE-Toolkit\Start-Ghidra.cmd
...\01-Disassembly-Debug\RE-Toolkit\Start-Rizin.cmd     :: 命令行，可传参
...\01-Disassembly-Debug\RE-Toolkit\Start-ImHex.cmd
...\01-Disassembly-Debug\RE-Toolkit\Start-PE-bear.cmd
...\01-Disassembly-Debug\RE-Toolkit\Start-ILSpy.cmd
...\06-Android-Mobile-RE\Start-GDA.cmd
...\06-Android-Mobile-RE\Start-Il2CppDumper.cmd
...\02-Dynamic-Instrumentation\Start-SystemInformer.cmd
...\09-Data-Crypto-Tools\Start-CyberChef.cmd             :: 起本地 HTTP 再开浏览器

:: 动态插桩：把 frida/adb 临时加入当前 shell 的 PATH
call ...\02-Dynamic-Instrumentation\frida\env.cmd

:: 恶意样本 CLI 三件套（capa / floss / yara64）：临时加入 PATH
call ...\07-Malware-Forensics\env.cmd
```

`RE_TOOLKIT` 环境变量与用户 PATH 中的 `Rizin\bin`、`DIE`、`jdk25\bin` 已全部更新，
新开的终端可直接使用 `rizin` / `diec` / `java`。

## MCP 服务

`cline_mcp_settings.json` 中 `ghidra` / `rea` / `frida` 三个服务的 command、args、
cwd 与 env 已全部指向新路径（`pdf-research` 在 `D:\Qlib`，未改动）。**改完需重启
MCP 服务**（Cline 面板中重启，或重载窗口）才会生效。

## 回滚

`_manifest\relocation-manifest.csv` 记录了每一条 `源 → 目标` 及状态，
`_manifest\relocate.log` 是执行日志。反向执行即可恢复原布局（需先删除三个联接）。

## 未纳入本次搬迁

以下目录与逆向相关但**属于工程项目而非工具**，或内含大量写死绝对路径的脚本，
按"不破坏科研/业务工程"原则保留原位：

- `D:\aecg`（740 MB，自主漏洞利用链生成 Agent 工作区；其 README 记录了 `D:\ghidra-mcp`、`D:\frida` 依赖，需要单独更新）
- `D:\aecg_offense`（frida hook / exploit 模板，隶属 aecg）
- `D:\pufayinhang`（1.8 GB，银行 App 逆向案件产物）
- `D:\TouchAlpha`（安卓智能体测试床，非逆向工具）
- `D:\Palantir_Research`（科研工程；其 `tools\unidbg` 已通过联接指向新位置）
- `D:\Cline_Dev_Workspace`（开发工作区）

## venv 搬迁注意事项（已处理）

Windows 虚拟环境里 `Scripts\*.exe` 是 **distlib 启动器**，内部**硬编码了创建时的
绝对路径**。目录一搬，这些 .exe 就会静默退出（`exit code 1`、无任何输出）。
`python.exe` 本身不受影响（它靠同目录 `pyvenv.cfg` 定位基础解释器），所以 MCP 服务
（直接调 `python.exe server.py`）在搬迁后仍能工作，但命令行入口会坏。

已用**钉死版本重装**的方式重建包装：

| venv | 已重建 | 结果 |
|---|---|---|
| `frida\.venv` | `frida-tools==14.10.4`、`pip==26.2.1` | `frida.exe` / `frida-ps.exe` → `17.18.0` |
| `ghidra-mcp\.venv` | `pyghidra==3.1.0`、`pip==26.2.1` | `pip.exe` / `pyghidra.exe` 正常 |

仍有以下**次要**包装未重建（功能不受影响，用时改用 `python -m <module>` 即可）：
`mcp.exe`、`uvicorn.exe`、`httpx2.exe`、`idna.exe`、`jsonschema.exe`、`pywin32_*.exe`、
`uiautomator2.exe`、`u2cli.exe`、`normalizer.exe`、`pygmentize.exe`、`cffi-gen-src.exe`。

`RevLab\packaging\.venv-build` 与 `RE_Automation_Framework\.venv-build` 是**打包用**环境
（PyInstaller），其中的 `pip.exe` / `pyi-*.exe` / `pyinstaller.exe` 同样失效；
它们只在重新打包时才需要，且 `dist\` 产物已存在，故未重建。

如果日后确实需要这些 exe 全部可用，最省事的兜底是重新建立旧路径联接（0 字节）：
`mklink /J D:\frida <本目录>\02-Dynamic-Instrumentation\frida` 等。

## 已知遗留问题（搬迁前既存）

- `05-Cases\GhidraProjects\lki\lki.gpr` 为 **0 字节**空壳（`lki.rep` 数据本身完好），
  双击无法打开，需在 Ghidra 中重建工程文件。
- `04-Runtimes\node` 的子项 ACL 属主为 SYSTEM/Administrators（当年提权安装所致），
  当前用户对目录根已补 `FullControl`；`npm -g` 全局安装仍可能因写权限失败。
- 系统 `JAVA_HOME` 仍指向 `C:\Java\jdk1.8.0_201`（该目录实际不存在），属无关的历史脏值；
  Ghidra 不读 `JAVA_HOME`，故不影响。

## 2026-10 新增工具（GitHub 官方 release 直取 + SHA-256 校验）

新增工具全部走 `_downloads\manifest.json` 统一管理，每条记录字段：
`repo / tag / name / size / digest / url / dest`（`digest` 取自 GitHub release asset 的
`sha256:` 字段；`ScyllaHide`、`Il2CppDumper` 两个 asset 上游**没有** digest，只校验字节数）。

```bat
:: 全部下载（并发 6，单文件日志 _dl_<name>.log）
powershell -ExecutionPolicy Bypass -File _downloads\_dl_all.ps1
:: 单个文件（镜像顺序 ghfast.top → ghproxy.net → gh-proxy.com → GitHub 直连，可断点续传）
powershell -ExecutionPolicy Bypass -File _downloads\_dl_one.ps1 -Name imhex-1.38.1-Windows-Portable-x86_64.zip
:: 大文件分块并发（镜像每条连接只给约 4 MB 就限速，故按 3 MB 切块轮转）
powershell -ExecutionPolicy Bypass -File _downloads\_dl_fast.ps1 -Name X.zip -BlockMB 3 -Parallel 8
:: 校验通过后解包到 dest（zip 内单层目录自动展平，.jar 直接复制）
powershell -ExecutionPolicy Bypass -File _downloads\_install.ps1
```

| 分类 | 工具 | 版本 | 位置 | 启动 |
|---|---|---|---|---|
| 01 静态分析 | ImHex | 1.38.1 | `01-Disassembly-Debug\ImHex` | `RE-Toolkit\Start-ImHex.cmd` |
| 01 静态分析 | PE-bear | 0.7.2 | `01-Disassembly-Debug\PE-bear` | `RE-Toolkit\Start-PE-bear.cmd` |
| 01 静态分析 | ILSpy（self-contained） | 11.2 | `01-Disassembly-Debug\ILSpy` | `RE-Toolkit\Start-ILSpy.cmd` |
| 02 动态插桩 | SystemInformer | 4.0.26241.138 | `02-Dynamic-Instrumentation\SystemInformer` | `Start-SystemInformer.cmd` |
| 02 动态插桩 | ScyllaHide | v1.4 | `02-Dynamic-Instrumentation\ScyllaHide` | 已复制进 `RE-Toolkit\x64dbg\release\{x64,x32}\plugins`（`ScyllaHideX64DBGPlugin.dp64/dp32` + `HookLibraryx*.dll` + `scylla_hide.ini`） |
| 06 安卓 | Apktool | 3.0.3 | `06-Android-Mobile-RE\Apktool` | `apktool.cmd d/b/if ...` |
| 06 安卓 | GDA | 4.12 | `06-Android-Mobile-RE\GDA` | `Start-GDA.cmd` |
| 06 安卓 | Il2CppDumper | 6.7.46 | `06-Android-Mobile-RE\Il2CppDumper` | `Start-Il2CppDumper.cmd` |
| 07 恶意代码 | capa | 10.0.0 | `07-Malware-Forensics\capa` | `capa.exe <样本>` |
| 07 恶意代码 | FLOSS | 3.2.0 | `07-Malware-Forensics\FLOSS` | `floss.exe <样本>` |
| 07 恶意代码 | YARA | 4.6.0 | `07-Malware-Forensics\YARA` | `yara64.exe <规则> <样本>` |
| 09 数据/密码 | CyberChef | 11.5.0 | `09-Data-Crypto-Tools\CyberChef` | `Start-CyberChef.cmd` |

几个使用要点：

- **ILSpy 用 self-contained 包**：本机没有 .NET 运行时，`ILSpy_windows_selfcontained_*` 自带运行时，
  双击 `Start-ILSpy.cmd` 即可，无需装 .NET。
- **CyberChef 必须走 HTTP**：zip 里只有 `index.html.gz/.br`（已从 `.gz` 还原出 `index.html`），
  且它的 Web Worker 在 `file://` 下会被浏览器拒绝加载，所以 `Start-CyberChef.cmd` 用
  `08-Python-RE-Toolchain\.venv` 的 python 起一个 `127.0.0.1:8765` 静态服务再开浏览器。
- **apktool.cmd 固定用 04-Runtimes\jdk25**，不依赖系统 Java；`java -jar ... --version` = `3.0.3`。
- **ScyllaHide 已装进 x64dbg**：`02-...\ScyllaHide\x64dbg\x{64,32}\plugins\` 的三个文件已复制到
  `01-...\RE-Toolkit\x64dbg\release\x{64,32}\plugins\`，x64dbg 启动后菜单 `插件 → ScyllaHide` 即可
  反反调试；另有 `IDA\`、`Olly1/2\`、`TitanEngine\`、`Generic\` 及 `InjectorCLIx64.exe`（可对独立进程注入）。
- **capa / FLOSS 是 PyInstaller 单文件**，首次运行需解包几秒；三者都可用
  `call ...\07-Malware-Forensics\env.cmd` 一次性加入当前 shell 的 PATH（实测 `capa.exe 10.0.0`、
  `yara64.exe 4.6.0`、`floss.exe v3.2.0`）。capa 自带规则只覆盖通用能力，要社区规则请 clone
  `mandiant/capa-rules` 后用 `-r` 指定（**规则库需联网另下，本次未包含**）。

### 08-Python-RE-Toolchain 共享 venv

`setup-pyenv.ps1` 建立 `.venv`（Python 3.12.10）并安装 pefile / oletools / capstone / unicorn /
keystone-engine / lief / pyelftools / objection / mitmproxy，末尾做 import 自检并把
`pip freeze` 写入 `requirements-lock.txt`。PyPI 对大 wheel 偶发卡住时脚本会自动改用清华镜像重试：

```bat
powershell -ExecutionPolicy Bypass -File 08-Python-RE-Toolchain\setup-pyenv.ps1
```

