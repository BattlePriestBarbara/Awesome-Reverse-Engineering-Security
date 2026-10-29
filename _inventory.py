"""Quick inventory of the toolkit: versions + entry points, printed as JSON.

Run with the shared venv python:
    .venv\\Scripts\\python.exe ..\\_inventory.py
"""
import json
import os
import subprocess
import sys

R = r"D:\逆向工具网络安全汇总"


def run(cmd, timeout=20):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=R)
        out = (p.stdout or b"").decode("utf-8", "replace").strip()
        err = (p.stderr or b"").decode("utf-8", "replace").strip()
        return (out or err).splitlines()[0] if (out or err) else ""
    except Exception as exc:  # noqa: BLE001
        return "ERR " + type(exc).__name__ + ": " + str(exc)


def pe_ver(rel):
    """FileVersion from the PE resource, via PowerShell (no extra deps)."""
    path = os.path.join(R, rel)
    if not os.path.exists(path):
        return "MISSING"
    ps = (
        "(Get-Item -LiteralPath '" + path + "').VersionInfo | "
        "ForEach-Object { $_.FileVersion + '/' + $_.ProductVersion }"
    )
    return run(["powershell", "-NoProfile", "-Command", ps], timeout=30)


def listing(rel):
    path = os.path.join(R, rel)
    return ", ".join(sorted(os.listdir(path))) if os.path.isdir(path) else "MISSING"


data = {
    "root_listing": listing("."),
    "cutter": pe_ver(r"01-Disassembly-Debug\RE-Toolkit\Cutter\cutter.exe"),
    "rizin": run([os.path.join(R, r"01-Disassembly-Debug\RE-Toolkit\Rizin\bin\rizin.exe"), "--version"]),
    "rizin_bin": listing(r"01-Disassembly-Debug\RE-Toolkit\Rizin\bin"),
    "x64dbg": pe_ver(r"01-Disassembly-Debug\RE-Toolkit\x64dbg\release\x64\x64dbg.exe"),
    "x64dbg_tree": listing(r"01-Disassembly-Debug\RE-Toolkit\x64dbg"),
    "dnspy": pe_ver(r"01-Disassembly-Debug\RE-Toolkit\dnSpy\dnSpy.exe"),
    "die_dir": listing(r"01-Disassembly-Debug\RE-Toolkit\DIE"),
    "diec_ver": run([os.path.join(R, r"01-Disassembly-Debug\RE-Toolkit\DIE\diec.exe"), "--version"]),
    "ghidra_dir": listing(r"01-Disassembly-Debug\Ghidra"),
    "jadx_dir": listing(r"01-Disassembly-Debug\jadx"),
    "ghidra_mcp_dir": listing(r"01-Disassembly-Debug\ghidra-mcp"),
    "frida": run([os.path.join(R, r"02-Dynamic-Instrumentation\frida\.venv\Scripts\frida.exe"), "--version"]),
    "frida_dir": listing(r"02-Dynamic-Instrumentation\frida"),
    "unidbg_dir": listing(r"02-Dynamic-Instrumentation\unidbg"),
    "lsposed_dir": listing(r"02-Dynamic-Instrumentation\LSPosed"),
    "node": run([os.path.join(R, r"04-Runtimes\node\node.exe"), "-v"]),
    "java": run([os.path.join(R, r"04-Runtimes\jdk25\bin\java.exe"), "-version"]),
    "rea_dir": listing(r"03-Automation-Agents\REA"),
    "revlab_dir": listing(r"03-Automation-Agents\RevLab"),
    "reafw_dir": listing(r"03-Automation-Agents\RE_Automation_Framework"),
    "autorev_dir": listing(r"03-Automation-Agents\AutoRev-Crypto"),
    "cases_dir": listing("05-Cases"),
    "imhex_ver": run([os.path.join(R, r"01-Disassembly-Debug\ImHex\imhex.exe"), "--version-short"]),
    "py_ver": run([os.path.join(R, r"08-Python-RE-Toolchain\.venv\Scripts\python.exe"), "-c",
                   "import sys;print(sys.version.split()[0])"]),
}

print(json.dumps(data, ensure_ascii=False, indent=2))
