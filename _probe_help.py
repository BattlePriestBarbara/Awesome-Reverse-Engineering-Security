"""Collect real --help output for the CLI tools so the manual quotes correct flags."""
import io
import os
import subprocess

R = r"D:\逆向工具网络安全汇总"
OUT = os.path.join(R, "_help.txt")

CMDS = [
    ("diec", [r"01-Disassembly-Debug\RE-Toolkit\DIE\diec.exe", "--help"]),
    ("rz-bin", [r"01-Disassembly-Debug\RE-Toolkit\Rizin\bin\rz-bin.exe", "-h"]),
    ("rz-asm", [r"01-Disassembly-Debug\RE-Toolkit\Rizin\bin\rz-asm.exe", "-h"]),
    ("capa", [r"07-Malware-Forensics\capa\capa.exe", "-h"]),
    ("floss", [r"07-Malware-Forensics\FLOSS\floss.exe", "-h"]),
    ("yara64", [r"07-Malware-Forensics\YARA\yara64.exe", "--help"]),
    ("Il2CppDumper", [r"06-Android-Mobile-RE\Il2CppDumper\Il2CppDumper.exe"]),
    ("imhex", [r"01-Disassembly-Debug\ImHex\imhex.exe", "--help"]),
    ("jadx_dir", None),
    ("yara_files", None),
    ("platform_tools", None),
]

buf = io.StringIO()
for name, cmd in CMDS:
    buf.write("=" * 70 + "\n== " + name + "\n")
    if name == "jadx_dir":
        p = os.path.join(R, r"01-Disassembly-Debug\jadx")
        buf.write("jadx entries: %r\n" % (os.listdir(p) if os.path.isdir(p) else "missing"))
        continue
    if name == "yara_files":
        p = os.path.join(R, r"07-Malware-Forensics\YARA")
        buf.write("YARA entries: %r\n" % sorted(os.listdir(p)))
        continue
    if name == "platform_tools":
        p = os.path.join(R, r"02-Dynamic-Instrumentation\frida\platform-tools")
        buf.write("platform-tools: %r\n" % (sorted(os.listdir(p)) if os.path.isdir(p) else "missing"))
        continue
    exe = os.path.join(R, cmd[0])
    if not os.path.exists(exe):
        buf.write("MISSING " + exe + "\n")
        continue
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=90, cwd=os.path.dirname(exe),
                           stdin=subprocess.DEVNULL)
        text = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001
        text = "ERR %s: %s" % (type(exc).__name__, exc)
    lines = text.splitlines()
    buf.write("\n".join(lines[:60]) + ("\n...(truncated, %d lines total)\n" % len(lines) if len(lines) > 60 else "\n"))

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(buf.getvalue())
print("written", OUT, os.path.getsize(OUT))
