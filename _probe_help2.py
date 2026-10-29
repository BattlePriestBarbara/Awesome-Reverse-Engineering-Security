"""Second probe pass: ImHex subcommand syntax, Il2CppDumper args, misc paths/facts."""
import io
import os
import subprocess

R = r"D:\逆向工具网络安全汇总"
OUT = os.path.join(R, "_help2.txt")
IMHEX = os.path.join(R, r"01-Disassembly-Debug\ImHex\imhex.exe")
buf = io.StringIO()


def sh(label, cmd, timeout=30):
    buf.write("=" * 70 + "\n== " + label + "\n$ " + " ".join(cmd) + "\n")
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        text = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
        buf.write(text[:2500] + ("\n...(truncated)\n" if len(text) > 2500 else "") + "\n")
    except Exception as exc:  # noqa: BLE001
        buf.write("ERR %s: %s\n" % (type(exc).__name__, exc))


for sub in ("--hash", "--magic", "--hexdump", "--pl", "--calc", "--encode", "--decode", "--demangle"):
    sh("imhex " + sub, [IMHEX, sub, "-h"])

sh("imhex --magic sample", [IMHEX, "--magic", os.path.join(R, r"01-Disassembly-Debug\PE-bear\PE-bear.exe")])
sh("imhex --hash sample", [IMHEX, "--hash", os.path.join(R, r"01-Disassembly-Debug\PE-bear\PE-bear.exe")])
sh("imhex --hexdump sample", [IMHEX, "--hexdump", "-i", os.path.join(R, r"01-Disassembly-Debug\PE-bear\PE-bear.exe")])

IL2CPP = os.path.join(R, r"06-Android-Mobile-RE\Il2CppDumper\Il2CppDumper.exe")
sh("Il2CppDumper ?", [IL2CPP, "-h"])
sh("Il2CppDumper /?", [IL2CPP, "/?"])

# facts
buf.write("\n#### facts\n")
buf.write("analyzeHeadless exists: %s\n" % os.path.exists(os.path.join(R, r"01-Disassembly-Debug\Ghidra\support\analyzeHeadless.bat")))
buf.write("ghidraRun: %s\n" % os.path.exists(os.path.join(R, r"01-Disassembly-Debug\Ghidra\ghidraRun.bat")))
for rel in (r"01-Disassembly-Debug\RE-Toolkit\x64dbg\release\x64", r"01-Disassembly-Debug\RE-Toolkit\x64dbg\release\x32"):
    p = os.path.join(R, rel)
    exes = [f for f in os.listdir(p) if f.lower().endswith(".exe")] if os.path.isdir(p) else []
    buf.write("%s exes: %s\n" % (rel, sorted(exes)[:6]))
lp = os.path.join(R, r"02-Dynamic-Instrumentation\LSPosed")
apks = []
for root, _dirs, files in os.walk(lp):
    apks += [os.path.join(root, f) for f in files if f.lower().endswith((".apk", ".dex"))]
buf.write("LSPosed apk/dex samples: %s\n" % apks[:6])
fv = os.path.join(R, r"02-Dynamic-Instrumentation\frida\.venv\Scripts")
buf.write("frida venv scripts (subset): %s\n" % [f for f in os.listdir(fv) if f.startswith(("frida", "objection"))][:8])
sh("frida-tools version", [os.path.join(fv, "frida.exe"), "--version"])
sh("pip show frida-tools", [os.path.join(R, r"02-Dynamic-Instrumentation\frida\.venv\Scripts\python.exe"), "-m", "pip", "show", "frida-tools"])
sh("objection", [os.path.join(R, r"08-Python-RE-Toolchain\.venv\Scripts\objection.exe"), "--version"])
sh("ghidra props", ["powershell", "-NoProfile", "-Command",
                    "(Get-Content -LiteralPath '%s' -TotalCount 5) -join ' | '" % os.path.join(R, r"01-Disassembly-Debug\Ghidra\GPL\application.properties")])

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(buf.getvalue())
print("written", OUT, os.path.getsize(OUT))
