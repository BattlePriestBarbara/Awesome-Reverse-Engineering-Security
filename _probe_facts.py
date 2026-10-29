"""Fourth probe pass: remaining version facts, launcher inventory, fixed YARA example."""
import io
import os
import subprocess
import tempfile

R = r"D:\逆向工具网络安全汇总"
OUT = os.path.join(R, r"_facts.txt")
buf = io.StringIO()


def ps(script):
    p = subprocess.run(["powershell", "-NoProfile", "-Command", script], capture_output=True, timeout=60)
    return ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace").strip()


def pe_ver(rel):
    path = os.path.join(R, rel)
    if not os.path.exists(path):
        return "MISSING"
    return ps("(Get-Item -LiteralPath '" + path + "').VersionInfo | ForEach-Object "
              "{ $_.FileVersion + ' / ' + $_.ProductVersion + ' / ' + $_.FileDescription }")


buf.write("### versions\n")
for rel in (r"06-Android-Mobile-RE\GDA\GDA.exe",
            r"02-Dynamic-Instrumentation\SystemInformer\amd64\SystemInformer.exe",
            r"01-Disassembly-Debug\PE-bear\PE-bear.exe",
            r"06-Android-Mobile-RE\Il2CppDumper\Il2CppDumper.exe",
            r"02-Dynamic-Instrumentation\ScyllaHide\ScyllaHideInjectorCLI\InjectorCLIx64.exe",
            r"07-Malware-Forensics\capa\capa.exe",
            r"07-Malware-Forensics\FLOSS\floss.exe",
            r"07-Malware-Forensics\YARA\yara64.exe",
            r"01-Disassembly-Debug\RE-Toolkit\Rizin\bin\rizin.exe"):
    buf.write("%-72s %s\n" % (rel, pe_ver(rel)))

buf.write("\n### ghidra application.properties\n")
gp = os.path.join(R, r"01-Disassembly-Debug\Ghidra\Ghidra\application.properties")
buf.write("exists=%s\n" % os.path.exists(gp))
if os.path.exists(gp):
    with open(gp, "r", encoding="latin-1") as fh:
        buf.write("\n".join(fh.read().splitlines()[:6]) + "\n")

buf.write("\n### scyllahide dir\n")
for d in (r"02-Dynamic-Instrumentation\ScyllaHide", r"01-Disassembly-Debug\RE-Toolkit\x64dbg\release\x64\plugins"):
    p = os.path.join(R, d)
    buf.write("%s: %s\n" % (d, sorted(os.listdir(p))[:20] if os.path.isdir(p) else "MISSING"))

buf.write("\n### launchers (*.cmd / *.ps1 / *.bat, depth<=3)\n")
for root, dirs, files in os.walk(R):
    rel = os.path.relpath(root, R)
    depth = 0 if rel == "." else rel.count(os.sep) + 1
    if depth > 3 or rel.startswith(("_downloads", "05-Cases", "04-Runtimes", "03-Automation-Agents", "01-Disassembly-Debug\\Ghidra", "01-Disassembly-Debug\\ImHex")):
        dirs[:] = []
        continue
    for f in sorted(files):
        if f.lower().endswith((".cmd", ".ps1", ".bat")):
            buf.write("%s\n" % os.path.join(rel, f))

buf.write("\n### fixed YARA example\n")
tmp = tempfile.mkdtemp(prefix="yara2_")
rule = os.path.join(tmp, "demo.yar")
with open(rule, "w", encoding="utf-8") as fh:
    fh.write('rule demo_mz_pe {\n    meta:\n        author = "manual"\n    strings:\n'
             '        $mz = { 4D 5A }\n        $pe = { 50 45 00 00 }\n'
             '    condition:\n        $mz at 0 and $pe\n}\n')
sample = os.path.join(R, r"02-Dynamic-Instrumentation\ScyllaHide\ScyllaTest_x64.exe")
for label, cmd in (("yara64 -s -m", [os.path.join(R, r"07-Malware-Forensics\YARA\yara64.exe"), "-s", "-m", rule, sample]),
                   ("yarac64", [os.path.join(R, r"07-Malware-Forensics\YARA\yarac64.exe"), rule, os.path.join(tmp, "demo.yarc")])):
    p = subprocess.run(cmd, capture_output=True, timeout=90)
    buf.write("$ " + " ".join(cmd) + "\n" + ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace") + "\n")
p = subprocess.run([os.path.join(R, r"07-Malware-Forensics\YARA\yara64.exe"), "-C",
                    os.path.join(tmp, "demo.yarc"), sample], capture_output=True, timeout=90)
buf.write("$ yara64 -C demo.yarc sample\n" + ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace") + "\n")

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(buf.getvalue())
print("written", OUT, os.path.getsize(OUT))
