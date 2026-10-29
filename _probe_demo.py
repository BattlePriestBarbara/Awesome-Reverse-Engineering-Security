"""Third probe pass: run the documented commands once so the manual quotes real output."""
import glob
import io
import os
import shutil
import subprocess
import tempfile

R = r"D:\逆向工具网络安全汇总"
OUT = os.path.join(R, "_demo.txt")
PY = os.path.join(R, r"08-Python-RE-Toolchain\.venv\Scripts\python.exe")
IMHEX = os.path.join(R, r"01-Disassembly-Debug\ImHex\imhex.exe")
DIE = os.path.join(R, r"01-Disassembly-Debug\RE-Toolkit\DIE\diec.exe")
RZBIN = os.path.join(R, r"01-Disassembly-Debug\RE-Toolkit\Rizin\bin\rz-bin.exe")
APKTOOL = os.path.join(R, r"06-Android-Mobile-RE\apktool.cmd")
YARA = os.path.join(R, r"07-Malware-Forensics\YARA\yara64.exe")
YARAC = os.path.join(R, r"07-Malware-Forensics\YARA\yarac64.exe")
CAPA = os.path.join(R, r"07-Malware-Forensics\capa\capa.exe")
FLOSS = os.path.join(R, r"07-Malware-Forensics\FLOSS\floss.exe")
SAMPLE = os.path.join(R, r"02-Dynamic-Instrumentation\ScyllaHide\ScyllaTest_x64.exe")
PEBEAR = os.path.join(R, r"01-Disassembly-Debug\PE-bear\PE-bear.exe")
APK = os.path.join(R, r"02-Dynamic-Instrumentation\LSPosed\_apk\LSPosed_v1_9_2_7024_zygisk_release_zip\manager.apk")
buf = io.StringIO()


def sh(label, cmd, timeout=240, limit=1800):
    buf.write("=" * 70 + "\n== " + label + "\n$ " + " ".join(cmd) + "\n")
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
        text = ((p.stdout or b"") + (p.stderr or b"")).decode("utf-8", "replace")
        buf.write(text[:limit] + ("\n...(truncated)\n" if len(text) > limit else "") + "\n")
    except Exception as exc:  # noqa: BLE001
        buf.write("ERR %s: %s\n" % (type(exc).__name__, exc))
    buf.write("\n")


# --- ImHex CLI
sh("imhex --magic desc", [IMHEX, "--magic", "desc", PEBEAR])
sh("imhex --magic mime", [IMHEX, "--magic", "mime", PEBEAR])
sh("imhex --hash sha256", [IMHEX, "--hash", "sha256", SAMPLE])
sh("imhex --hexdump 0 64", [IMHEX, "--hexdump", PEBEAR, "0", "64"])
sh("imhex --calc", [IMHEX, "--calc", "0x30*2"])
sh("imhex --encode base64", [IMHEX, "--encode", "base64", "hello"])
sh("imhex --demangle", [IMHEX, "--demangle", "_Z3fooi"])

# --- DIE
sh("diec -j", [DIE, "-j", SAMPLE], limit=2500)
sh("diec -e -i", [DIE, "-e", "-i", SAMPLE], limit=1200)

# --- rizin
sh("rz-bin -I", [RZBIN, "-I", SAMPLE], limit=1200)
sh("rz-bin -zj (first part)", [RZBIN, "-j", "-z", "-N", "6:120", SAMPLE], limit=1200)

# --- YARA
tmp = tempfile.mkdtemp(prefix="yara_demo_")
rule = os.path.join(tmp, "demo.yar")
with open(rule, "w", encoding="utf-8") as fh:
    fh.write('rule demo_mz_pe {\n  meta:\n    author = "manual"\n  strings:\n    $mz = { 4D 5A }\n'
             '    $pe = "PE\\0\\0" ascii\n  condition:\n    $mz at 0 and $pe\n}\n')
compiled = os.path.join(tmp, "demo.yarc")
sh("yarac64 compile", [YARAC, rule, compiled])
sh("yara64 -s -m", [YARA, "-s", "-m", rule, SAMPLE])
sh("yara64 -C compiled", [YARA, "-C", compiled, SAMPLE])

# --- capa / floss on a small known PE
sh("capa", [CAPA, SAMPLE], timeout=300, limit=1500)
sh("capa -j (head)", [CAPA, "-j", SAMPLE], timeout=300, limit=800)
sh("floss --only static", [FLOSS, "--only", "static", SAMPLE], timeout=300, limit=1200)

# --- apktool real decode
out_dir = os.path.join(tempfile.gettempdir(), "apktool_demo")
shutil.rmtree(out_dir, ignore_errors=True)
sh("apktool d manager.apk", ["cmd", "/c", APKTOOL, "d", APK, "-o", out_dir, "-f"], timeout=300, limit=1200)
buf.write("apktool output tree (top): %s\n" % (sorted(os.listdir(out_dir))[:12] if os.path.isdir(out_dir) else "MISSING"))
smali = glob.glob(os.path.join(out_dir, "smali*"))
buf.write("smali dirs: %s\n" % [os.path.basename(p) for p in smali])
buf.write("AndroidManifest.xml size: %s\n" % (
    os.path.getsize(os.path.join(out_dir, "AndroidManifest.xml")) if os.path.exists(os.path.join(out_dir, "AndroidManifest.xml")) else "n/a"))
shutil.rmtree(out_dir, ignore_errors=True)
shutil.rmtree(tmp, ignore_errors=True)

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(buf.getvalue())
print("written", OUT, os.path.getsize(OUT))
