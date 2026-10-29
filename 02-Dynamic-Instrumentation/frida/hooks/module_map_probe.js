// module_map_probe.js - structured (send-based) snapshot of the target's loaded modules.
//
// Why this exists: the frida-mcp sink records ONLY send() payloads (console.log is dropped),
// so console-only hooks report "0 events". This probe emits ONE JSON record that answers, on
// the live process, the decisive question from the dynamic report (section 9.3):
//   * which ABI directories the app's own .so files are mapped from,
//   * whether the ARM translation layer (libnb) modules are visible in this address space.
//
// Usage: frida_run_script(target=<process name>, source_path=D:\frida\hooks\module_map_probe.js)

function abiOf(path) {
    var m = /\/(arm64-v8a|armeabi-v7a|armeabi|x86_64|x86)\//.exec(path || "");
    return m ? m[1] : "?";
}

setImmediate(function () {
    var mods = Process.enumerateModules();
    var app = [];
    var abiCounts = {};
    var nb = [];

    mods.forEach(function (m) {
        var p = m.path || "";
        if (/\/data\/(app|data)\/com\.hicorenational\.antifraud/.test(p)) {
            var abi = abiOf(p);
            var onload = null;
            try { onload = m.getExportByName("JNI_OnLoad"); } catch (e) { }
            app.push({
                name: m.name,
                abi: abi,
                base: m.base.toString(),
                sizeKB: Math.round(m.size / 1024),
                jniOnLoad: onload ? onload.toString() : null
            });
            abiCounts[abi] = (abiCounts[abi] || 0) + 1;
        }
        if (/\/nb\//.test(p) || /\/lib64\/arm64\//.test(p) || /\/lib64\/arm\//.test(p)) {
            nb.push({ name: m.name, path: p });
        }
    });

    send({
        kind: "module_map",
        arch: Process.arch,
        pointerSize: Process.pointerSize,
        totalModules: mods.length,
        appModuleCount: app.length,
        appAbiCounts: abiCounts,
        appModules: app,
        armGuestCount: nb.length,
        armGuestSample: nb.slice(0, 30)
    });
});
