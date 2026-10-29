/*
 * root_bypass_arm64.js - native-layer root / su / Magisk concealment for ARM64 real devices.
 *
 * WHY NATIVE AND NOT JAVA
 * -----------------------
 * The target (com.hicorenational.antifraud, "360 jiagu VIP" + DTC/dex2c) compiles its own
 * Java methods to native code, and its root check does not come back through the Java
 * boundary: on the LDPlayer run every Java-layer probe stayed silent (File.exists,
 * Runtime.exec, PackageManager.getPackageInfo and 21 framework APIs, zero hits) while the
 * app was demonstrably running a ROOT check (dialog "本应用不支持ROOT设备" + self-close).
 * The check therefore runs below ART, inside libjiagu_vip_64.so / the DTC'd code, and any
 * path-based test has to pass through libc. That is where this script sits.
 *
 * Java-level equivalents (File.exists, Runtime.exec, PackageManager.getPackageInfo) live in
 * agent/agent9.js, which needs frida-compile because Frida 17 no longer bundles the Java
 * bridge. Use BOTH layers: agent9 covers the parts ART still executes, this file covers the
 * DTC/native parts that agent9 cannot reach.
 *
 * STRATEGY (narrow denylist, fail-closed only on it; everything else passes through)
 * --------------------------------------------------------------------------------
 *   open/openat/open64/openat64/fopen/fopen64/freopen   -> -1 / NULL + errno ENOENT
 *   access/faccessat                                    -> -1 + errno ENOENT
 *   stat/stat64/lstat/lstat64/fstatat                   -> -1 + errno ENOENT
 *   readlink/readlinkat                                 -> -1 + errno ENOENT
 *   opendir/readdir                                     -> su/magisk entries inside a
 *                                                          known bin dir are skipped
 *   execve/execv/execvp/fexecve/posix_spawn/posix_spawnp -> -1 + errno EPERM
 *   __system_property_get                               -> ro.debuggable/ro.secure/
 *                                                          ro.build.tags/... rewritten
 *   (opt-in) scrub_maps                                 -> /proc/self/maps is served from a
 *                                                          memfd with frida/magisk lines
 *                                                          removed (see CFG.scrub_maps)
 *
 * Every blocked call is reported once as a send() record, so the JSONL proves what the app
 * actually probed. All NativeFunction/Interceptor work is individually try/catch-guarded:
 * a single failed hook must never take the process down.
 *
 * USAGE
 *   MCP :  frida_run_hook(target="<pid|name>", hook="root_bypass_arm64", seconds=60,
 *                         script_args={"verbose":true,"cap":200})
 *   CLI :  D:\frida\frida.cmd -U -p <pid> -l D:\frida\hooks\root_bypass_arm64.js
 *
 * NOTE ON ABI: attach+onLeave is used for every variadic-capable libc function (open/openat
 * are variadic through the mode argument), so the original ABI is untouched. Only
 * non-variadic functions (readdir, execve, __system_property_get) are Interceptor.replace'd.
 *
 * NOTE ON Arm64 DIRENTS: bionic's struct dirent is
 *   { uint64 d_ino; int64 d_off; uint16 d_reclen; uint8 d_type; char d_name[256]; }
 * so d_name sits at offset 19 on arm64 (CFG.d_name_offset overrides it).
 */

var CFG = (typeof FRIDA_MCP_ARGS === "object" && FRIDA_MCP_ARGS) || {};
var T0 = Date.now();

var VERBOSE = CFG.verbose !== false;
var CAP = typeof CFG.cap === "number" ? CFG.cap : 200;
var MAX_RECORDS = typeof CFG.max_records === "number" ? CFG.max_records : 3000;
var SCRUB_MAPS = CFG.scrub_maps === true;      // opt-in: see the readme note above
var MASK_PROPS = CFG.mask_props !== false;     // default on: cheap and high value
var D_NAME_OFFSET = typeof CFG.d_name_offset === "number" ? CFG.d_name_offset : 19;

var counters = {};
var sent = 0;

function bump(map, key) {
    map[key] = (map[key] || 0) + 1;
}

function emit(record) {
    if (!VERBOSE) return;
    if (sent >= MAX_RECORDS) { bump(counters, "record_cap_dropped"); return; }
    sent++;
    try {
        record.t_ms = Date.now() - T0;
        record.type = record.type || "event";
        send(record);
    } catch (e) { /* never let reporting break the hook */ }
}

function safeCStr(p) {
    try {
        if (p === null || p.isNull()) return null;
        return p.readCString();
    } catch (e) { return null; }
}

function libc() {
    try { return Process.findModuleByName("libc.so") || Process.findModuleByName("libc.so.6"); }
    catch (e) { return null; }
}

function libcExport(name) {
    var module = libc();
    if (!module) return null;
    try { return module.getExportByName(name); } catch (e) { return null; }
}

// errno must be rewritten AFTER the real call already set it, so the hook order is:
// retval.replace(...) then setErrno(...).
var setErrno = (function () {
    var addr = libcExport("__errno") || libcExport("__errno_location");
    if (!addr) return function () { };
    var fn;
    try { fn = new NativeFunction(addr, "pointer", []); } catch (e) { return function () { }; }
    return function (code) {
        try { fn().writeInt(code); } catch (e) { }
    };
})();

var EPERM = 1, ENOENT = 2, EACCES = 13;

// ---------------------------------------------------------------------------------------
// denylist
// ---------------------------------------------------------------------------------------
var DENY_PATTERNS = [
    /(^|\/)su(\.\w+)?$/i,                 // /system/bin/su, /system/xbin/su, /sbin/su, ...
    /(^|\/)magisk$/i,
    /(^|\/)magisk(64|32|init|policy|hide|boot|d)$/i,
    /(^|\/)ksud(64)?$/i,
    /(^|\/)supersu$/i,
    /(^|\/)suhide/i,
    /(^|\/)magisk\.apk$/i,
    /(^|\/)superuser\.(apk|dat|db)$/i,
    /\/data\/adb\/magisk/i,
    /\/data\/adb\/modules/i,
    /\/data\/adb\/ksu/i,
    /\/data\/adb\/kernelsu/i,
    /\/sbin\/\.magisk/i,
    /\/dev\/\.magisk/i,
    /(^|\/)busybox\/su$/i
];

// directories whose *directory listing* must not reveal su/magisk entries
var BIN_DIRS = [
    "/system/bin", "/system/xbin", "/system/sbin", "/system/usr/bin",
    "/sbin", "/vendor/bin", "/system/vendor/bin", "/data/adb", "/data/adb/magisk"
];
var DENY_ENTRY_RE = /^(su|su\.\w+|magisk\w*|ksud?\w*|supersu\w*|superuser\w*|suhide\w*)$/i;

function deniedPath(path) {
    if (!path) return false;
    for (var i = 0; i < DENY_PATTERNS.length; i++) {
        if (DENY_PATTERNS[i].test(path)) return true;
    }
    return false;
}

function isBinDir(path) {
    if (!path) return false;
    for (var i = 0; i < BIN_DIRS.length; i++) {
        if (path === BIN_DIRS[i] || path.indexOf(BIN_DIRS[i] + "/") === 0) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------------------
// 1) path-based checks: attach + onLeave (ABI-safe, the real call still runs)
// ---------------------------------------------------------------------------------------
var PATH_SPECS = {
    open: { kind: "int", args: ["pointer", "int"], path: 0 },
    open64: { kind: "int", args: ["pointer", "int"], path: 0 },
    openat: { kind: "int", args: ["int", "pointer", "int"], path: 1 },
    openat64: { kind: "int", args: ["int", "pointer", "int"], path: 1 },
    fopen: { kind: "ptr", args: ["pointer", "pointer"], path: 0 },
    fopen64: { kind: "ptr", args: ["pointer", "pointer"], path: 0 },
    freopen: { kind: "ptr", args: ["pointer", "pointer", "pointer"], path: 0 },
    access: { kind: "int", args: ["pointer", "int"], path: 0 },
    faccessat: { kind: "int", args: ["int", "pointer", "int", "int"], path: 1 },
    stat: { kind: "int", args: ["pointer", "pointer"], path: 0 },
    stat64: { kind: "int", args: ["pointer", "pointer"], path: 0 },
    lstat: { kind: "int", args: ["pointer", "pointer"], path: 0 },
    lstat64: { kind: "int", args: ["pointer", "pointer"], path: 0 },
    fstatat: { kind: "int", args: ["int", "pointer", "pointer", "int"], path: 1 },
    fstatat64: { kind: "int", args: ["int", "pointer", "pointer", "int"], path: 1 },
    readlink: { kind: "int", args: ["pointer", "pointer", "size_t"], path: 0 },
    readlinkat: { kind: "int", args: ["int", "pointer", "pointer", "size_t"], path: 1 }
};

var installed = [];
var missing = [];
var failed = [];

function installPathHooks() {
    Object.keys(PATH_SPECS).forEach(function (symbol) {
        var spec = PATH_SPECS[symbol];
        var address = libcExport(symbol);
        if (!address) { missing.push(symbol); return; }
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    this.denied = false;
                    this.path = null;
                    try {
                        var path = safeCStr(args[spec.path]);
                        if (path !== null && deniedPath(path)) {
                            this.denied = true;
                            this.path = path;
                        }
                    } catch (e) { }
                },
                onLeave: function (retval) {
                    if (!this.denied) return;
                    try {
                        if (spec.kind === "ptr") retval.replace(ptr(0)); else retval.replace(-1);
                        setErrno(ENOENT);
                    } catch (e) { }
                    bump(counters, "blocked:" + symbol);
                    if ((counters["blocked:" + symbol] || 0) <= CAP) {
                        emit({ type: "root_hide", op: symbol, path: this.path, action: "ENOENT" });
                    }
                }
            });
            installed.push(symbol);
        } catch (e) {
            failed.push(symbol + ": " + e);
        }
    });
}

// ---------------------------------------------------------------------------------------
// 2) directory listings: skip su/magisk entries inside BIN_DIRS
//    opendir/opendir64 are attach-only (we just remember DIR* -> path); readdir is
//    replaced because it must be able to consume several entries in one call.
// ---------------------------------------------------------------------------------------
var dirPaths = {};
var MAX_DIR_TRACK = 4096;

function installDirHooks() {
    ["opendir", "opendir64"].forEach(function (symbol) {
        var address = libcExport(symbol);
        if (!address) { missing.push(symbol); return; }
        try {
            Interceptor.attach(address, {
                onEnter: function (args) { this.path = safeCStr(args[0]); },
                onLeave: function (retval) {
                    try {
                        if (!this.path || retval.isNull()) return;
                        if (!isBinDir(this.path)) return;
                        if (Object.keys(dirPaths).length > MAX_DIR_TRACK) dirPaths = {};
                        dirPaths[retval.toString()] = this.path;
                        emit({ type: "root_hide_dir", op: symbol, path: this.path, dir: retval.toString() });
                    } catch (e) { }
                }
            });
            installed.push(symbol);
        } catch (e) { failed.push(symbol + ": " + e); }
    });

    var readdirAddr = libcExport("readdir") || libcExport("readdir64");
    if (!readdirAddr) { missing.push("readdir"); return; }
    try {
        var origReaddir = new NativeFunction(readdirAddr, "pointer", ["pointer"]);
        Interceptor.replace(readdirAddr, new NativeCallback(function (dirp) {
            try {
                var dir = dirPaths[dirp.toString()];
                if (!dir) return origReaddir(dirp);
                for (var guard = 0; guard < 64; guard++) {
                    var entry = origReaddir(dirp);
                    if (entry.isNull()) return entry;
                    var name = null;
                    try { name = entry.add(D_NAME_OFFSET).readCString(); } catch (e) { name = null; }
                    if (name === null) return entry;
                    if (!DENY_ENTRY_RE.test(name)) return entry;
                    bump(counters, "readdir_hidden");
                    if ((counters["readdir_hidden"] || 0) <= CAP) {
                        emit({ type: "root_hide_dir_entry", path: dir, name: name, action: "skipped" });
                    }
                }
                return origReaddir(dirp);
            } catch (e) {
                return origReaddir(dirp);
            }
        }, "pointer", ["pointer"]));
        installed.push("readdir");
    } catch (e) { failed.push("readdir: " + e); }
}

// ---------------------------------------------------------------------------------------
// 3) process spawning: the app runs `su -c id` style checks through Runtime.exec, which
//    reaches fork+exec inside libc. exec* never returns on success, so this family is
//    replace'd (they are non-variadic; execl is deliberately left alone because it is).
// ---------------------------------------------------------------------------------------
var EXEC_SPECS = [
    { name: "execve", args: ["pointer", "pointer", "pointer"], path: 0 },
    { name: "execv", args: ["pointer", "pointer"], path: 0 },
    { name: "execvp", args: ["pointer", "pointer"], path: 0 },
    { name: "fexecve", args: ["int", "pointer", "pointer"], path: -1 },
    { name: "posix_spawn", args: ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer"], path: 1 },
    { name: "posix_spawnp", args: ["pointer", "pointer", "pointer", "pointer", "pointer", "pointer"], path: 1 }
];

function argv0(argvPtr) {
    try {
        if (argvPtr === null || argvPtr.isNull()) return null;
        var first = argvPtr.readPointer();
        if (first.isNull()) return null;
        return first.readCString();
    } catch (e) { return null; }
}

function installExecHooks() {
    EXEC_SPECS.forEach(function (spec) {
        var address = libcExport(spec.name);
        if (!address) { missing.push(spec.name); return; }
        try {
            var orig = new NativeFunction(address, "int", spec.args);
            var callback = new NativeCallback(function () {
                var args = Array.prototype.slice.call(arguments);
                if (IN_INTERNAL) return orig.apply(null, args);
                var path = spec.path >= 0 ? safeCStr(args[spec.path]) : null;
                var argvIndex = spec.name.indexOf("posix_spawn") === 0 ? 4 : 1;
                var a0 = argv0(args[argvIndex]);
                var deny = (path !== null && deniedPath(path)) ||
                    (a0 !== null && DENY_ENTRY_RE.test(a0));
                if (!deny) return orig.apply(null, args);
                setErrno(EPERM);
                bump(counters, "blocked:" + spec.name);
                if ((counters["blocked:" + spec.name] || 0) <= CAP) {
                    emit({ type: "root_hide_exec", op: spec.name, path: path, argv0: a0, action: "EPERM" });
                }
                return -1;
            }, "int", spec.args);
            Interceptor.replace(address, callback);
            installed.push(spec.name);
        } catch (e) { failed.push(spec.name + ": " + e); }
    });
}

// ---------------------------------------------------------------------------------------
// 4) system properties: the classic native root/debuggable probe
// ---------------------------------------------------------------------------------------
var PROP_MASK = {
    "ro.debuggable": "0",
    "ro.secure": "1",
    "ro.build.tags": "release-keys",
    "ro.build.type": "user",
    "ro.build.selinux": "1",
    "ro.kernel.qemu": "0",
    "ro.boot.verifiedbootstate": "green",
    "ro.boot.flash.locked": "1",
    "ro.boot.veritymode": "enforcing",
    "service.adb.root": "0",
    "ro.boot.selinux": "enforcing"
};
var PROP_INTEREST_RE = /(debuggable|secure|build\.(tags|type)|qemu|verifiedboot|flash\.locked|adb|selinux|magisk|su|board|hardware|product\.(model|name|device))/i;
var propSeen = {};

function installPropHook() {
    var address = libcExport("__system_property_get");
    if (!address) { missing.push("__system_property_get"); return; }
    try {
        var orig = new NativeFunction(address, "int", ["pointer", "pointer"]);
        Interceptor.replace(address, new NativeCallback(function (namePtr, valuePtr) {
            var name = null;
            try { name = namePtr.readCString(); } catch (e) { name = null; }
            if (IN_INTERNAL || name === null) return orig(namePtr, valuePtr);
            if (MASK_PROPS && Object.prototype.hasOwnProperty.call(PROP_MASK, name)) {
                var masked = PROP_MASK[name];
                try {
                    valuePtr.writeUtf8String(masked);
                    valuePtr.add(masked.length).writeU8(0);
                } catch (e) { return orig(namePtr, valuePtr); }
                bump(counters, "prop_masked");
                if ((counters["prop_masked"] || 0) <= CAP) {
                    emit({ type: "prop", name: name, value: masked, masked: true });
                }
                return masked.length;
            }
            var ret = orig(namePtr, valuePtr);
            if (!propSeen[name]) {
                propSeen[name] = true;
                if (PROP_INTEREST_RE.test(name) && Object.keys(propSeen).length <= 200) {
                    var value = null;
                    try { value = valuePtr.readCString(); } catch (e) { }
                    emit({ type: "prop", name: name, value: value, masked: false, ret: ret });
                }
            }
            return ret;
        }, "int", ["pointer", "pointer"]));
        installed.push("__system_property_get");
    } catch (e) { failed.push("__system_property_get: " + e); }
}

// ---------------------------------------------------------------------------------------
// 5) /proc/self/maps scrubbing (OPT-IN, CFG.scrub_maps=true)
//    The most common *native* frida/magisk detection is reading /proc/self/maps and grepping
//    for mapped module names - and our own injection is visible there. When enabled, the
//    original file is read once, the offending lines are dropped, and the result is served
//    from an anonymous memfd. Internal libc calls are flagged IN_INTERNAL so they never
//    re-enter these hooks.
// ---------------------------------------------------------------------------------------
var IN_INTERNAL = false;
var MAPS_RE = /^\/proc\/(self|\d+)\/(maps|task\/\d+\/maps)$/;
var SCRUB_DENY_RE = /(frida|gum-js|gadget|linjector|magisk|riru|zygisk|xposed|substrate|re\.frida|\/data\/local\/tmp)/i;

function installMapsScrub() {
    if (!SCRUB_MAPS) return;
    var addresses = {
        open: libcExport("open"), read: libcExport("read"), write: libcExport("write"),
        lseek: libcExport("lseek"), close: libcExport("close"),
        memfd_create: libcExport("memfd_create"), fdopen: libcExport("fdopen")
    };
    if (!addresses.memfd_create || !addresses.open || !addresses.read ||
        !addresses.write || !addresses.lseek || !addresses.close) {
        failed.push("scrub_maps: memfd_create/open/read/write/lseek/close not all exported");
        return;
    }
    var nOpen = new NativeFunction(addresses.open, "int", ["pointer", "int"]);
    var nRead = new NativeFunction(addresses.read, "long", ["int", "pointer", "size_t"]);
    var nWrite = new NativeFunction(addresses.write, "long", ["int", "pointer", "size_t"]);
    var nLseek = new NativeFunction(addresses.lseek, "long", ["int", "long", "int"]);
    var nClose = new NativeFunction(addresses.close, "int", ["int"]);
    var nMemfd = new NativeFunction(addresses.memfd_create, "int", ["pointer", "uint"]);
    var nFdopen = addresses.fdopen ? new NativeFunction(addresses.fdopen, "pointer", ["int", "pointer"]) : null;

    function scrubToMemfd(path) {
        IN_INTERNAL = true;
        var source = -1, fd = -1;
        try {
            source = nOpen(Memory.allocUtf8String(path), 0 /* O_RDONLY */);
            if (source < 0) return -1;
            var buffer = Memory.alloc(65536);
            var parts = [];
            var total = 0;
            for (var i = 0; i < 4096; i++) {
                var n = nRead(source, buffer, 65536);
                if (n <= 0) break;
                parts.push(buffer.readUtf8String(n));
                total += n;
                if (total > 8 * 1024 * 1024) break;
            }
            nClose(source);
            source = -1;
            var kept = [];
            var lines = parts.join("").split("\n");
            for (var j = 0; j < lines.length; j++) {
                if (!lines[j].length) continue;
                if (SCRUB_DENY_RE.test(lines[j])) continue;
                kept.push(lines[j]);
            }
            var out = kept.join("\n") + "\n";
            fd = nMemfd(Memory.allocUtf8String("m"), 0);
            if (fd < 0) return -1;
            nWrite(fd, Memory.allocUtf8String(out), out.length);
            nLseek(fd, 0, 0 /* SEEK_SET */);
            return fd;
        } finally {
            if (source >= 0) { try { nClose(source); } catch (e) { } }
            IN_INTERNAL = false;
        }
    }

    // fd-returning variants
    [["open", 0], ["open64", 0], ["openat", 1], ["openat64", 1]].forEach(function (spec) {
        var address = libcExport(spec[0]);
        if (!address) return;
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    this.maps = null;
                    try {
                        var path = safeCStr(args[spec[1]]);
                        if (path !== null && MAPS_RE.test(path)) this.maps = path;
                    } catch (e) { }
                },
                onLeave: function (retval) {
                    if (!this.maps || IN_INTERNAL) return;
                    var fd = scrubToMemfd(this.maps);
                    if (fd < 0) return;
                    try {
                        var original = retval.toInt32();
                        if (original >= 0) nClose(original);
                        retval.replace(fd);
                        bump(counters, "maps_scrubbed");
                        if ((counters.maps_scrubbed || 0) <= CAP) {
                            emit({ type: "root_hide_maps", op: spec[0], path: this.maps, fd: fd });
                        }
                    } catch (e) { }
                }
            });
        } catch (e) { failed.push("scrub_maps:" + spec[0] + ": " + e); }
    });

    // FILE*-returning variants
    [["fopen", 0], ["fopen64", 0]].forEach(function (spec) {
        var address = libcExport(spec[0]);
        if (!address || !nFdopen) return;
        var modePtr = Memory.allocUtf8String("r");
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    this.maps = null;
                    try {
                        var path = safeCStr(args[spec[1]]);
                        if (path !== null && MAPS_RE.test(path)) this.maps = path;
                    } catch (e) { }
                },
                onLeave: function (retval) {
                    if (!this.maps || IN_INTERNAL) return;
                    var fd = scrubToMemfd(this.maps);
                    if (fd < 0) return;
                    try {
                        var stream = nFdopen(fd, modePtr);
                        if (stream.isNull()) { nClose(fd); return; }
                        retval.replace(stream);
                        bump(counters, "maps_scrubbed");
                        if ((counters.maps_scrubbed || 0) <= CAP) {
                            emit({ type: "root_hide_maps", op: spec[0], path: this.maps, fd: fd });
                        }
                    } catch (e) { }
                }
            });
        } catch (e) { failed.push("scrub_maps:" + spec[0] + ": " + e); }
    });
    installed.push("scrub_maps");
}

// ---------------------------------------------------------------------------------------
// 6) bootstrap + periodic evidence
// ---------------------------------------------------------------------------------------
function heartbeat() {
    emit({ type: "heartbeat", up_ms: Date.now() - T0, sent: sent, counters: counters });
}

setImmediate(function () {
    var module = libc();
    emit({
        type: "root_bypass_start",
        arch: Process.arch,
        platform: Process.platform,
        pid: Process.id,
        frida: Frida.version,
        libc_base: module ? module.base.toString() : null,
        libc_size: module ? module.size : null,
        errno_symbol: !!libcExport("__errno"),
        config: { verbose: VERBOSE, cap: CAP, mask_props: MASK_PROPS, scrub_maps: SCRUB_MAPS }
    });

    installPathHooks();
    installDirHooks();
    installExecHooks();
    installPropHook();
    installMapsScrub();

    emit({ type: "root_bypass_hooks", installed: installed, missing: missing, failed: failed });

    var heartbeatMs = typeof CFG.heartbeat_ms === "number" ? CFG.heartbeat_ms : 5000;
    setInterval(heartbeat, heartbeatMs);

    var summaryMs = typeof CFG.summary_ms === "number" ? CFG.summary_ms : 30000;
    setTimeout(function () {
        emit({
            type: "root_bypass_summary", up_ms: Date.now() - T0, sent: sent,
            counters: counters, installed: installed, missing: missing, failed: failed
        });
    }, summaryMs);
});
