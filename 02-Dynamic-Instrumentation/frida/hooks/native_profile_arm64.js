/*
 * native_profile_arm64.js - native-layer behavioural profiler for an ARM64 real device.
 *
 * PURPOSE
 * -------
 * Produce the native half of the AI feature vector for D:\base\antifraud.apk (360 jiagu VIP +
 * DTC/dex2c) on a real arm64 device, where the app's own code really is ARM and libc is the
 * app's libc (on the x86_64 LDPlayer instance the app's libraries ran inside the libnb ARM
 * guest space, so x86_64 libc hooks observed nothing - see the session's section 9.3).
 *
 * WHAT IS CAPTURED (time series, module base, arguments)
 * ----------------------------------------------------
 *   profile_start   device/arch/frida/config, libc + linker base, page size
 *   module          every non-system module with name/base/size/path (packer, app .so, odex)
 *   export_index    export inventory of the watched modules (total, JNI_OnLoad addr)
 *   jni_onload      JNI_OnLoad(JavaVM*, void*) entry + return (packer init)
 *   java_entry      hit counters for the watched modules' Java_* exports (DTC surface)
 *   dlopen          every dlopen/android_dlopen_ext result, with late module re-scan
 *   file            open/openat/open64/fopen/access/stat/lstat/readlink + class + ret
 *   prop            __system_property_get, name/value/masked
 *   socket          socket()/socketpair() domain+type, fd tracked for I/O attribution
 *   connect         connect() with decoded sockaddr (AF_INET/AF_INET6/AF_UNIX) + backtrace
 *   net_io          send/recv/sendto/recvfrom/read/write on *tracked socket fds only*
 *   mmap            executable or large mappings (JIT/DTC/loader), with prot/flags
 *   heartbeat       counters every 5 s (survives a hard kill)
 *   summary         final counters + top paths / top peers / timeline
 *
 * DESIGN CONSTRAINTS (learned the hard way in this project)
 * --------------------------------------------------------
 *   * frida-mcp records send() ONLY - console.log is dropped. Everything goes through send().
 *   * read/write are only reported for fds that socket()/socketpair() handed out, otherwise
 *     the log is drowned by the linker's own I/O (and frida's transport writes).
 *   * Every class of file access has its own cap; over-cap hits are counted, not emitted, so
 *     the totals stay meaningful without exploding the JSONL.
 *   * I/O prefix bytes are truncated and escaped, never raw.
 *
 * USAGE
 *   MCP:  frida_run_hook(target="国家反诈中心", hook="native_profile_arm64", seconds=30,
 *                        script_args={"seconds":30,"cap_file":{"app":1500}})
 *   CLI:  D:\frida\.venv\Scripts\python.exe D:\frida\dump_dex.py --attach <pid> \
 *             --js D:\frida\hooks\native_profile_arm64.js --seconds 30
 *
 * Extractor: D:\Palantir_Research\scripts\aggregate_native_profile.py
 */

var CFG = (typeof FRIDA_MCP_ARGS === "object" && FRIDA_MCP_ARGS) || {};
var T0 = Date.now();
var PKG = CFG.pkg || "com.hicorenational.antifraud";

var MAX_RECORDS = typeof CFG.max_records === "number" ? CFG.max_records : 6000;
var SOCKET_PAYLOAD = typeof CFG.socket_payload === "number" ? CFG.socket_payload : 64;
var MMAP_MIN = typeof CFG.mmap_min === "number" ? CFG.mmap_min : 262144;
var WANT_BACKTRACE = CFG.backtrace !== false;
var BT_DEPTH = typeof CFG.bt_depth === "number" ? CFG.bt_depth : 3;
var HOOK_JAVA_EXPORTS = CFG.hook_java_exports !== false;
var MAX_JAVA_EXPORTS = typeof CFG.max_java_exports === "number" ? CFG.max_java_exports : 300;
var SUMMARY_MS = (typeof CFG.seconds === "number" ? CFG.seconds : 30) * 1000;

var CLASS_CAPS = (CFG.cap_file && typeof CFG.cap_file === "object") ? CFG.cap_file : {
    proc: 400, app: 1500, root: 500, frida: 200, so: 400, system: 400, dalvik: 200, other: 400
};
var NET_CAP = typeof CFG.cap_net === "number" ? CFG.cap_net : 800;

var counters = {};
var dropped = {};
var sent = 0;
var topPaths = {};
var topPeers = {};
var netEvents = 0;

function bump(map, key) {
    if (!map[key]) map[key] = 0;
    map[key]++;
    return map[key];
}

function emit(record) {
    if (sent >= MAX_RECORDS) { bump(dropped, "record_cap"); return false; }
    sent++;
    try {
        record.t_ms = Date.now() - T0;
        if (record.tid === undefined) record.tid = Process.getCurrentThreadId();
        send(record);
        return true;
    } catch (e) { return false; }
}

function safeCStr(p) {
    try {
        if (p === null || p.isNull()) return null;
        return p.readCString();
    } catch (e) { return null; }
}

function libc() {
    try { return Process.findModuleByName("libc.so"); } catch (e) { return null; }
}

function libcExport(name) {
    var module = libc();
    if (!module) return null;
    try { return module.getExportByName(name); } catch (e) { return null; }
}

function moduleOf(address) {
    try {
        var module = Process.findModuleByAddress(address);
        if (!module) return "?";
        return module.name + "+0x" + address.sub(module.base).toString(16);
    } catch (e) { return "?"; }
}

function backtraceHere(context) {
    if (!WANT_BACKTRACE) return null;
    var out = [];
    try {
        var frames = Thread.backtrace(context, Backtracer.FUZZY);
        for (var i = 0; i < frames.length && out.length < BT_DEPTH; i++) out.push(moduleOf(frames[i]));
    } catch (e) { }
    return out.length ? out : null;
}

function classify(path) {
    if (!path) return "other";
    if (path.indexOf("/proc/") === 0) return "proc";
    if (path.indexOf(PKG) >= 0) return "app";
    if (/(^|\/)su(\.\w+)?$|magisk|ksud|supersu|superuser|\/data\/adb/i.test(path)) return "root";
    if (/frida|gum-js|linjector/i.test(path)) return "frida";
    if (/\.so$/.test(path)) return "so";
    if (path.indexOf("/system") === 0 || path.indexOf("/apex") === 0 ||
        path.indexOf("/vendor") === 0 || path.indexOf("/odm") === 0) return "system";
    if (path.indexOf("/data/dalvik-cache") === 0 || /\.(odex|vdex|art)$/.test(path)) return "dalvik";
    return "other";
}

function previewBytes(p, length) {
    var n = Math.min(length, SOCKET_PAYLOAD);
    if (n <= 0) return null;
    try {
        var buf = new Uint8Array(p.readByteArray(n));
        var text = "", hex = "";
        for (var i = 0; i < buf.length; i++) {
            var c = buf[i];
            text += (c >= 32 && c < 127) ? String.fromCharCode(c) : ".";
            hex += (c < 16 ? "0" : "") + c.toString(16);
        }
        return { len: length, text: text, hex: hex };
    } catch (e) { return null; }
}

// AF_INET/AF_INET6 port + address and AF_UNIX path, all network byte order.
function readSockaddr(p) {
    try {
        if (p === null || p.isNull()) return null;
        var family = p.readU16();
        if (family === 2) {
            var port = (p.add(2).readU8() << 8) | p.add(3).readU8();
            var b = p.add(4);
            var ip = [b.readU8(), b.add(1).readU8(), b.add(2).readU8(), b.add(3).readU8()].join(".");
            return { af: "AF_INET", ip: ip, port: port };
        }
        if (family === 10) {
            var port6 = (p.add(2).readU8() << 8) | p.add(3).readU8();
            var bytes = new Uint8Array(p.add(8).readByteArray(16));
            var groups = [];
            for (var i = 0; i < 16; i += 2) groups.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
            return { af: "AF_INET6", ip: groups.join(":"), port: port6 };
        }
        if (family === 1) return { af: "AF_UNIX", path: safeCStr(p.add(2)) };
        return { af: "AF_" + family };
    } catch (e) { return { err: String(e) }; }
}

// ---------------------------------------------------------------------------------------
// module inventory / packer surface
// ---------------------------------------------------------------------------------------
var socketFds = {};
var hookedJni = {};
var javaEntryHits = {};
var seenModules = {};

var APP_PATH_RE = /\/data\/(app|data|user|local\/tmp)\//;
var WATCH_RE = /libjiagu|libmd\.so|libcwlive|libtnet|libBugly|libmmkv|libidl_license|libocr-sdk|base\.odex|libnp\.so|libns\.so/i;

function abiOf(path) {
    // On-device native library dirs are /data/app/<pkg>/lib/arm64 (NOT arm64-v8a), while APK
    // contents use lib/arm64-v8a - match both, longest alternative first.
    var match = /\/(arm64-v8a|armeabi-v7a|armeabi|x86_64|arm64|armeabi|x86|arm)\//.exec(path || "");
    return match ? match[1] : "?";
}

function isAppModule(module) {
    var path = module.path || "";
    return APP_PATH_RE.test(path) || /libjiagu/i.test(path) || module.name === "base.odex" ||
        WATCH_RE.test(module.name);
}

function indexModule(module) {
    if (seenModules[module.name + "@" + module.base]) return;
    seenModules[module.name + "@" + module.base] = module;
    if (!isAppModule(module)) return;
    emit({
        type: "module", name: module.name, base: module.base.toString(), size: module.size,
        path: module.path, abi: abiOf(module.path)
    });
    indexExports(module);
    hookJniOnLoad(module);
}

function indexExports(module) {
    var exports = [];
    try { exports = module.enumerateExports(); } catch (e) { exports = []; }
    var javaNames = [];
    var jniNames = [];
    var onLoad = null;
    for (var i = 0; i < exports.length; i++) {
        var entry = exports[i];
        if (entry.type !== "function") continue;
        if (entry.name === "JNI_OnLoad") onLoad = entry.address;
        if (/^Java_/.test(entry.name) && javaNames.length < 200) javaNames.push(entry.name);
        else if (/^JNI_/.test(entry.name) && jniNames.length < 50) jniNames.push(entry.name);
    }
    emit({
        type: "export_index", module: module.name, base: module.base.toString(), size: module.size,
        total_exports: exports.length, jni_onload: onLoad ? onLoad.toString() : null,
        java_entry_count: javaNames.length, java_entries: javaNames, jni_entries: jniNames
    });
    if (HOOK_JAVA_EXPORTS) {
        var limited = exports.filter(function (e) { return e.type === "function" && /^Java_/.test(e.name); })
            .slice(0, MAX_JAVA_EXPORTS);
        limited.forEach(function (entry) {
            var key = module.name + "!" + entry.name;
            if (hookedJni[key]) return;
            hookedJni[key] = true;
            try {
                Interceptor.attach(entry.address, { onEnter: function () { bump(javaEntryHits, key); } });
            } catch (e) { }
        });
    }
}

function hookJniOnLoad(module) {
    var address = null;
    try { address = module.getExportByName("JNI_OnLoad"); } catch (e) { }
    if (!address) return;
    var key = module.name + "!JNI_OnLoad";
    if (hookedJni[key]) return;
    hookedJni[key] = true;
    try {
        Interceptor.attach(address, {
            onEnter: function (args) { this.vm = args[0]; this.reserved = args[1]; },
            onLeave: function (retval) {
                var ret = null;
                try { ret = retval.toInt32(); } catch (e) { }
                emit({
                    type: "jni_onload", module: module.name, base: module.base.toString(),
                    addr: address.toString(), size: module.size,
                    vm: this.vm ? this.vm.toString() : null,
                    reserved: this.reserved ? this.reserved.toString() : null,
                    ret: ret, bt: backtraceHere(this.context)
                });
            }
        });
    } catch (e) {
        emit({ type: "hook_fail", what: key, err: String(e) });
    }
}

function scanModules() {
    var all = [];
    try { all = Process.enumerateModules(); } catch (e) { }
    all.forEach(indexModule);
    return all.length;
}

// ---------------------------------------------------------------------------------------
// file access: every path-based check the app/packer makes, classified and capped
// ---------------------------------------------------------------------------------------
var FILE_SPECS = {
    open: { args: ["pointer", "int"], path: 0, ret: "int" },
    open64: { args: ["pointer", "int"], path: 0, ret: "int" },
    openat: { args: ["int", "pointer", "int"], path: 1, ret: "int" },
    openat64: { args: ["int", "pointer", "int"], path: 1, ret: "int" },
    fopen: { args: ["pointer", "pointer"], path: 0, ret: "ptr" },
    fopen64: { args: ["pointer", "pointer"], path: 0, ret: "ptr" },
    access: { args: ["pointer", "int"], path: 0, ret: "int" },
    faccessat: { args: ["int", "pointer", "int", "int"], path: 1, ret: "int" },
    stat: { args: ["pointer", "pointer"], path: 0, ret: "int" },
    stat64: { args: ["pointer", "pointer"], path: 0, ret: "int" },
    lstat: { args: ["pointer", "pointer"], path: 0, ret: "int" },
    lstat64: { args: ["pointer", "pointer"], path: 0, ret: "int" },
    fstatat: { args: ["int", "pointer", "pointer", "int"], path: 1, ret: "int" },
    readlink: { args: ["pointer", "pointer", "size_t"], path: 0, ret: "int" },
    readlinkat: { args: ["int", "pointer", "pointer", "size_t"], path: 1, ret: "int" }
};

function installFileHooks() {
    var installed = [];
    Object.keys(FILE_SPECS).forEach(function (symbol) {
        var spec = FILE_SPECS[symbol];
        var address = libcExport(symbol);
        if (!address) return;
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    this.rec = false;
                    this.cls = null;
                    this.path = null;
                    try {
                        var path = safeCStr(args[spec.path]);
                        if (path === null) return;
                        this.path = path;
                        this.cls = classify(path);
                        bump(counters, "file:" + this.cls);
                        bump(topPaths, this.cls + "|" + path);
                        var cap = CLASS_CAPS[this.cls] === undefined ? 400 : CLASS_CAPS[this.cls];
                        var hits = counters["file:" + this.cls] || 0;
                        if (hits <= cap) this.rec = true;
                        else bump(dropped, "file:" + this.cls);
                    } catch (e) { }
                },
                onLeave: function (retval) {
                    if (!this.rec) return;
                    var ret = null;
                    try { ret = spec.ret === "int" ? retval.toInt32() : retval.toString(); } catch (e) { }
                    var record = {
                        type: "file", op: symbol, path: this.path, cls: this.cls, ret: ret
                    };
                    if (this.cls === "root" || this.cls === "proc" || this.cls === "frida") {
                        record.bt = backtraceHere(this.context);
                    }
                    emit(record);
                }
            });
            installed.push(symbol);
        } catch (e) {
            emit({ type: "hook_fail", what: "file:" + symbol, err: String(e) });
        }
    });
    return installed;
}

// ---------------------------------------------------------------------------------------
// system properties (emulator/root/debuggable probes live here)
// ---------------------------------------------------------------------------------------
var propSeen = {};

function installPropHook() {
    var address = libcExport("__system_property_get");
    if (!address) return null;
    try {
        Interceptor.attach(address, {
            onEnter: function (args) {
                this.name = safeCStr(args[0]);
                this.valuePtr = args[1];
            },
            onLeave: function (retval) {
                var ret = null;
                try { ret = retval.toInt32(); } catch (e) { }
                if (!this.name) return;
                bump(counters, "prop");
                if (propSeen[this.name]) return;
                if (Object.keys(propSeen).length > 250) return;
                propSeen[this.name] = true;
                var value = null;
                try { value = (this.valuePtr && ret > 0) ? this.valuePtr.readCString() : null; } catch (e) { }
                emit({ type: "prop", name: this.name, value: value, ret: ret });
            }
        });
        return "__system_property_get";
    } catch (e) {
        emit({ type: "hook_fail", what: "prop", err: String(e) });
        return null;
    }
}

// ---------------------------------------------------------------------------------------
// network: socket/connect/send/recv (+ sendto/recvfrom) and I/O on tracked socket fds
// ---------------------------------------------------------------------------------------
var AF_NAMES = { 0: "AF_UNSPEC", 1: "AF_UNIX", 2: "AF_INET", 3: "AF_AX25", 4: "AF_IPX", 10: "AF_INET6", 16: "AF_NETLINK", 17: "AF_PACKET" };
var SOCK_NAMES = { 1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW", 5: "SOCK_SEQPACKET" };

var readErrno = (function () {
    var addr = libcExport("__errno") || libcExport("__errno_location");
    if (!addr) return function () { return null; };
    var fn;
    try { fn = new NativeFunction(addr, "pointer", []); } catch (e) { return function () { return null; }; }
    return function () {
        try { return fn().readInt(); } catch (e) { return null; }
    };
})();

function afName(v) { return AF_NAMES[v] || ("AF_" + v); }
function sockName(v) { return SOCK_NAMES[v & 0xf] || ("SOCK_" + v); }

function trackFd(fd, info) {
    if (!socketFds[fd]) {
        socketFds[fd] = info;
        bump(counters, "socket_tracked");
    }
}

function installNetworkHooks() {
    var installed = [];

    function attach(symbol, handlers) {
        var address = libcExport(symbol);
        if (!address) return;
        try {
            Interceptor.attach(address, handlers);
            installed.push(symbol);
        } catch (e) {
            emit({ type: "hook_fail", what: "net:" + symbol, err: String(e) });
        }
    }

    attach("socket", {
        onEnter: function (args) {
            this.domain = args[0].toInt32();
            this.type = args[1].toInt32();
            this.protocol = args[2].toInt32();
        },
        onLeave: function (retval) {
            var fd = null;
            try { fd = retval.toInt32(); } catch (e) { }
            bump(counters, "socket");
            if (fd !== null && fd >= 0) {
                trackFd(fd, { domain: this.domain, type: this.type, protocol: this.protocol });
            }
            emit({
                type: "socket", domain: afName(this.domain), sock_type: sockName(this.type),
                protocol: this.protocol, fd: fd, ok: (fd !== null && fd >= 0)
            });
        }
    });

    attach("socketpair", {
        onEnter: function (args) {
            this.domain = args[0].toInt32();
            this.type = args[1].toInt32();
            this.protocol = args[2].toInt32();
            this.sv = args[3];
        },
        onLeave: function (retval) {
            var ret = null, fds = null;
            try { ret = retval.toInt32(); } catch (e) { }
            if (ret === 0 && this.sv) {
                try {
                    fds = [this.sv.readInt(), this.sv.add(4).readInt()];
                    trackFd(fds[0], { domain: this.domain, type: this.type, protocol: this.protocol, pair: true });
                    trackFd(fds[1], { domain: this.domain, type: this.type, protocol: this.protocol, pair: true });
                } catch (e) { }
            }
            emit({
                type: "socketpair", domain: afName(this.domain), sock_type: sockName(this.type),
                protocol: this.protocol, ret: ret, fds: fds
            });
        }
    });

    attach("connect", {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.sock = socketFds[this.fd] || { domain: -1 };
            this.peer = readSockaddr(args[1]);
            this.socklen = args[2].toInt32();
        },
        onLeave: function (retval) {
            var ret = null;
            try { ret = retval.toInt32(); } catch (e) { }
            var peer = this.peer || {};
            var key = peer.ip ? (peer.ip + ":" + peer.port) : (peer.path || peer.af || "?");
            bump(topPeers, key);
            bump(counters, ret === 0 ? "connect_ok" : "connect_fail");
            emit({
                type: "connect", fd: this.fd, domain: afName(this.sock.domain),
                peer: peer, socklen: this.socklen, ret: ret,
                errno: ret === 0 ? null : readErrno(), bt: backtraceHere(this.context)
            });
        }
    });

    // outbound payload: the buffer already holds it at entry
    attach("send", ioHandler("send", 2, "in"));
    attach("sendto", ioHandler("sendto", 2, "in"));
    attach("write", ioHandler("write", 2, "in"));
    // inbound payload: the length is only known once the call returned
    attach("recv", ioHandler("recv", 2, "out"));
    attach("recvfrom", ioHandler("recvfrom", 2, "out"));
    attach("read", ioHandler("read", 2, "out"));

    attach("close", {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.was = !!socketFds[this.fd];
        },
        onLeave: function () {
            if (!this.was) return;
            delete socketFds[this.fd];
            emit({ type: "socket_close", fd: this.fd });
        }
    });

    return installed;
}

// direction "in"  -> buffer holds the payload at entry (send/write)
// direction "out" -> buffer holds the payload only after the call returned (recv/read)
function ioHandler(op, lenIndex, direction) {
    return {
        onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.len = args[lenIndex].toInt32();
            this.sock = socketFds[this.fd] || null;
            this.preview = null;
            var hits = bump(counters, "io:" + op);
            this.rec = !!this.sock && hits <= NET_CAP;
            if (this.sock && !this.rec) bump(dropped, "io:" + op);
            if (this.rec && direction === "in") this.preview = previewBytes(this.buf, this.len);
        },
        onLeave: function (retval) {
            if (!this.rec) return;
            var ret = null;
            try { ret = retval.toInt32(); } catch (e) { }
            if (direction === "out" && ret !== null && ret > 0) {
                this.preview = previewBytes(this.buf, ret);
            }
            bump(counters, "net_io_total");
            netEvents++;
            emit({
                type: "net_io", op: op, fd: this.fd, want: this.len, ret: ret,
                domain: afName(this.sock.domain), kind: sockName(this.sock.type || 0),
                preview: this.preview
            });
        }
    };
}

// ---------------------------------------------------------------------------------------
// memory: executable or large mappings + mprotect that turns a page executable
// (this is how the packer releases decrypted code; DTC/Dex2C lands here too)
// ---------------------------------------------------------------------------------------
var PROT_NAMES = { 1: "r", 2: "w", 4: "x" };

function protString(prot) {
    // read/write/exec order, so the profile reads "rwx" not "xwr"
    var out = "";
    [1, 2, 4].forEach(function (bit) { if (prot & bit) out += PROT_NAMES[bit]; });
    return out.length ? out : "-";
}

function installMemoryHooks() {
    var installed = [];

    var mmapAddr = libcExport("mmap");
    if (mmapAddr) {
        try {
            Interceptor.attach(mmapAddr, {
                onEnter: function (args) {
                    this.addr = args[0];
                    this.len = args[1].toInt32();
                    this.prot = args[2].toInt32();
                    this.flags = args[3].toInt32();
                    this.fd = args[4].toInt32();
                    this.off = args[5].toString();
                    var exec = (this.prot & 4) !== 0;
                    this.rec = exec || this.len >= MMAP_MIN;
                    bump(counters, exec ? "mmap_exec" : "mmap");
                    if (!this.rec) return;
                },
                onLeave: function (retval) {
                    if (!this.rec) return;
                    emit({
                        type: "mmap", addr: this.addr ? this.addr.toString() : null, len: this.len,
                        prot: protString(this.prot), flags: this.flags, fd: this.fd, off: this.off,
                        ret: retval.toString(), bt: backtraceHere(this.context)
                    });
                }
            });
            installed.push("mmap");
        } catch (e) { emit({ type: "hook_fail", what: "memory:mmap", err: String(e) }); }
    }

    var mprotectAddr = libcExport("mprotect");
    if (mprotectAddr) {
        try {
            Interceptor.attach(mprotectAddr, {
                onEnter: function (args) {
                    this.addr = args[0];
                    this.len = args[1].toInt32();
                    this.prot = args[2].toInt32();
                    this.rec = (this.prot & 4) !== 0;
                    bump(counters, this.rec ? "mprotect_x" : "mprotect");
                },
                onLeave: function (retval) {
                    if (!this.rec) return;
                    var ret = null;
                    try { ret = retval.toInt32(); } catch (e) { }
                    emit({
                        type: "mprotect", addr: this.addr.toString(), len: this.len,
                        prot: protString(this.prot), ret: ret, bt: backtraceHere(this.context)
                    });
                }
            });
            installed.push("mprotect");
        } catch (e) { emit({ type: "hook_fail", what: "memory:mprotect", err: String(e) }); }
    }

    return installed;
}

// ---------------------------------------------------------------------------------------
// dlopen watcher: the packer and the app load their libraries lazily
// ---------------------------------------------------------------------------------------
function installDlopenWatcher() {
    var installed = [];
    var rescanScheduled = false;

    function scheduleRescan() {
        if (rescanScheduled) return;
        rescanScheduled = true;
        setTimeout(function () {
            rescanScheduled = false;
            scanModules();
        }, 250);
    }

    [["android_dlopen_ext", 0], ["dlopen", 0]].forEach(function (spec) {
        var address = libcExport(spec[0]);
        if (!address) return;
        try {
            Interceptor.attach(address, {
                onEnter: function (args) { this.path = safeCStr(args[spec[1]]); },
                onLeave: function (retval) {
                    var ret = retval.toString();
                    var key = (this.path || "<null>") + " -> " + ret;
                    bump(counters, "dlopen");
                    if (!seenDlopen[key]) {
                        seenDlopen[key] = true;
                        emit({ type: "dlopen", fn: spec[0], path: this.path, ret: ret });
                    }
                    scheduleRescan();
                }
            });
            installed.push(spec[0]);
        } catch (e) { emit({ type: "hook_fail", what: "dlopen:" + spec[0], err: String(e) }); }
    });

    // catch libraries that were already loaded before the hooks went in
    [1000, 3000, 8000, 15000].forEach(function (delay) { setTimeout(scanModules, delay); });
    return installed;
}

var seenDlopen = {};

function topN(map, n) {
    var entries = [];
    for (var key in map) {
        if (Object.prototype.hasOwnProperty.call(map, key)) entries.push([key, map[key]]);
    }
    entries.sort(function (a, b) { return b[1] - a[1]; });
    return entries.slice(0, n).map(function (e) { return { key: e[0], count: e[1] }; });
}

function appModuleList() {
    var out = [];
    try {
        Process.enumerateModules().forEach(function (module) {
            if (isAppModule(module)) out.push(module.name + "@" + module.base);
        });
    } catch (e) { }
    return out;
}

function snapshot() {
    return {
        counts: counters,
        dropped: dropped,
        records: sent,
        tracked_socket_fds: Object.keys(socketFds).length,
        java_entry_hits: javaEntryHits,
        top_paths: topN(topPaths, 40),
        top_peers: topN(topPeers, 20),
        modules: appModuleList()
    };
}

// ---------------------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------------------
setImmediate(function () {
    emit({
        type: "profile_start", arch: Process.arch, platform: Process.platform, pid: Process.id,
        frida: Frida.version, pkg: PKG, pointer_size: Process.pointerSize,
        page_size: Process.pageSize, libc_base: libc() ? libc().base.toString() : null,
        config: {
            max_records: MAX_RECORDS, socket_payload: SOCKET_PAYLOAD, mmap_min: MMAP_MIN,
            backtrace: WANT_BACKTRACE, net_cap: NET_CAP, summary_ms: SUMMARY_MS,
            file_caps: CLASS_CAPS
        }
    });

    var scanned = scanModules();
    var fileHooks = installFileHooks();
    var propHook = installPropHook();
    var netHooks = installNetworkHooks();
    var memoryHooks = installMemoryHooks();
    var dlopenHooks = installDlopenWatcher();

    emit({
        type: "hooks_ready", modules_scanned: scanned,
        file: fileHooks, prop: propHook, net: netHooks, memory: memoryHooks, dlopen: dlopenHooks,
        jni_hooks: Object.keys(hookedJni).length,
        note: "read/write are reported only for fds handed out by socket()/socketpair()"
    });

    setInterval(function () {
        emit({
            type: "heartbeat", up_ms: Date.now() - T0, counters: counters,
            dropped: dropped, records: sent
        });
    }, typeof CFG.heartbeat_ms === "number" ? CFG.heartbeat_ms : 5000);

    setTimeout(function () {
        scanModules();
        emit({ type: "summary", up_ms: Date.now() - T0, data: snapshot() });
    }, SUMMARY_MS);
});
