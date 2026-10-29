/*
 * sg_class_filter.js -- recon + optional filter for the six Cyrillic-named
 * classes under com.alibaba.wireless.security.securitybody.open
 *
 * WHY
 *   The obfuscator put a Cyrillic letter (U+0430..U+0434) into six class names
 *   in the SecurityGuard "open" package. They read like Latin at a glance but
 *   can never collide with a real ASCII class, so they hide reflective /
 *   dynamic entry points. Confirmed descriptors and raw MUTF-8 tails:
 *
 *     Lcom/alibaba/wireless/security/securitybody/open/MalDetect$<U+0430>;  ... 24 d0 b0
 *     Lcom/alibaba/wireless/security/securitybody/open/<U+0430>;            ... 2f d0 b0
 *     Lcom/alibaba/wireless/security/securitybody/open/<U+0431>;            ... 2f d0 b1
 *     Lcom/alibaba/wireless/security/securitybody/open/<U+0432>;            ... 2f d0 b2
 *     Lcom/alibaba/wireless/security/securitybody/open/<U+0433>;            ... 2f d0 b3
 *     Lcom/alibaba/wireless/security/securitybody/open/<U+0434>;            ... 2f d0 b4
 *
 *   This script never embeds those letters as literals. They are rebuilt from
 *   code points, so the file stays pure ASCII (0x00..0x7e) and survives any
 *   editor or console that would re-encode it (the host console is GBK, which
 *   is exactly what garbles U+0430 into 0x90AA). All output is additionally
 *   escaped as \uXXXX so log lines stay readable in that console.
 *
 * WHAT IT DOES
 *   1. Enumerates loaded classes, keeps names inside the "open" package whose
 *      simple name carries a non-ASCII code point (the VM is the source of
 *      truth for the bytes, not this file).
 *   2. Hooks every declared method plus every constructor of each match and
 *      reports enter / leave / throw through send(). The frida-mcp sink only
 *      records send() payloads -- console.log is dropped, so send() is the
 *      only channel used here.
 *   3. Watches ClassLoader.loadClass / Class.forName so a match that is
 *      resolved later (reflection, lazy init) is hooked the moment it loads.
 *   4. Rescans on a timer and emits one coverage summary naming exactly which
 *      of the six expected classes were actually seen.
 *   5. "device spoof" (CONF.spoof, on by default) repairs the *inputs* a risk
 *      model reads instead of fighting the page it produces: root/magisk/frida
 *      artefacts, emulator Build fields and properties, telephony ids.  Its two
 *      later sections go deeper, because a Java-only disguise turns out to be
 *      worse than none once the engine is native:
 *        "deep disguise"  android_id, Build.getSerial, SIM, sensor identity/rate,
 *                         battery, network MAC, cpu count, memory sizes
 *        "native layer"   the libc answers a .so actually uses -- /proc/self/maps
 *                         and .../task/<tid>/comm content, __system_property_get,
 *                         dl_iterate_phdr
 *   6. "forced-login bypass" refuses navigation to a login page at
 *      Activity.startActivity*()/Instrumentation, before the Activity exists.
 *   7. "auth diagnostic" (CONF.diag) records both sides of a login wall -- the
 *      client's own isLogin() answers, and mtop's ret codes plus whether the
 *      outgoing request even carried a Cookie -- then prints one verdict.  The
 *      point is that "client-gated" vs "server-denied" becomes a measurement
 *      instead of a guess; it is read-only unless CONF.diag.forceLogin is on.
 *
 * LOADERS (why plain Java.use is not enough here)
 *   Measured on Taobao 10.68.0 / Android 9 x86_64: every one of these classes
 *   throws ClassNotFoundException from Java.use() -- including the pure-ASCII
 *   MalDetect -- because they are defined by a *child* loader of the app
 *   loader, and a parent never resolves its child's classes. Java.choose()
 *   cannot help either; it sweeps zero ClassLoader instances on this ART.
 *   Loaders are therefore enumerated through Java.enumerateClassLoaders()
 *   (art::ClassLinker::VisitClassLoaders), one Java.ClassFactory is kept per
 *   loader, and each class is resolved through whichever loader owns it. The
 *   loader that worked is recorded per class and reported by `coverage`.
 *
 * FILTER MODE
 *   CONF.filter = false -> observe only, behaviour is untouched (default).
 *   CONF.filter = true  -> any method whose name is listed in CONF.stub is
 *                          neutralised: the original is skipped and a
 *                          type-appropriate default is returned. CONF.stub is
 *                          empty by default, so even with filter = true this
 *                          changes nothing until you name a method.
 *   Constructors ($init) are never stubbed -- replacing a constructor's
 *   return value is meaningless.
 *
 * BUILD (Frida 17 bundles no Java bridge -- see the note below)
 *   D:\frida\buildtools\compile\build.cmd D:\frida\hooks\sg_class_filter.js ^
 *       D:\frida\agent\sg_class_filter.compiled.js
 *
 * USAGE
 *   frida_run_script target=<package or pid> ^
 *                    source_path=D:\frida\agent\sg_class_filter.compiled.js seconds=45
 *
 *   seconds must outlast the largest CONF.rescanAtMs offset (30 s by default),
 *   or the final coverage summary -- the line that answers "did we see all
 *   six?" -- is never reached.
 *
 *   Read the JSONL evidence, then set CONF.stub / CONF.filter and rebuild.
 */

/* ------------------------------------------------------------------ *
 * Frida 17: the Java bridge is no longer part of the agent runtime
 * ------------------------------------------------------------------ *
 * Frida 16 shipped frida-java-bridge inside GumJS; Frida 17 (this host runs
 * 17.18.0) does not, so in a RAW script `Java` is undefined and the first
 * Java.* call dies with "ReferenceError: 'Java' is not defined" -- which is
 * exactly what loading this file raw produced.
 *
 * The import below is what pulls the bridge in, and it only resolves under
 * frida-compile. Hence two artifacts:
 *
 *     hooks/sg_class_filter.js           <- this file, the compile input
 *     agent/sg_class_filter.compiled.js  <- what frida_run_script loads
 *
 * Loading this file raw now fails at parse time (SyntaxError on `import`);
 * that is expected and is the reminder to run build.cmd first.
 */
import Java from 'frida-java-bridge';

var CONF = {
    // Dot form, as returned by Java.enumerateLoadedClassesSync().
    pkgDot: "com.alibaba.wireless.security.securitybody.open.",

    // The six expected simple names, built from code points so this source
    // file stays ASCII. 0x430..0x434 == U+0430..U+0434.
    expected: [
        String.fromCharCode(0x430),                    // U+0430
        String.fromCharCode(0x431),                    // U+0431
        String.fromCharCode(0x432),                    // U+0432
        String.fromCharCode(0x433),                    // U+0433
        String.fromCharCode(0x434),                    // U+0434
        "MalDetect$" + String.fromCharCode(0x430)      // MalDetect$ + U+0430
    ],

    filter: false,          // false = pure observation
    stub: [],               // method names to neutralise when filter === true
    watchLoads: true,       // hook ClassLoader.loadClass / Class.forName
    rescanAtMs: [2000, 5000, 10000, 20000, 30000],
    maxStringLen: 160,      // clip logged strings
    maxBytes: 48,           // clip logged byte[] as hex

    // ---- forced-login bypass (section: "forced-login bypass") --------------
    // Independent of filter/stub: this blocks *navigation to a login page*,
    // it never neutralises a SecurityGuard method.
    bypass: {
        enabled: true,
        // Strong signal: matched anywhere in the target class name.
        words: ["login", "signin", "sign_in", "sign-in", "logon", "passport",
                "oauth", "authorize", "regist"],
        // Weak signal: the cold-start route legitimately passes through one of
        // these, so they are only blocked after softWindowMs.
        softWords: ["welcome", "splash", "guide", "onboard"],
        softWindowMs: 8000,
        allow: [],                  // class-name substrings that are never blocked
        hookInstrumentation: true,  // backstop for router-driven starts
        fakeCancel: true,           // synthesise onActivityResult(RESULT_CANCELED)
        maxCancelClasses: 8
    },

    // ---- auth diagnostic (section: "auth diagnostic", task 1) --------------
    // Read-only by default: this reports *why* a login wall appeared.  It never
    // changes a login decision, so a diagnostic run cannot alter what it
    // measures.  The long comment sits at the section itself.
    diag: {
        enabled: true,

        // Only these namespaces are inventoried.  Scanning every loaded class
        // for /login/ would hit unrelated names (WebView's LoginHandler,
        // okhttp auth, ...) and bury the interesting ones.
        pkgRe: /^(com\.taobao|com\.alibaba|com\.ali\.user|mtopsdk|anet\.channel)\./,
        // ...and inside them, only names that carry one of these words.
        classRe: /(login|logon|signin|sign_in|account|userinfo|session|passport|autologin|aliuser|cookie|token|utdid)/i,

        // Method names whose *return value is* the login state.  They are
        // matched by name AND by signature (boolean / String, no arguments),
        // so an unrelated void isLogin(int) overload can never be hooked.
        boolMethods: ["isLogin", "isLogined", "isLoggedIn", "isLoginValid",
                      "isSessionValid", "isSidValid", "checkLogin",
                      "isUserLogin", "isLogining", "isAutoLogin", "hasLogin"],
        stringMethods: ["getUserId", "getNick", "getSid", "getSessionId",
                        "getSessionID", "getAutoLoginToken", "getCookie",
                        "getUtdid", "getLoginToken", "getNickName", "getAccount"],

        // mtop accessors that carry the server's verdict.  Only the two entry
        // points every consumer calls are hooked; the other fields are *read
        // from inside* them (see hookAuthMtop) because a hooked getter that is
        // called from a hook re-enters itself.
        mtopEntry: ["getRetCode", "isApiSuccess"],

        // Dialog classes worth naming.  The forced-login bypass intercepts
        // Activity starts only, so a dialog-style login sheet is invisible to
        // it -- seeing one here is the answer to "why did the bypass miss it?".
        dialogRe: /(login|account|passport|aliuser|risk|verify|captcha)/i,

        // Bounds.  A cold start loads ~20k classes; these keep the scan and the
        // log proportional to what a human can read afterwards.
        maxClasses: 80,
        maxHooks: 220,
        maxEvents: 400,
        stackSamples: 3,        // first N state calls get a Java caller stack
        earlyVerdictMs: 20000,  // a shorter run (--seconds 30) still gets one
        verdictAtMs: 40000,     // the one to read when the window is long enough

        // Task 3 "plan B", OFF on purpose.  Forcing isLogin() to true proves
        // which side of the gate you were on, and nothing more: no Cookie is
        // created, so every signed call is still rejected by the server while
        // the client now believes a lie.  Kept as a measurable probe.
        forceLogin: false,
        loginFlag: true
    },

    // ---- device spoof (section: "device spoof") ----------------------------
    // Independent of everything above.  Repairs the *inputs* the risk model
    // reads (root artefacts, emulator build, telephony ids, frida leftovers)
    // instead of fighting the page it produces.
    //
    // Every hook calls the original unless it explicitly overrides, and no hook
    // changes a return *type*, so a wrong guess cannot make the app fail a cast.
    spoof: {
        enabled: true,

        // 1. root / magisk / superuser artefacts -> "does not exist"
        hideRoot: true,
        // Paths are matched case-insensitively.  The plain "su" segment is
        // handled separately (see isRootPath): a substring test would hide
        // /system/usr, which the app really does stat during startup.
        rootWords: ["magisk", "supersu", "superuser", "daemonsu", "kingroot",
                    "ksud", "busybox", "xposed", "substrate", "frida", "gadget",
                    "linjector", "rootcloak", "re.frida"],

        // 2. system properties that betray a debuggable / emulated build
        props: true,
        propMap: {
            "ro.debuggable": "0",
            "ro.secure": "1",
            "ro.build.type": "user",
            "ro.build.tags": "release-keys",
            "ro.boot.verifiedbootstate": "green",
            "ro.boot.flash.locked": "1",
            "service.adb.root": "0",
            "ro.kernel.qemu": "0"
        },

        // 3. Build.* rewritten to a real API-28 handset.  The guest is Android 9
        //    (sdk 28), so claiming a Pixel 5 on Android 12 would be internally
        //    inconsistent -- version fields are deliberately left alone and only
        //    the identity of the device is replaced.  ABIs / SUPPORTED_ABIS are
        //    NOT touched: they are read by the package manager's native-library
        //    loader, and a wrong answer there breaks the app instead of hiding it.
        build: true,
        buildFields: {
            FINGERPRINT: "Xiaomi/cepheus/cepheus:9/PKQ1.190110.001/9.8.1:user/release-keys",
            MODEL: "MI 9",
            MANUFACTURER: "Xiaomi",
            BRAND: "Xiaomi",
            DEVICE: "cepheus",
            PRODUCT: "cepheus",
            BOARD: "cepheus",
            HARDWARE: "qcom",
            DISPLAY: "PKQ1.190110.001",
            ID: "PKQ1.190110.001",
            TAGS: "release-keys",
            TYPE: "user",
            HOST: "c3-miui-ota-bd013.bj",
            USER: "builder",
            BOOTLOADER: "unknown",
            SERIAL: "9c1f2d3a"
        },

        // 4. telephony identifiers.  Both are Luhn-valid, and getDeviceId /
        //    getImei return the SAME value on purpose: a model that cross-checks
        //    the two must not see a disagreement.
        telephony: true,
        imei: "356938035643809",
        meid: "A1000012345678",

        // 5. light anti-frida: drop instrumentation names from directory
        //    listings.  Only names are filtered -- /proc/self/maps CONTENT is
        //    read through native code that a Java hook cannot reach, so that
        //    vector is explicitly out of scope here (see the section comment).
        hideFrida: true,
        fridaNames: ["frida", "gum-js", "gumjs", "gadget", "linjector",
                     "re.frida", "gmain", "gdbus"],

        // 6. WebView URL block (task 3).  OFF by default, and measured
        //    unnecessary on this guest: the QR page is native
        //    (aliuser_* resource-ids), not H5.  Enable it only after checking
        //    that the page in front of you really is a WebView.
        webviewBlock: {
            enabled: false,
            words: ["login", "qrcode", "verify", "riskcheck", "secverify"]
        },

        // ---- deep disguise (section: "deep disguise", task 4) -----------------
        // Every value below is chosen to AGREE with buildFields above.  A
        // disguise that contradicts itself (MI 9 next to 0011ff13) is a stronger
        // emulator signal than no disguise at all, so these are not free
        // variables: serial == buildFields.SERIAL, and the fingerprint string is
        // repeated in the native prop map for the same reason.
        deep: {
            enabled: true,

            // --- 4.1 identity -------------------------------------------------
            // 16 hex chars.  The example in the task list (a1b2c3d4e5f6g7h8) is
            // NOT hex -- g/h are not digits -- so a parser reading android_id as
            // a 64-bit id would reject it.  This one parses.
            androidId: "a1b2c3d4e5f60718",
            // A Mi 9 reports one serial on every surface: Build.SERIAL,
            // Build.getSerial(), ro.serialno, ro.boot.serialno.  "RF8N1234567"
            // is a Samsung-style value and would contradict the Xiaomi
            // fingerprint, so the handset's own short hex serial is used.
            serial: "9c1f2d3a",
            iccId: "8986001234567890120",     // 20 digits, Luhn-valid, CMCC
            imsi: "460001234567890",          // MCC 460 / MNC 00
            simOperator: "46000",
            simOperatorName: "CMCC",
            countryIso: "cn",
            // An ICCID next to SIM_STATE_ABSENT is a contradiction, so the
            // matching state comes with it (5 == READY).
            simState: 5,
            phoneType: 1,                     // PHONE_TYPE_GSM

            // --- 4.2 sensors ---------------------------------------------------
            // Nothing has to be invented on this guest: it reports 8 hardware
            // sensors (measured).  What gives it away is their identity -- every
            // one is capped at 5 Hz and every vendor string is an emulator stub.
            // Adding a missing sensor is impossible (Sensor has no public
            // constructor), so the repair is per-sensor identity + rate.
            sensorMinDelay: 5000,             // 200 Hz
            sensorMinDelayFloor: 200000,      // "5 Hz or slower" == emulator cap
            sensorTypes: {
                1: { name: "LSM6DSO Accelerometer", vendor: "STMicroelectronics",
                     version: 1, maxRange: 78.4532, resolution: 0.002392, power: 0.16 },
                2: { name: "AK09918 Magnetometer", vendor: "AKM",
                     version: 1, maxRange: 4912.0, resolution: 0.15, power: 0.28 },
                4: { name: "LSM6DSO Gyroscope", vendor: "STMicroelectronics",
                     version: 1, maxRange: 34.906586, resolution: 0.001065, power: 0.17 },
                5: { name: "TMD3702 Light sensor", vendor: "AMS",
                     version: 2, maxRange: 8192.0, resolution: 1.0, power: 0.1 },
                8: { name: "TMD3702 Proximity sensor", vendor: "AMS",
                     version: 2, maxRange: 10.0, resolution: 1.0, power: 0.1 }
            },

            // --- 4.3 power / network -------------------------------------------
            // Measured on this guest: AC and USB powered, level 100, status 2.
            // "charging at 100%" is the contradiction; a phone on a desk is
            // discharging at 87.
            batteryExtras: {
                level: 87, scale: 100, status: 3, health: 2, present: 1,
                plugged: 0, voltage: 4012, temperature: 302
            },
            batteryProps: { 1: 2740000, 2: -320000, 3: -305000, 4: 87, 5: 10800000 },
            batteryLongProps: { 1: 2740000000, 2: -320000, 3: -305000 },
            // What Android 9 already reports to apps; set explicitly so an
            // emulator that leaks the hardware MAC cannot leak it here.
            wifiMac: "02:00:00:00:00:00",
            // NetworkInterface is the surface that still shows the real MAC.
            // Measured here it equals the AP's BSSID (00:db:42:db:24:80), which
            // cannot happen on real hardware -- so it gets its own OUI.
            wifiIface: "wlan0",
            wifiIfaceMac: "3c:bd:3e:5f:1a:72",   // Xiaomi Communications

            // --- 4.4 cpu / memory ----------------------------------------------
            cores: 8,                          // measured: 4
            nativeHeapSize: 33554432,
            nativeHeapAllocated: 12582912,
            nativeHeapFree: 20971520,
            totalMem: 6442450944               // 6 GiB, what a Mi 9 has (measured: 4)
        },

        // ---- native layer (section: "native layer", task 5) -------------------
        // The Java hooks above cannot reach SecurityGuard's engine: it is a .so,
        // and it reads /proc, properties and thread names through libc.
        // Measured on this guest, with every Java hook already installed:
        //     ro.kernel.qemu               1        (Java hook answers 0)
        //     ro.debuggable                1        (ditto)
        //     ro.serialno                  0011ff13 (Build.SERIAL answers 9c1f2d3a)
        //     ro.dalvik.vm.native.bridge   libnb.so
        // i.e. the Java disguise made the two views DISAGREE, and disagreement
        // is exactly what a multi-surface model looks for.  This layer closes it.
        native: {
            enabled: true,

            // Substrings that must not appear in a maps line the app reads.
            // "libnb" is the ARM-translation bridge: an ARM64 .so mapped into an
            // x86_64 process is the clearest single emulator signal on this host.
            dropWords: ["frida", "gum-js", "gumjs", "libgum", "gadget",
                        "linjector", "frida-helper", "re.frida", "libnb"],
            // Anonymous RWX regions hold Interceptor trampolines -- and also
            // legitimate JIT arenas.  OFF: holes of that shape are themselves
            // suspicious, and the names above already cover the agent.
            dropAnonRwx: false,
            // The filtered copy is a memfd; it shows up in maps as
            // "/memfd:jit-cache (deleted)" and is filtered out too, so a second
            // read cannot see the first read's scratch file.
            memfdName: "jit-cache",

            // Frida's threads are named gum-js-loop / gmain / gdbus /
            // pool-frida, and /proc/self/task/<tid>/comm needs no permission to
            // read.  A thread name is 15 bytes max.
            threadNames: ["gum-js-loop", "gmain", "gdbus", "pool-frida", "frida"],
            threadNameReplace: "pool-1-thread",

            // dl_iterate_phdr() is the second way to enumerate loaded images
            // (the linker's link_map); frida-agent is in it.
            hookDlIterate: true,
            // Task 5 "plan A".  Kept because it was asked for, but it can only
            // redirect OUR OWN JS calls: the target never executes GumJS, so it
            // hides nothing from it.  The libc hooks above are what the app can
            // actually observe -- this one is a guard on our own diagnostics.
            hookFindModule: true,

            // Properties as seen through __system_property_get(), i.e. what a
            // native engine reads.  Kept in step with CONF.spoof.propMap and
            // CONF.spoof.buildFields; please edit all three together.
            props: {


                "ro.serialno": "9c1f2d3a",
                "ro.boot.serialno": "9c1f2d3a",
                "ro.product.model": "MI 9",
                "ro.product.manufacturer": "Xiaomi",
                "ro.product.brand": "Xiaomi",
                "ro.product.device": "cepheus",
                "ro.product.name": "cepheus",
                "ro.product.board": "cepheus",
                "ro.build.fingerprint":
                    "Xiaomi/cepheus/cepheus:9/PKQ1.190110.001/9.8.1:user/release-keys",
                "ro.bootimage.build.fingerprint":
                    "Xiaomi/cepheus/cepheus:9/PKQ1.190110.001/9.8.1:user/release-keys",
                "ro.vendor.build.fingerprint":
                    "Xiaomi/cepheus/cepheus:9/PKQ1.190110.001/9.8.1:user/release-keys",
                "ro.build.flavor": "cepheus-user",
                "ro.board.platform": "msm8150",
                "ro.hardware": "qcom",
                "ro.hardware.egl": "adreno",
                "ro.boot.hardware": "qcom",
                // Empty == "no native bridge", which is what a real device
                // answers.  NOTE: libnb keeps running regardless; this only
                // stops the property from announcing it.
                "ro.dalvik.vm.native.bridge": "",
                "ro.debuggable": "0",
                "ro.secure": "1",
                "ro.build.type": "user",
                "ro.build.tags": "release-keys",
                "ro.boot.verifiedbootstate": "green",
                "ro.boot.flash.locked": "1",
                "service.adb.root": "0",
                "ro.kernel.qemu": "0"
                // ro.product.cpu.abilist is NOT here on purpose: x86_64 code is
                // genuinely running and the loader would fail an arm64 claim.
            }
        }
    }
};

/* ------------------------------------------------------------------ *
 * helpers
 * ------------------------------------------------------------------ */

// Render every non-printable / non-ASCII UTF-16 unit as \uXXXX so the log is
// safe in a GBK console and unambiguous about which code point matched.
function esc(s) {
    s = String(s);
    var out = "";
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c < 0x20 || c > 0x7e) {
            out += "\\u" + ("0000" + c.toString(16)).slice(-4);
        } else {
            out += s.charAt(i);
        }
    }
    return out;
}

// Code points above ASCII, formatted for humans ("U+0430").
function cps(s) {
    s = String(s);
    var out = [];
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c > 0x7e) out.push("U+" + ("0000" + c.toString(16).toUpperCase()).slice(-4));
    }
    return out;
}

// Any code point outside 0x00..0x7e? Deliberately not restricted to the
// Cyrillic block, so Greek/fullwidth homoglyphs in the same package are also
// caught -- the package filter above keeps the blast radius to "open.".
function hasNonAscii(s) {
    for (var i = 0; i < s.length; i++) {
        if (s.charCodeAt(i) > 0x7e) return true;
    }
    return false;
}

function clip(s, n) {
    s = String(s);
    return s.length > n ? s.slice(0, n) + "..." : s;
}

// Compact, allocation-light rendering of a Java argument or return value.
function fmt(v) {
    if (v === null) return "null";
    if (v === undefined) return "undefined";
    var t = typeof v;
    if (t === "string") return clip(v, CONF.maxStringLen);
    if (t === "number" || t === "boolean") return String(v);
    try {
        var cn = v.$className;
        if (cn === "[B") {
            var len = v.length;
            var lim = len < CONF.maxBytes ? len : CONF.maxBytes;
            var hex = "";
            for (var i = 0; i < lim; i++) {
                hex += ("0" + (v[i] & 0xff).toString(16)).slice(-2);
            }
            return "byte[" + len + "] " + hex + (len > lim ? "..." : "");
        }
        if (cn === "[C") return "char[" + v.length + "] " + clip(String(v), CONF.maxStringLen);
        if (cn) return cn + " " + clip(String(v), CONF.maxStringLen);
    } catch (e) { /* fall through to String() */ }
    try { return clip(String(v), CONF.maxStringLen); } catch (e2) { return "<" + t + ">"; }
}

// "(int,java.lang.String)" from an overload's argument types.
function sigOf(ov) {
    var parts = [];
    try {
        var ts = ov.argumentTypes;
        for (var i = 0; i < ts.length; i++) parts.push(ts[i].className);
    } catch (e) { }
    return "(" + parts.join(",") + ")";
}

// Type-appropriate zero value for filter mode.
function defaultReturn(ov) {
    var rt = "";
    try { rt = ov.returnType.className; } catch (e) { }
    if (rt === "void") return undefined;
    if (rt === "boolean") return false;
    if (rt === "char") return 0;
    if (rt === "byte" || rt === "short" || rt === "int" || rt === "long") return 0;
    if (rt === "float" || rt === "double") return 0.0;
    return null;
}

/* ------------------------------------------------------------------ *
 * logging sink
 * ------------------------------------------------------------------ *
 * frida-mcp drops console.log(), so send() is the only channel that
 * survives into the JSONL evidence file.
 */
var SEQ = 0;

function emit(o) {
    SEQ += 1;
    o.seq = SEQ;
    o.t = Date.now();
    try { send(o); } catch (e) { /* host went away */ }
}

/* ------------------------------------------------------------------ *
 * hook bookkeeping
 * ------------------------------------------------------------------ */

// key = "<full>#<method><signature>" -- guards against double hooking when
// the rescan timers run after a class was already processed.
var hookedKeys = {};
var hookedClasses = {};      // fullName -> {short, methods, overloads, via}
var processedClasses = {};   // fullName -> reason: resolved, but nothing to hook
var hookCount = 0;

function isReserved(name) {
    return name === "$init" || name === "$dispose" || name === "class" ||
        name === "$className" || name === "$new" || name === "$alloc";
}

// Should this method be neutralised?  Only active when CONF.filter is set.
function stubMatch(fullName, shortName, method) {
    if (!CONF.filter) return false;
    var stub = CONF.stub;
    for (var i = 0; i < stub.length; i++) {
        var pat = stub[i];
        if (pat === "*#" + method) return true;
        if (pat === shortName + "#" + method) return true;
        if (pat === fullName + "#" + method) return true;
    }
    return false;
}

// "com.a.b.c" -> "c"
function shortOf(fullName) {
    var i = fullName.lastIndexOf(".");
    return i < 0 ? fullName : fullName.slice(i + 1);
}

/* ------------------------------------------------------------------ *
 * per-class hooking
 * ------------------------------------------------------------------ */

// Overload.call() demands an explicit arity; these classes are small, so a
// switch up to 6 arguments plus an apply() fallback covers everything. Using
// ov.call() (not this[name]()) guarantees we never re-enter our own hook.
function callOv(ov, self, a) {
    switch (a.length) {
        case 0: return ov.call(self);
        case 1: return ov.call(self, a[0]);
        case 2: return ov.call(self, a[0], a[1]);
        case 3: return ov.call(self, a[0], a[1], a[2]);
        case 4: return ov.call(self, a[0], a[1], a[2], a[3]);
        case 5: return ov.call(self, a[0], a[1], a[2], a[3], a[4]);
        case 6: return ov.call(self, a[0], a[1], a[2], a[3], a[4], a[5]);
    }
    return ov.apply(self, a);
}

// Replace one overload: log the call, then either pass through or, in filter
// mode, return a type-appropriate default without calling the original.
function install(ov, fullName, shortName, m, sig) {
    ov.implementation = function () {
        var a = [];
        for (var i = 0; i < arguments.length; i++) a.push(arguments[i]);

        var stub = stubMatch(fullName, shortName, m);
        var rec = {
            ev: stub ? "call-stub" : "call",
            cls: esc(shortName),
            m: esc(m),
            sig: sig,
            args: []
        };
        for (var j = 0; j < a.length; j++) rec.args.push(esc(fmt(a[j])));

        if (stub) {
            var d = defaultReturn(ov);
            rec.ret = esc(fmt(d));
            emit(rec);
            return d;
        }

        var r;
        try {
            r = callOv(ov, this, a);
        } catch (e) {
            rec.err = clip(String(e), 200);
            emit(rec);
            throw e;              // preserve the original failure semantics
        }
        rec.ret = esc(fmt(r));
        emit(rec);
        return r;
    };
}

/* ------------------------------------------------------------------ *
 * class loaders
 * ------------------------------------------------------------------ *
 * Taobao's SecurityGuard "open" classes are NOT reachable through the default
 * ClassFactory. Measured on this build (10.68.0, Android 9 x86_64): every one
 * of the nine names under ...securitybody.open. -- including the pure-ASCII
 * MalDetect -- throws ClassNotFoundException from Java.use(), because they are
 * defined by a child loader of the app loader (com.taobao.appbundle.runtime.
 * InjectClassLoader); a parent never resolves its child's classes.
 *
 * Java.choose("java.lang.ClassLoader") is not a way out: it sweeps ZERO
 * instances on this ART, which is exactly what made the classes look
 * unresolvable. The bridge exposes the right primitive instead --
 * Java.enumerateClassLoaders(), i.e. art::ClassLinker::VisitClassLoaders --
 * and Java.ClassFactory.get(loader) turns one loader into a factory that can
 * resolve its own classes.
 *
 * The async form is required, not stylistic: the bridge deletes each loader's
 * global ref once onMatch returns, so Java.retain() has to run inside the
 * callback or the wrapper is dangling afterwards.
 */

var loaderIds = {};
var loaderFactories = [];      // [{ id, factory }]
var lastLoaderSweep = 0;
var useFailReported = {};      // fullName -> true, keeps rescan noise down

function loaderId(l) {
    try { return String(l.getClass().getName()) + "@" + l.hashCode(); } catch (e) { return null; }
}

// Pin the loader wrapper for the life of the session and cache one factory
// per distinct loader. Returns true only for a loader we had not seen yet.
function noteLoader(l) {
    if (!l) return false;
    var id = loaderId(l);
    if (id === null || loaderIds[id]) return false;
    var kept, f;
    try {
        kept = Java.retain(l);
        f = Java.ClassFactory.get(kept);
    } catch (e) {
        emit({ ev: "loader-factory-failed", id: esc(String(id)), err: clip(String(e), 200) });
        return false;
    }
    loaderIds[id] = true;
    loaderFactories.push({ id: id, factory: f });
    emit({ ev: "loader-seen", id: esc(id), n: loaderFactories.length });
    return true;
}

// minIntervalMs throttles the sweep: hookClass() asks for one on every failed
// resolution, and VisitClassLoaders suspends all ART threads while it runs.
function sweepLoaders(minIntervalMs) {
    var now = Date.now();
    if (minIntervalMs && now - lastLoaderSweep < minIntervalMs) return 0;
    lastLoaderSweep = now;
    var found = 0;
    try {
        Java.enumerateClassLoaders({
            onMatch: function (l) {
                if (noteLoader(l)) found += 1;
            },
            onComplete: function () { }
        });
    } catch (e) {
        emit({ ev: "enumerate-loaders-failed", err: clip(String(e), 200) });
        return -1;
    }
    return found;
}

// Declared constructors and fields, used only by the "resolved but nothing to
// hook" line: declared methods = 0 is either a pure marker class or a
// constructor-only one, and saying which turns an ambiguous gap into a fact.
function countCtors(K) {
    try { return K.class.getDeclaredConstructors().length; } catch (e) { return -1; }
}

function countFields(K) {
    try { return K.class.getDeclaredFields().length; } catch (e) { return -1; }
}

// Hook every declared member of one class. Returns the number of overloads
// wired up, or 0 when the class is already processed, cannot be resolved, or
// declares nothing but reserved members. $init is never touched.
function hookClass(fullName) {
    if (hookedClasses[fullName] || processedClasses[fullName]) return 0;
    var shortName = shortOf(fullName);

    // Resolution is loader-dependent (see the class-loaders block above): the
    // default ClassFactory only sees the app loader, and these classes live in
    // one of its children. Try the default first -- it is the fast path and it
    // is what every non-SecurityGuard class hits -- then walk the loaders we
    // have discovered.
    var K = null;
    var via = "default";
    try {
        K = Java.use(fullName);
    } catch (e) {
        // First miss pays for a sweep; later misses reuse the list and are
        // throttled inside sweepLoaders().
        if (!useFailReported[fullName]) sweepLoaders(0);
        for (var li = 0; li < loaderFactories.length; li++) {
            try {
                K = loaderFactories[li].factory.use(fullName);
                via = loaderFactories[li].id;
                emit({
                    ev: "use-via-loader", cls: esc(fullName), via: esc(via),
                    loaders: loaderFactories.length
                });
                break;
            } catch (e2) { }
        }
        if (K === null) {
            if (!useFailReported[fullName]) {
                useFailReported[fullName] = true;
                emit({
                    ev: "use-failed", cls: esc(fullName), err: clip(String(e), 200),
                    loaders: loaderFactories.length
                });
            }
            return 0;
        }
    }

    // Frida exposes overloads per name but not the name list itself, so ask
    // java.lang.Class. De-duplicated in declaration order.
    var declared = [];
    try {
        var ms = K.class.getDeclaredMethods();
        for (var i = 0; i < ms.length; i++) {
            var mn = String(ms[i].getName());
            if (declared.indexOf(mn) < 0) declared.push(mn);
        }
    } catch (e2) {
        emit({ ev: "enum-failed", cls: esc(fullName), err: clip(String(e2), 200) });
        return 0;
    }

    var done = [];
    var total = 0;
    for (var j = 0; j < declared.length; j++) {
        var m = declared[j];
        if (isReserved(m)) continue;

        var ovs = null;
        try { ovs = K[m].overloads; } catch (e3) { ovs = null; }
        if (!ovs) continue;

        var hit = 0;
        for (var k = 0; k < ovs.length; k++) {
            var ov = ovs[k];
            var sig = sigOf(ov);
            var key = fullName + "#" + m + sig;
            if (hookedKeys[key]) continue;
            hookedKeys[key] = true;
            try {
                install(ov, fullName, shortName, m, sig);
                hit += 1;
            } catch (e4) {
                emit({
                    ev: "hook-failed", cls: esc(shortName), m: esc(m), sig: sig,
                    err: clip(String(e4), 200)
                });
            }
        }
        if (hit > 0) {
            done.push(m + "x" + hit);
            total += hit;
        }
    }

    // Resolved, walked, nothing to install. Record it so the rescan timers stop
    // retrying: MalDetect$<U+0430> is exactly this case -- it declares no
    // methods, so "seen but not hooked" is the honest final answer, not a bug
    // to keep re-attempting every ten seconds.
    if (total === 0) {
        processedClasses[fullName] = "no-hookable-members";
        emit({
            ev: "class-no-members", cls: esc(fullName), short: esc(shortName),
            cps: cps(shortName), declared: declared.length, via: esc(via),
            ctors: countCtors(K), fields: countFields(K)
        });
        return 0;
    }
    hookCount += total;
    hookedClasses[fullName] = { short: shortName, methods: done, overloads: total, via: via };
    emit({
        ev: "class-hooked", cls: esc(fullName), short: esc(shortName),
        cps: cps(shortName), methods: done.length, overloads: total, via: esc(via), list: done
    });
    return total;
}

/* ------------------------------------------------------------------ *
 * matching
 * ------------------------------------------------------------------ */

// Is this a class we care about?  Two tests, both required: the name sits
// directly in the "open" package and its simple part carries a non-ASCII
// code point.  The package test caps the blast radius; the code point test
// is what actually finds the Cyrillic names.
function isTarget(fullName) {
    if (!fullName) return false;
    var name = String(fullName);
    if (name.indexOf(CONF.pkgDot) !== 0) return false;
    var shortName = name.slice(CONF.pkgDot.length);
    if (shortName.length === 0) return false;
    if (shortName.indexOf(".") >= 0) return false;   // sub-package, not ours
    return hasNonAscii(shortName);
}

// fullName -> true for every match the VM has handed us so far.  Kept apart
// from hookedClasses because a class can be seen and still fail to hook
// (use-failed / enum-failed), and the coverage summary must say so.
var seenTargets = {};

function noteSeen(fullName) {
    if (seenTargets[fullName]) return false;
    seenTargets[fullName] = true;
    emit({
        ev: "target-seen", cls: esc(fullName),
        short: esc(shortOf(fullName)), cps: cps(shortOf(fullName))
    });
    return true;
}

// Enumerate every loaded class and hook each match that is not wired yet.
// This is the single place hookClass() is driven from, so a class found at
// boot and a class found on the last timer take the identical path.
function rescan(tag) {
    var names;
    try {
        names = Java.enumerateLoadedClassesSync();
    } catch (e) {
        emit({ ev: "enum-classes-failed", tag: tag, err: clip(String(e), 200) });
        return -1;
    }
    var fresh = 0;
    for (var i = 0; i < names.length; i++) {
        var fn = names[i];
        if (!isTarget(fn)) continue;
        noteSeen(fn);
        if (hookedClasses[fn] || processedClasses[fn]) continue;
        fresh += hookClass(fn);
    }
    return fresh;
}

/* ------------------------------------------------------------------ *
 * late-resolution watchers
 * ------------------------------------------------------------------ *
 * The six classes are reflective entry points, so most of them are simply
 * not loaded when this script starts.  Hooking the loader instead of the
 * class catches a match the moment it becomes reachable, even when the
 * caller drops the reference straight away.
 */

// Wrap one loader overload: run the original, then inspect the class it
// resolved.  A named function rather than a loop-local closure because `ov`
// must be captured per iteration -- a `var` in the loop would leave every
// implementation pointing at the last overload.
function watchOne(ov, kls, m, sig) {
    ov.implementation = function () {
        var a = [];
        for (var i = 0; i < arguments.length; i++) a.push(arguments[i]);
        var r = callOv(ov, this, a);      // exceptions propagate untouched
        try {
            if (r !== null && r !== undefined) {
                var nm = String(r.getName());
                if (isTarget(nm)) {
                    // `this` is the loader that just resolved a target: the
                    // cheapest and most precise loader source there is.
                    noteLoader(this);
                    noteSeen(nm);
                    if (!hookedClasses[nm] && !processedClasses[nm]) hookClass(nm);
                }
            }
        } catch (e) {
            emit({ ev: "watch-check-failed", m: esc(m), err: clip(String(e), 200) });
        }
        return r;
    };
}

function watchLoads() {
    var APIs = [
        ["java.lang.ClassLoader", "loadClass"],
        ["java.lang.ClassLoader", "findClass"],
        ["java.lang.Class", "forName"]
    ];
    var installed = 0;
    for (var i = 0; i < APIs.length; i++) {
        var kls = APIs[i][0], m = APIs[i][1];
        var K;
        try {
            K = Java.use(kls);
        } catch (e) {
            emit({ ev: "watch-skip", cls: esc(kls), m: esc(m), err: clip(String(e), 200) });
            continue;
        }
        var ovs;
        try {
            ovs = K[m].overloads;
        } catch (e2) {
            emit({ ev: "watch-skip", cls: esc(kls), m: esc(m), err: clip(String(e2), 200) });
            continue;
        }
        for (var j = 0; j < ovs.length; j++) {
            var ov = ovs[j];
            var sig = sigOf(ov);
            var key = "watch:" + kls + "#" + m + sig;
            if (hookedKeys[key]) continue;
            hookedKeys[key] = true;
            try {
                watchOne(ov, kls, m, sig);
                installed += 1;
            } catch (e3) {
                emit({ ev: "watch-failed", cls: esc(kls), m: esc(m), sig: sig, err: clip(String(e3), 200) });
            }
        }
    }
    emit({ ev: "watchers", installed: installed });
    return installed;
}

/* ------------------------------------------------------------------ *
 * coverage summary
 * ------------------------------------------------------------------ */

function countKeys(o) {
    var n = 0;
    for (var k in o) {
        if (Object.prototype.hasOwnProperty.call(o, k)) n += 1;
    }
    return n;
}

// One row per expected class plus anything unexpected the scan turned up.
// This is the only place the six names are checked off, so a short log is
// itself the answer to "did we actually see all six?".
function coverage() {
    var rows = [];
    var missing = [];
    var seen = 0;
    for (var i = 0; i < CONF.expected.length; i++) {
        var shortName = CONF.expected[i];
        var fullName = CONF.pkgDot + shortName;
        var got = Object.prototype.hasOwnProperty.call(seenTargets, fullName);
        if (got) seen += 1; else missing.push(esc(shortName));
        var h = hookedClasses[fullName];
        rows.push({
            short: esc(shortName),
            cps: cps(shortName),
            full: esc(fullName),
            seen: got,
            hooked: !!h,
            overloads: h ? h.overloads : 0,
            via: h ? esc(h.via) : null,
            // "hooked" alone cannot tell "never loaded" from "loaded but has no
            // methods", and those mean very different things to the operator.
            state: h ? "hooked" : (processedClasses[fullName] || (got ? "unresolved" : "absent"))
        });
    }

    var extra = [];
    for (var name in seenTargets) {
        if (!Object.prototype.hasOwnProperty.call(seenTargets, name)) continue;
        if (CONF.expected.indexOf(shortOf(name)) < 0) extra.push(esc(name));
    }

    var hooked = [];
    for (var fn in hookedClasses) {
        if (!Object.prototype.hasOwnProperty.call(hookedClasses, fn)) continue;
        hooked.push(esc(hookedClasses[fn].short) + ":" + hookedClasses[fn].overloads);
    }

    // Seen, resolved, but nothing installable -- recorded once per class so the
    // summary states it instead of leaving a silent hole in the row list.
    var skipped = [];
    for (var pn in processedClasses) {
        if (!Object.prototype.hasOwnProperty.call(processedClasses, pn)) continue;
        skipped.push(esc(shortOf(pn)) + ":" + processedClasses[pn]);
    }

    emit({
        ev: "coverage",
        pkg: esc(CONF.pkgDot),
        expected: CONF.expected.length,
        seenClasses: seen,
        hookClasses: countKeys(hookedClasses),
        hookOverloads: hookCount,
        noMemberClasses: countKeys(processedClasses),
        filter: CONF.filter,
        stubN: CONF.stub.length,
        bypassHits: BYPASS.hits,
        rows: rows,
        missing: missing,
        extra: extra,
        hooked: hooked,
        skipped: skipped
    });
    return rows;
}

/* ------------------------------------------------------------------ *
 * forced-login bypass (feed-forward control)
 * ------------------------------------------------------------------ *
 * WHY
 *   Taobao's guest mode still routes to LoginActivity / forced guide pages
 *   whenever a "logged-in-only" surface is touched (cart tab, profile tab,
 *   some feed cards).  A UI-only sweep cannot fix that: by the time the login
 *   Activity is on screen the navigation has already happened.
 *
 *   So the jump is stopped one layer below the UI, where it is a single
 *   decision: Activity.startActivity*() / Instrumentation.execStartActivity().
 *   Both are hooked, because Activity subclasses may override the former and
 *   routers may call the latter directly -- execStartActivity is the funnel
 *   every real start passes through.
 *
 * REFUSE TO BREAK COLD START
 *   "welcome" / "splash" / "guide" are matched too, but Taobao's own launcher
 *   classes live in that namespace.  Three guards keep the app startable:
 *     1. the intent's component equal to our package's launch activity is
 *        never blocked;
 *     2. soft words (welcome/splash/guide/onboard) are only blocked once the
 *        soft window (CONF.bypass.softWindowMs) has elapsed -- i.e. long after
 *        the cold-start route has happened;
 *     3. any class in CONF.bypass.allow is never blocked.
 *
 * STARTACTIVITYFORRESULT
 *   Dropping the call leaves the caller waiting for a result that never
 *   comes.  Unless CONF.bypass.fakeCancel is false, a synthetic
 *   onActivityResult(requestCode, RESULT_CANCELED, null) is posted to the main
 *   looper, so the caller unwinds as "user cancelled" instead of hanging.  It
 *   is capped (maxCancelClasses) because every post registers a small class.
 *
 *   This section is independent of the SecurityGuard enumeration below; it
 *   never touches CONF.filter / CONF.stub and installs before the first scan.
 */

var BYPASS = {
    hits: 0,
    logged: 0,
    myPkg: null,
    launcher: null,
    cancelClasses: 0,
    cancelKeep: [],        // keeps registered Runnable classes + their captures alive
    bootMs: Date.now()
};

function lower(s) {
    return String(s).toLowerCase();
}

// Package + launcher activity, resolved once the VM has an Application.
// Deliberately retried until it succeeds: called from a hook that can fire
// before Application.attach(), and a "not found" answer would silently
// disable the launcher exemption.
function pkgAndLauncher() {
    if (BYPASS.myPkg !== null && BYPASS.launcher !== null) return;
    try {
        var app = Java.use("android.app.ActivityThread").currentApplication();
        if (app === null || app === undefined) return;
        BYPASS.myPkg = String(app.getPackageName());
        var li = app.getPackageManager().getLaunchIntentForPackage(BYPASS.myPkg);
        if (li !== null && li !== undefined) {
            var comp = li.getComponent();
            if (comp !== null && comp !== undefined) {
                BYPASS.launcher = String(comp.getClassName());
            }
        }
    } catch (e) {
        if (BYPASS.logged < 2) {
            BYPASS.logged += 1;
            emit({ ev: "bypass-init", err: clip(String(e), 200) });
        }
    }
}

// Explicit component class name, or null for an implicit intent (those carry
// no class to judge; the Python watcher is the fallback for that case).
function classOfIntent(intent) {
    if (intent === null || intent === undefined) return null;
    try {
        var comp = intent.getComponent();
        if (comp !== null && comp !== undefined) return String(comp.getClassName());
    } catch (e) { }
    return null;
}

function matchesAny(cls, list) {
    var lc = lower(cls);
    for (var i = 0; i < list.length; i++) {
        if (lc.indexOf(lower(list[i])) >= 0) return list[i];
    }
    return null;
}

// null = let the call through, otherwise { cls, why, soft }.
function blockDecision(intent) {
    if (!CONF.bypass.enabled) return null;
    var cls = classOfIntent(intent);
    if (cls === null) return null;
    pkgAndLauncher();
    if (BYPASS.launcher !== null && cls === BYPASS.launcher) return null;
    if (matchesAny(cls, CONF.bypass.allow) !== null) return null;

    var strong = matchesAny(cls, CONF.bypass.words);
    if (strong !== null) return { cls: cls, why: "word:" + strong, soft: false };

    var soft = matchesAny(cls, CONF.bypass.softWords);
    if (soft !== null) {
        // A long-lived session that suddenly routes to a welcome/splash screen
        // is being bounced to a guide page, not starting up.
        if (Date.now() - BYPASS.bootMs < CONF.bypass.softWindowMs) return null;
        return { cls: cls, why: "soft:" + soft, soft: true };
    }
    return null;
}

// One line per blocked jump.  `msg` is the human line the host mirrors to its
// console (run_agent.py prints payload.msg for ev === "bypass").
function logBlock(d, hookName) {
    BYPASS.hits += 1;
    emit({
        ev: "bypass",
        hook: hookName,
        cls: esc(d.cls),
        why: d.why,
        soft: d.soft,
        n: BYPASS.hits,
        msg: "[Bypass] Blocked login activity: " + esc(d.cls)
    });
}

// Give a blocked startActivityForResult() caller a result instead of leaving it
// pending: post onActivityResult(requestCode, RESULT_CANCELED, null) to the main
// looper.  Each post needs its own Runnable implementation (it captures the
// activity + requestCode), so this stops after CONF.bypass.maxCancelClasses.
function fakeCancel(act, requestCode) {
    if (act === null || act === undefined) return;
    if (!CONF.bypass.fakeCancel) return;
    if (BYPASS.cancelClasses >= CONF.bypass.maxCancelClasses) return;
    BYPASS.cancelClasses += 1;
    try {
        var Runnable = Java.use("java.lang.Runnable");
        var target = act;
        var code = requestCode;
        var K = Java.registerClass({
            name: "rea.BypassCancel" + BYPASS.cancelClasses,
            implements: [Runnable],
            methods: {
                run: function () {
                    try {
                        // 0 == Activity.RESULT_CANCELED
                        target.onActivityResult(code, 0, null);
                    } catch (e) {
                        emit({ ev: "bypass-cancel-failed", err: clip(String(e), 160) });
                    }
                }
            }
        });
        BYPASS.cancelKeep.push(K);
        var Handler = Java.use("android.os.Handler");
        var Looper = Java.use("android.os.Looper");
        Handler.$new(Looper.getMainLooper()).post(K.$new());
    } catch (e) {
        emit({ ev: "bypass-cancel-skip", err: clip(String(e), 160) });
    }
}
// Replace every overload of klass[name]() that takes an Intent.  The Intent's
// position comes from argumentTypes rather than being assumed, because the
// startActivity family has several shapes:
//     (Intent) (Intent,Bundle) (Intent,int) (Intent,int,Bundle)
//     (Fragment,Intent,int) (Activity,Intent,int,Bundle)
//     execStartActivity(Context,IBinder,IBinder,Activity,Intent,int[,Bundle])
// Returns the number of overloads installed.
function hookStarter(klass, name, hookTag, withResult) {
    var fn;
    try { fn = klass[name]; } catch (e) { return 0; }
    if (fn === undefined || fn === null) return 0;
    var ovs = fn.overloads;
    var installed = 0;
    for (var i = 0; i < ovs.length; i++) {
        var ov = ovs[i];
        var types = [];
        try { types = ov.argumentTypes; } catch (e2) { }
        var ai = -1;
        for (var t = 0; t < types.length; t++) {
            if (types[t].className === "android.content.Intent") { ai = t; break; }
        }
        if (ai < 0) continue;
        installStarter(ov, ai, hookTag + sigOf(ov), withResult);
        installed += 1;
    }
    return installed;
}

// Java.cast() is the only way to obtain a wrapper that actually exposes
// Activity.onActivityResult().  A wrapper keeps the *declared* type of the slot
// it came from, and that type is not always Activity:
//   * startActivity* hooks -> `this` is the Activity (fine as-is)
//   * execStartActivity    -> `this` is the Instrumentation, and the caller sits
//                             in an Activity- or Context-typed argument
// So every plausible slot is offered here and the first one that really is an
// Activity wins; a non-Activity argument simply throws and is skipped.
function pickActivity(list) {
    for (var i = 0; i < list.length; i++) {
        var o = list[i];
        if (o === null || o === undefined) continue;
        try {
            return Java.cast(o, Java.use("android.app.Activity"));
        } catch (e) { /* not an Activity: next candidate */ }
    }
    return null;
}

// The replacement itself: same shape as `install` above (log, then either drop
// the original call or pass it through).  callOv is reused so the original is
// invoked through the overload handle and never re-enters this hook.
function installStarter(ov, ai, tag, withResult) {
    // Positions are resolved once, from the overload's own argument list.
    var types = [];
    try { types = ov.argumentTypes; } catch (e) { }
    var actIdx = -1, ctxIdx = -1;
    for (var t = 0; t < types.length; t++) {
        var cn = types[t].className;
        if (actIdx < 0 && cn === "android.app.Activity") actIdx = t;
        if (ctxIdx < 0 && cn === "android.content.Context") ctxIdx = t;
    }

    ov.implementation = function () {
        var d = blockDecision(arguments[ai]);
        if (d !== null) {
            logBlock(d, tag);
            if (withResult) {
                var cand = [];
                if (actIdx >= 0) cand.push(arguments[actIdx]);
                if (ctxIdx >= 0) cand.push(arguments[ctxIdx]);
                cand.push(this);
                var caller = pickActivity(cand);
                if (caller !== null) {
                    fakeCancel(caller, arguments[ai + 1]);
                } else {
                    emit({ ev: "bypass-cancel-skip", why: "no-caller", hook: tag });
                }
            }
            return defaultReturn(ov);
        }
        var a = [];
        for (var k = 0; k < arguments.length; k++) a.push(arguments[k]);
        return callOv(ov, this, a);
    };
}

function installBypass() {
    if (!CONF.bypass.enabled) {
        emit({ ev: "bypass-boot", enabled: false });
        return;
    }
    var n = 0;
    try {
        var Activity = Java.use("android.app.Activity");
        n += hookStarter(Activity, "startActivity", "Activity.startActivity", false);
        n += hookStarter(Activity, "startActivityForResult", "Activity.startActivityForResult", true);
        // androidx ActivityResultLauncher / fragment-driven starts land here.
        n += hookStarter(Activity, "startActivityFromFragment", "Activity.startActivityFromFragment", true);
        n += hookStarter(Activity, "startActivityFromChild", "Activity.startActivityFromChild", true);
    } catch (e) {
        emit({ ev: "bypass-hook-failed", where: "Activity", err: clip(String(e), 200) });
    }
    if (CONF.bypass.hookInstrumentation) {
        try {
            var Instr = Java.use("android.app.Instrumentation");
            var nI = hookStarter(Instr, "execStartActivity", "Instrumentation.execStartActivity", true);
            n += nI;
        } catch (e2) {
            emit({ ev: "bypass-hook-failed", where: "Instrumentation", err: clip(String(e2), 200) });
        }
    }
    pkgAndLauncher();
    emit({
        ev: "bypass-boot",
        enabled: true,
        hookOverloads: n,
        words: CONF.bypass.words.length,
        softWords: CONF.bypass.softWords.length,
        softWindowMs: CONF.bypass.softWindowMs,
        fakeCancel: CONF.bypass.fakeCancel,
        instr: CONF.bypass.hookInstrumentation,
        pkg: esc(BYPASS.myPkg || "?"),
        launcher: esc(BYPASS.launcher || "?")
    });
}

/* ------------------------------------------------------------------ *
 * device spoof (root / emulator / frida fingerprints)
 * ------------------------------------------------------------------ *
 * WHY THIS LAYER EXISTS
 *   On this host the risk model reacts to three things at once -- an x86_64
 *   emulator image, a rooted system, and an attached frida -- and its answer is
 *   a QR verification page that no UI dismissal can leave (measured: one BACK,
 *   two BACKs and a tap on the page's own back arrow all leave
 *   UserLoginActivity focused).  This section repairs the *inputs* instead of
 *   fighting the page.
 *
 * SAFETY CONTRACT (every hook in this section)
 *   1. the original overload handle is captured BEFORE the replacement is
 *      installed, and the replacement forwards to it for every decision it does
 *      not explicitly override;
 *   2. the whole body of a replacement is inside try/catch, and the catch path
 *      also forwards -- a failed override must never become a thrown exception
 *      inside the app;
 *   3. a class, field or overload that cannot be resolved is reported as
 *      "spoof-skip" and skipped; it never aborts boot;
 *   4. no return TYPE changes: exists() stays boolean, get() stays String,
 *      getDeviceId() stays String -- so a wrong guess cannot break a cast.
 *
 * WHAT IS DELIBERATELY NOT DONE
 *   * Build.SUPPORTED_ABIS / os.arch are left alone.  The package manager's
 *     native-library loader reads them; lying there breaks the app instead of
 *     hiding the emulator.
 *   * /proc/self/maps CONTENT is left alone.  SecurityGuard reads it through
 *     native code, which a Java hook cannot reach; only directory *listings*
 *     are filtered (hideFrida), and that limitation is stated here instead of
 *     being papered over.
 */

var SPOOF = {
    fileCache: {},          // path -> boolean; File.exists() is very hot
    fileCacheN: 0,
    hits: {},               // per-key counters, also the log rate limiter
    verifyTries: 0          // bounded retries while the app is still starting
};

// "/system/bin/su" ends with the segment, "/system/usr/..." does not: a plain
// substring test would hide the latter, which the app really does stat.
var SU_SEGMENT = /(?:^|\/)su(?:\/|$)/;

function spoofBump(k) {
    SPOOF.hits[k] = (SPOOF.hits[k] || 0) + 1;
    return SPOOF.hits[k];
}

// Emit at most `cap` lines per key.  A File.exists() hook fires thousands of
// times per second; unthrottled logging would bury the SG evidence.
function spoofNote(ev, key, extra, cap) {
    var c = spoofBump(key);
    if (c > (cap || 4)) return;
    var o = { ev: ev, n: c };
    if (extra) { for (var k in extra) o[k] = extra[k]; }
    emit(o);
}

function spoofSkip(where, err) {
    emit({ ev: "spoof-skip", where: where, err: clip(String(err), 160) });
}

function isRootPath(p) {
    var s = String(p);
    var cached = SPOOF.fileCache[s];
    if (cached !== undefined) return cached;
    var lp = s.toLowerCase();
    var verdict = SU_SEGMENT.test(lp);
    if (!verdict) {
        for (var i = 0; i < CONF.spoof.rootWords.length; i++) {
            if (lp.indexOf(CONF.spoof.rootWords[i]) >= 0) { verdict = true; break; }
        }
    }
    if (SPOOF.fileCacheN < 1024) {          // bounded cache, then decide per call
        SPOOF.fileCache[s] = verdict;
        SPOOF.fileCacheN += 1;
    }
    return verdict;
}

// exists() and isFile() take no arguments and return boolean -- the two shapes
// a root check actually uses.
function hookFilePredicate(File, name) {
    var fn;
    try { fn = File[name]; } catch (e) { return 0; }
    if (fn === undefined || fn === null) return 0;
    var ovs = fn.overloads;
    var n = 0;
    for (var i = 0; i < ovs.length; i++) {
        if (ovs[i].argumentTypes.length !== 0) continue;
        try {
            (function (orig, tag) {
                orig.implementation = function () {
                    var p = null;
                    try { p = this.getPath(); } catch (e1) { p = null; }
                    try {
                        if (p !== null && isRootPath(p)) {
                            spoofNote("spoof-root-hide", "hide:" + tag,
                                { path: esc(clip(String(p), 120)) }, 8);
                            return false;
                        }
                    } catch (e2) { /* forward below */ }
                    return orig.call(this);
                };
            })(ovs[i], name);
            n += 1;
        } catch (e3) {
            spoofSkip("File." + name, e3);
        }
    }
    return n;
}

function fridaName(name) {
    if (name === null || name === undefined) return false;
    var ln = String(name).toLowerCase();
    for (var i = 0; i < CONF.spoof.fridaNames.length; i++) {
        if (ln.indexOf(CONF.spoof.fridaNames[i]) >= 0) return true;
    }
    return false;
}

// File.list() -> String[] and File.listFiles() -> File[]: same filter, two
// element types.  Java.array() builds the replacement in the right type, and
// the untouched array is returned as-is when nothing matched -- so a listing
// the filter has no opinion about costs one loop and nothing else.
function hookFileListing(File) {
    var n = 0;
    try {
        var listOv = File.list.overload();
        var origList = listOv;
        listOv.implementation = function () {
            var arr = origList.call(this);
            try {
                if (arr === null || arr === undefined) return arr;
                var kept = [];
                for (var i = 0; i < arr.length; i++) {
                    if (!fridaName(arr[i])) kept.push(arr[i]);
                }
                if (kept.length === arr.length) return arr;
                spoofNote("spoof-frida-hide", "hide:list",
                    { path: esc(clip(String(this.getPath()), 120)),
                      dropped: arr.length - kept.length }, 6);
                return Java.array("java.lang.String", kept);
            } catch (e) {
                return arr;
            }
        };
        n += 1;
    } catch (e1) {
        spoofSkip("File.list", e1);
    }
    try {
        var lfOv = File.listFiles.overload();
        var origLf = lfOv;
        lfOv.implementation = function () {
            var arr = origLf.call(this);
            try {
                if (arr === null || arr === undefined) return arr;
                var kept = [];
                for (var i = 0; i < arr.length; i++) {
                    var nm = null;
                    try { nm = arr[i].getName(); } catch (e0) { nm = null; }
                    if (!fridaName(nm)) kept.push(arr[i]);
                }
                if (kept.length === arr.length) return arr;
                spoofNote("spoof-frida-hide", "hide:listFiles",
                    { path: esc(clip(String(this.getPath()), 120)),
                      dropped: arr.length - kept.length }, 6);
                return Java.array("java.io.File", kept);
            } catch (e) {
                return arr;
            }
        };
        n += 1;
    } catch (e2) {
        spoofSkip("File.listFiles", e2);
    }
    return n;
}

function propOverride(key) {
    if (key === null || key === undefined) return null;
    var v = CONF.spoof.propMap[String(key)];
    return (v === undefined) ? null : v;
}

// SystemProperties.get(String) / get(String,String) both return String, so the
// spoofed value can be returned directly (Frida converts a JS string to
// java.lang.String on return).  Only overloads whose FIRST argument is a String
// are touched; getInt/getLong/getBoolean have their own shape and are hooked
// separately below.
function hookPropGetters(SP) {
    var n = 0;
    var names = ["get"];
    for (var i = 0; i < names.length; i++) {
        var fn;
        try { fn = SP[names[i]]; } catch (e) { continue; }
        if (fn === undefined || fn === null) continue;
        var ovs = fn.overloads;
        for (var j = 0; j < ovs.length; j++) {
            var ov = ovs[j];
            var types = [];
            try { types = ov.argumentTypes; } catch (e2) { continue; }
            if (types.length === 0 || types[0].className !== "java.lang.String") continue;
            try {
                (function (orig) {
                    orig.implementation = function () {
                        var a = [];
                        for (var k = 0; k < arguments.length; k++) a.push(arguments[k]);
                        try {
                            var v = propOverride(a[0]);
                            if (v !== null) {
                                spoofNote("spoof-prop", "prop:" + String(a[0]),
                                    { key: esc(clip(String(a[0]), 80)), val: v }, 8);
                                return v;
                            }
                        } catch (e3) { /* forward below */ }
                        return callOv(orig, this, a);
                    };
                })(ov);
                n += 1;
            } catch (e4) {
                spoofSkip("SystemProperties." + names[i] + sigOf(ov), e4);
            }
        }
    }
    return n;
}

// getBoolean(String,boolean) and getInt(String,int) read the same properties
// through a different surface; a key that is spoofed in get() but not here is a
// contradiction a fingerprint model can see.
function hookPropScalars(SP) {
    var n = 0;
    try {
        var gb = SP.getBoolean.overload("java.lang.String", "boolean");
        var origGb = gb;
        gb.implementation = function (k, def) {
            try {
                var v = propOverride(k);
                if (v !== null) return v !== "0";
            } catch (e1) { /* forward */ }
            return origGb.call(this, k, def);
        };
        n += 1;
    } catch (e2) {
        spoofSkip("SystemProperties.getBoolean", e2);
    }
    try {
        var gi = SP.getInt.overload("java.lang.String", "int");
        var origGi = gi;
        gi.implementation = function (k, def) {
            try {
                var v = propOverride(k);
                if (v !== null) {
                    var num = parseInt(v, 10);
                    return isNaN(num) ? def : num;
                }
            } catch (e3) { /* forward */ }
            return origGi.call(this, k, def);
        };
        n += 1;
    } catch (e4) {
        spoofSkip("SystemProperties.getInt", e4);
    }
    return n;
}

// Build.* are static final String fields.  The bridge exposes a static field as
// a writable handle, and these particular fields are initialised from
// SystemProperties at runtime (they are not compile-time constants), so a
// write here is what the app reads back.  Each field is independent: a field
// that cannot be written is reported and the rest still install.
function hookBuildFields(B) {
    var n = 0;
    for (var k in CONF.spoof.buildFields) {
        try {
            B[k].value = CONF.spoof.buildFields[k];
            n += 1;
        } catch (e) {
            spoofSkip("Build." + k, e);
        }
    }
    return n;
}

// One value for both getDeviceId() and getImei(): a model that cross-checks the
// two surfaces must not see a disagreement.  The value is Luhn-valid, so a
// checksum test passes as well.
function hookTelephonyGetter(TM, name, value) {
    var fn;
    try { fn = TM[name]; } catch (e) { return 0; }
    if (fn === undefined || fn === null) return 0;
    var ovs = fn.overloads;
    var n = 0;
    for (var i = 0; i < ovs.length; i++) {
        var ov = ovs[i];
        var types = [];
        try { types = ov.argumentTypes; } catch (e) { continue; }
        // Only the no-argument shape and the slot-0 shape are answered.  A
        // different slot keeps the platform's answer: inventing a value there
        // would be a contradiction, not a disguise.
        if (types.length > 1) continue;
        if (types.length === 1 && types[0].className !== "int") continue;
        try {
            (function (orig, tag) {
                orig.implementation = function () {
                    var a = [];
                    for (var k = 0; k < arguments.length; k++) a.push(arguments[k]);
                    try {
                        if (a.length === 0 || a[0] === 0) {
                            spoofNote("spoof-telephony", "tel:" + tag,
                                { m: tag, val: value }, 4);
                            return value;
                        }
                    } catch (e1) { /* forward below */ }
                    return callOv(orig, this, a);
                };
            })(ov, name);
            n += 1;
        } catch (e2) {
            spoofSkip("TelephonyManager." + name + sigOf(ov), e2);
        }
    }
    return n;
}

// Task 3: WebView URL block.  OFF by default -- measured unnecessary here, the
// QR page is a native Fragment (aliuser_* resource-ids), not H5.  When enabled,
// loadUrl() is dropped for a matching URL and reported; every other URL and
// every other caller still goes through untouched.
function blockedUrl(u) {
    if (u === null || u === undefined) return null;
    var lu = String(u).toLowerCase();
    var words = CONF.spoof.webviewBlock.words;
    for (var i = 0; i < words.length; i++) {
        if (lu.indexOf(words[i]) >= 0) return words[i];
    }
    return null;
}

function hookWebview(WV) {
    var n = 0;
    try {
        var loadUrl = WV.loadUrl.overload("java.lang.String");
        var origUrl = loadUrl;
        loadUrl.implementation = function (u) {
            try {
                var w = blockedUrl(u);
                if (w !== null) {
                    spoofNote("spoof-webview-block", "wv:loadUrl",
                        { url: esc(clip(String(u), 140)), why: w }, 12);
                    return;
                }
            } catch (e1) { /* forward */ }
            return origUrl.call(this, u);
        };
        n += 1;
    } catch (e2) {
        spoofSkip("WebView.loadUrl(String)", e2);
    }
    try {
        var ldb = WV.loadDataWithBaseURL.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "java.lang.String", "java.lang.String");
        var origLdb = ldb;
        ldb.implementation = function (base, data, mime, enc, hist) {
            try {
                var w = blockedUrl(base);
                if (w !== null) {
                    spoofNote("spoof-webview-block", "wv:loadData",
                        { url: esc(clip(String(base), 140)), why: w }, 12);
                    return;
                }
            } catch (e3) { /* forward */ }
            return origLdb.call(this, base, data, mime, enc, hist);
        };
        n += 1;
    } catch (e4) {
        spoofSkip("WebView.loadDataWithBaseURL", e4);
    }
    return n;
}

/* ------------------------------------------------------------------ *
 * deep disguise: identity, sensors, power/network, cpu/mem   (task 4)
 * ------------------------------------------------------------------ *
 * WHY THIS IS SEPARATE FROM THE BLOCK ABOVE
 *   Everything above repairs artefacts a *Java* caller can see.  A risk model
 *   also samples the surfaces below, and each of them still reported the
 *   emulator on this guest (all values measured before any hook existed --
 *   capturePre() records them again on every run):
 *
 *     Settings.Secure "android_id"      3a2df761b285af09
 *     Build.getSerial()                 0011ff13
 *     sensor list                       8 hw sensors, every one capped at 5 Hz
 *     battery                           AC+USB powered, level 100, status 2
 *     Runtime.availableProcessors()     4
 *     ActivityManager totalMem          4 GiB        (a Mi 9 has 6)
 *
 *   Half a disguise is worse than none: a model that cross-checks surfaces sees
 *   "MI 9" next to "0011ff13" and scores it higher than an honest emulator.  So
 *   every value here agrees with CONF.spoof.buildFields, and spoofVerify()
 *   prints the pre-hook truth next to the post-hook answer.
 *
 * WHAT IS DELIBERATELY NOT DONE
 *   * Sensor LIST fabrication.  android.hardware.Sensor has no public
 *     constructor, so a sensor that is absent cannot be synthesised -- a
 *     "return a list with an accelerometer" hook is only implementable on a
 *     guest that already has one.  This one has 8, so the useful repair is the
 *     per-sensor identity + rate below.
 *   * Build.SUPPORTED_ABIS / os.arch / abilist / sysfs / cpuinfo: untouched.
 *     x86_64 code is genuinely executing; claiming arm64 breaks the native
 *     loader instead of hiding anything.
 */

var DEEP = { pre: {} };

function deepCatch(where, e) {
    spoofSkip(where, e);
}

// The app's own context: the only way to reach the platform services the way
// the target does (and the way to read values that need the app's permissions).
function appContext() {
    try {
        var app = Java.use("android.app.ActivityThread").currentApplication();
        if (app !== null && app !== undefined) return app.getApplicationContext();
    } catch (e) { /* no application yet */ }
    return null;
}

function sysService(ctx, name) {
    try {
        if (ctx !== null) return ctx.getSystemService(name);
    } catch (e) { /* service missing */ }
    return null;
}

// Context.getSystemService() is declared to return java.lang.Object, and the Java
// bridge resolves methods from the DECLARED type -- so an uncast service object
// answers every method with "not a function".  (Measured: the wrapper only had
// Object's members, while Java.cast() to the real class worked.)  Every service
// therefore goes through here.
function svc(ctx, name, className) {
    var o = sysService(ctx, name);
    if (o === null || o === undefined) return null;
    try {
        return Java.cast(o, Java.use(className));
    } catch (e) {
        deepCatch("cast:" + className, e);
        return null;
    }
}

// Records the truth once, before the matching hook exists.  Anything that
// throws (missing permission, missing API on this API level) is recorded as "?"
// rather than aborting the capture -- an unreadable surface is evidence too.
function preRead(key, fn) {
    try {
        DEEP.pre[key] = fn();
    } catch (e) {
        DEEP.pre[key] = "?" + clip(String(e), 60);
    }
}

function deepSerial() {
    return CONF.spoof.deep.serial || CONF.spoof.buildFields.SERIAL;
}

function capturePre() {
    var ctx = appContext();
    if (ctx === null) {
        // Spawn case: this script is loaded before device.resume(), so there is no
        // Application yet.  The hooks are in place before the first frame anyway,
        // so there is no "before" to record -- saying so beats a wall of "?".
        emit({ ev: "spoof-pre", skipped: "no application context yet (script loaded before resume)" });
        return;
    }
    preRead("androidId", function () {
        return String(Java.use("android.provider.Settings$Secure")
            .getString(ctx.getContentResolver(), "android_id"));
    });
    preRead("serial", function () {
        return String(Java.use("android.os.Build").getSerial());
    });
    preRead("buildSerial", function () {
        return String(Java.use("android.os.Build").SERIAL.value);
    });
    preRead("sim", function () {
        var tm = svc(ctx, "phone", "android.telephony.TelephonyManager");
        return {
            iccid: String(tm.getSimSerialNumber()),
            imsi: String(tm.getSubscriberId()),
            state: tm.getSimState(),
            op: String(tm.getSimOperator())
        };
    });
    preRead("sensors", function () {
        var sm = svc(ctx, "sensor", "android.hardware.SensorManager");
        var l = sm.getSensorList(-1);
        var out = [];
        for (var i = 0; i < l.size() && i < 12; i++) {
            // List.get() is declared to return java.lang.Object, so the element
            // wrapper has Object's methods only -- cast it to Sensor first.
            var s = Java.cast(l.get(i), Java.use("android.hardware.Sensor"));
            out.push(String(s.getName()) + "|" + String(s.getVendor()) + "|t" +
                s.getType() + "|min" + s.getMinDelay());
        }
        return { n: l.size(), sample: out };
    });
    preRead("battery", function () {
        var F = Java.use("android.content.IntentFilter");
        var it = ctx.registerReceiver(null, F.$new("android.intent.action.BATTERY_CHANGED"));
        var bm = svc(ctx, "batterymanager", "android.os.BatteryManager");
        return {
            level: it.getIntExtra("level", -1),
            status: it.getIntExtra("status", -1),
            plugged: it.getIntExtra("plugged", -1),
            voltage: it.getIntExtra("voltage", -1),
            capacity: bm.getIntProperty(4)
        };
    });
    preRead("cores", function () {
        return Java.use("java.lang.Runtime").getRuntime().availableProcessors();
    });
    preRead("heap", function () {
        var D = Java.use("android.os.Debug");
        return { size: D.getNativeHeapSize(), allocated: D.getNativeHeapAllocatedSize() };
    });
    preRead("mem", function () {
        var mi = Java.use("android.app.ActivityManager$MemoryInfo").$new();
        svc(ctx, "activity", "android.app.ActivityManager").getMemoryInfo(mi);
        return { total: mi.totalMem.value, avail: mi.availMem.value };
    });
    preRead("wifi", function () {
        var wi = svc(ctx, "wifi", "android.net.wifi.WifiManager").getConnectionInfo();
        return { mac: String(wi.getMacAddress()), ssid: String(wi.getSSID()) };
    });
    emit({ ev: "spoof-pre", note: "values the guest reported before any hook", pre: DEEP.pre });
}

/* ---------------- 4.1 identity: android_id / serial / SIM ---------------- */

// Settings.Secure.getString(ContentResolver, String) is the only documented way
// to read android_id, and it has a (ContentResolver, String, String) sibling
// (the "default" form) -- both are hooked, and both answer only for that one
// key.  Every other key, and every other caller, goes through untouched.
function hookAndroidId() {
    var S;
    try {
        S = Java.use("android.provider.Settings$Secure");
    } catch (e) {
        deepCatch("Settings$Secure", e);
        return 0;
    }
    var n = 0;
    var ovs = S.getString.overloads;
    for (var i = 0; i < ovs.length; i++) {
        var ov = ovs[i];
        var types = [];
        try { types = ov.argumentTypes; } catch (e2) { continue; }
        if (types.length < 2) continue;
        if (types[0].className !== "android.content.ContentResolver") continue;
        if (types[1].className !== "java.lang.String") continue;
        try {
            (function (orig) {
                orig.implementation = function () {
                    var a = [];
                    for (var k = 0; k < arguments.length; k++) a.push(arguments[k]);
                    try {
                        if (String(a[1]) === "android_id") {
                            spoofNote("spoof-android-id", "settings:android_id",
                                { val: CONF.spoof.deep.androidId }, 3);
                            return CONF.spoof.deep.androidId;
                        }
                    } catch (e3) { /* forward below */ }
                    return callOv(orig, this, a);
                };
            })(ov);
            n += 1;
        } catch (e4) {
            deepCatch("Settings.Secure.getString" + sigOf(ov), e4);
        }
    }
    return n;
}

// Build.getSerial() is what Settings.Secure.ANDROID_ID's sibling surface looks
// at on API 26+, and it returns ro.serialno -- 0011ff13 here.  It is answered
// with the same value as Build.SERIAL (written by hookBuildFields), because two
// different serials from one device is a contradiction, not a disguise.
function hookBuildSerial() {
    var B;
    try {
        B = Java.use("android.os.Build");
    } catch (e) {
        deepCatch("android.os.Build", e);
        return 0;
    }
    var n = 0;
    try {
        var ov = B.getSerial.overload();
        var orig = ov;
        ov.implementation = function () {
            try {
                spoofNote("spoof-serial", "Build.getSerial", { val: deepSerial() }, 3);
                return deepSerial();
            } catch (e1) {
                return orig.call(this);
            }
        };
        n += 1;
    } catch (e2) {
        deepCatch("Build.getSerial", e2);
    }
    return n;
}

// The SIM is answered as a whole: an ICCID next to SIM_STATE_ABSENT (which is
// what an emulator reports) is more suspicious than no ICCID at all.  String and
// int getters share the helper already used for getDeviceId/getImei, so the
// "no-argument or slot 0 only" rule stays in one place.
function hookSimDeep(TM) {
    var d = CONF.spoof.deep;
    var n = 0;
    n += hookTelephonyGetter(TM, "getSimSerialNumber", d.iccId);
    n += hookTelephonyGetter(TM, "getSubscriberId", d.imsi);
    n += hookTelephonyGetter(TM, "getSimOperator", d.simOperator);
    n += hookTelephonyGetter(TM, "getSimOperatorName", d.simOperatorName);
    n += hookTelephonyGetter(TM, "getNetworkOperator", d.simOperator);
    n += hookTelephonyGetter(TM, "getNetworkOperatorName", d.simOperatorName);
    n += hookTelephonyGetter(TM, "getSimCountryIso", d.countryIso);
    n += hookTelephonyGetter(TM, "getNetworkCountryIso", d.countryIso);
    n += hookTelephonyGetter(TM, "getSimState", d.simState);      // int return
    n += hookTelephonyGetter(TM, "getPhoneType", d.phoneType);    // int return
    return n;
}

/* ------------- 4.2 sensors: identity fields + rate cap repair ------------- */

// Getter -> field name in CONF.spoof.deep.sensorTypes.  getMinDelay is listed
// too, but it has no per-type value: it is repaired by the floor rule below,
// because 5 Hz is the emulator's cap on *every* sensor while on-change sensors
// (proximity, light) legitimately report 0.
var SENSOR_GETTERS = [
    ["getName", "name"],
    ["getVendor", "vendor"],
    ["getVersion", "version"],
    // Android's public API is getMaximumRange(); getMaxRange() does not exist on
    // API 28 (measured: NoSuchMethodException), so the table key stays maxRange
    // while the hook targets the method that is really there.
    ["getMaximumRange", "maxRange"],
    ["getResolution", "resolution"],
    ["getPower", "power"],
    ["getMinDelay", "minDelay"]
];

// The original is always called first and its value is what is returned unless
// a rule fires: an unanswered sensor therefore keeps the platform's answer, so a
// wrong guess can never make the app fail a cast.
function hookSensorFields() {
    var Sensor;
    try {
        Sensor = Java.use("android.hardware.Sensor");
    } catch (e) {
        deepCatch("android.hardware.Sensor", e);
        return 0;
    }
    var n = 0;
    var ok = [], miss = [];
    for (var g = 0; g < SENSOR_GETTERS.length; g++) {
        var getter = SENSOR_GETTERS[g][0];
        var field = SENSOR_GETTERS[g][1];
        var fn;
        try { fn = Sensor[getter]; } catch (e1) { deepCatch("Sensor." + getter, e1); miss.push(getter); continue; }
        if (fn === undefined || fn === null) { miss.push(getter); continue; }
        var hookedHere = 0;
        var ovs = fn.overloads;
        for (var i = 0; i < ovs.length; i++) {
            var ov = ovs[i];
            var types = [];
            try { types = ov.argumentTypes; } catch (e2) { continue; }
            if (types.length !== 0) continue;
            try {
                (function (orig, tag, f) {
                    orig.implementation = function () {
                        var real = orig.call(this);
                        try {
                            var t = this.getType();
                            var row = CONF.spoof.deep.sensorTypes[t];
                            if (row && row[f] !== undefined && row[f] !== null) {
                                spoofNote("spoof-sensor", "sensor:" + tag + ":" + t,
                                    { type: t, val: row[f] }, 1);
                                return row[f];
                            }
                            if (f === "minDelay" &&
                                real >= CONF.spoof.deep.sensorMinDelayFloor) {
                                spoofNote("spoof-sensor", "sensor:minDelay:" + t,
                                    { type: t, was: real, val: CONF.spoof.deep.sensorMinDelay }, 1);
                                return CONF.spoof.deep.sensorMinDelay;
                            }
                        } catch (e3) { /* forward below */ }
                        return real;
                    };
                })(ov, getter, field);
                n += 1;
                hookedHere += 1;
            } catch (e4) {
                deepCatch("Sensor." + getter, e4);
            }
        }
        if (hookedHere > 0) ok.push(getter); else miss.push(getter);
    }
    return { n: n, ok: ok, miss: miss };
}

// SensorManager.getSensorList() is abstract, so hooking it intercepts nothing
// (the call site dispatches on the concrete class).  SystemSensorManager is that
// class.  Its value is NOT rewritten -- see the section comment about Sensor
// having no public constructor -- it is logged, so the evidence says how many
// sensors the guest really reports.
function hookSensorList() {
    var SM;
    try {
        SM = Java.use("android.hardware.SystemSensorManager");
    } catch (e) {
        deepCatch("SystemSensorManager", e);
        return 0;
    }
    try {
        var ov = SM.getSensorList.overload("int");
        var orig = ov;
        ov.implementation = function (t) {
            var l = orig.call(this, t);
            try {
                if (l !== null) {
                    spoofNote("spoof-sensor-list", "list:" + t,
                        { type: t, n: l.size() }, 2);
                }
            } catch (e1) { /* forward below */ }
            return l;
        };
        return 1;
    } catch (e2) {
        deepCatch("SystemSensorManager.getSensorList", e2);
        return 0;
    }
}

/* ------------------ 4.3 battery / network identity ------------------ */

// Two surfaces read the same pack: BatteryManager.get*Property() and the sticky
// ACTION_BATTERY_CHANGED intent.  Both are answered, because answering only one
// leaves the other reporting "AC powered, 100%" next to "87%, discharging".
function hookBattery() {
    var d = CONF.spoof.deep;
    var n = 0;
    var BM = null;
    try {
        BM = Java.use("android.os.BatteryManager");
    } catch (e1) {
        deepCatch("android.os.BatteryManager", e1);
    }
    if (BM !== null) {
        var props = [["getIntProperty", d.batteryProps], ["getLongProperty", d.batteryLongProps]];
        for (var i = 0; i < props.length; i++) {
            var name = props[i][0];
            var table = props[i][1];
            try {
                var ov = BM[name].overload("int");
                (function (orig, tbl, tag) {
                    orig.implementation = function (id) {
                        var real = orig.call(this, id);
                        try {
                            var v = tbl[id];
                            if (v !== undefined && v !== null) {
                                spoofNote("spoof-battery", tag + ":" + id,
                                    { id: id, val: v }, 2);
                                return v;
                            }
                        } catch (e2) { /* forward below */ }
                        return real;
                    };
                })(ov, table, name);
                n += 1;
            } catch (e3) {
                deepCatch("BatteryManager." + name, e3);
            }
        }
    }
    try {
        var I = Java.use("android.content.Intent");
        var ove = I.getIntExtra.overload("java.lang.String", "int");
        var origE = ove;
        ove.implementation = function (k, def) {
            var real = origE.call(this, k, def);
            try {
                // Only the battery intent is answered: every other Intent pays
                // one getAction() and nothing else.
                if (String(this.getAction()) === "android.intent.action.BATTERY_CHANGED") {
                    var v = d.batteryExtras[String(k)];
                    if (v !== undefined && v !== null) return v;
                }
            } catch (e4) { /* forward below */ }
            return real;
        };
        n += 1;
    } catch (e5) {
        deepCatch("Intent.getIntExtra", e5);
    }
    return n;
}

// "3c:bd:3e:5f:1a:72" -> signed Java bytes.
function macBytes(s) {
    var parts = String(s).split(":");
    var out = [];
    for (var i = 0; i < parts.length; i++) {
        var b = parseInt(parts[i], 16);
        if (isNaN(b)) b = 0;
        out.push(b > 127 ? b - 256 : b);
    }
    return out;
}

// WifiInfo.getMacAddress() already answers 02:00:00:00:00:00 on Android 6+ for
// every app, so this hook only guarantees it on a guest that might leak the
// hardware MAC.  NetworkInterface is the surface that *does* show the real MAC:
// measured here it equals the AP's BSSID, which no handset can produce.
function hookWifi() {
    var d = CONF.spoof.deep;
    var n = 0;
    try {
        var WI = Java.use("android.net.wifi.WifiInfo");
        var ov = WI.getMacAddress.overload();
        var orig = ov;
        ov.implementation = function () {
            var real = orig.call(this);
            try {
                spoofNote("spoof-wifi", "WifiInfo.getMacAddress", { val: d.wifiMac }, 2);
                return d.wifiMac;
            } catch (e1) { return real; }
        };
        n += 1;
    } catch (e2) {
        deepCatch("WifiInfo.getMacAddress", e2);
    }
    try {
        var NI = Java.use("java.net.NetworkInterface");
        var ovn = NI.getHardwareAddress.overload();
        var orign = ovn;
        ovn.implementation = function () {
            var real = orign.call(this);
            try {
                if (String(this.getName()) === d.wifiIface) {
                    spoofNote("spoof-wifi", "NetworkInterface:" + d.wifiIface,
                        { val: d.wifiIfaceMac }, 2);
                    return Java.array("byte", macBytes(d.wifiIfaceMac));
                }
            } catch (e3) { /* forward below */ }
            return real;
        };
        n += 1;
    } catch (e4) {
        deepCatch("NetworkInterface.getHardwareAddress", e4);
    }
    return n;
}

/* -------------------- 4.4 cpu / memory size -------------------- */

function hookHardware() {
    var d = CONF.spoof.deep;
    var n = 0;
    try {
        var R = Java.use("java.lang.Runtime");
        var ov = R.availableProcessors.overload();
        var orig = ov;
        ov.implementation = function () {
            var real = orig.call(this);
            try {
                spoofNote("spoof-hw", "availableProcessors", { val: d.cores }, 2);
                return d.cores;
            } catch (e1) { return real; }
        };
        n += 1;
    } catch (e2) {
        deepCatch("Runtime.availableProcessors", e2);
    }

    // android.os.Debug is static and no-argument for all three sizes.  The values
    // satisfy free = size - allocated, which is the only relation a model can
    // check about them without another syscall.
    var dbg = [["getNativeHeapSize", d.nativeHeapSize],
               ["getNativeHeapAllocatedSize", d.nativeHeapAllocated],
               ["getNativeHeapFreeSize", d.nativeHeapFree]];
    var D = null;
    try {
        D = Java.use("android.os.Debug");
    } catch (e3) {
        deepCatch("android.os.Debug", e3);
    }
    for (var i = 0; D !== null && i < dbg.length; i++) {
        try {
            var ovi = D[dbg[i][0]].overload();
            (function (orig, val, tag) {
                orig.implementation = function () {
                    var real = orig.call(this);
                    try {
                        spoofNote("spoof-hw", tag, { val: val }, 1);
                        return val;
                    } catch (e4) { return real; }
                };
            })(ovi, dbg[i][1], dbg[i][0]);
            n += 1;
        } catch (e5) {
            deepCatch("Debug." + dbg[i][0], e5);
        }
    }

    // totalMem is a field of the object the caller passes in, so the original is
    // called first and only the field is rewritten -- no object is fabricated.
    try {
        var AM = Java.use("android.app.ActivityManager");
        var ovm = AM.getMemoryInfo.overload("android.app.ActivityManager$MemoryInfo");
        var origm = ovm;
        ovm.implementation = function (mi) {
            var r = origm.call(this, mi);
            try {
                if (mi !== null && mi !== undefined) {
                    mi.totalMem.value = d.totalMem;
                    spoofNote("spoof-hw", "MemoryInfo.totalMem", { val: d.totalMem }, 2);
                }
            } catch (e6) { /* forward below */ }
            return r;
        };
        n += 1;
    } catch (e7) {
        deepCatch("ActivityManager.getMemoryInfo", e7);
    }
    return n;
}

// Installs task 4.  capturePre() runs first and through the *unhooked* surface,
// so the JSONL carries the real values next to the disguise.
function installDeep() {
    if (!CONF.spoof.deep || !CONF.spoof.deep.enabled) {
        emit({ ev: "spoof-deep", enabled: false });
        return;
    }
    var counts = {};

    counts["androidId"] = hookAndroidId();
    counts["serial"] = hookBuildSerial();
    try {
        counts["sim"] = hookSimDeep(Java.use("android.telephony.TelephonyManager"));
    } catch (e1) {
        deepCatch("TelephonyManager(sim)", e1);
    }
    counts["sensors"] = hookSensorFields();
    counts["sensorList"] = hookSensorList();
    counts["battery"] = hookBattery();
    counts["wifi"] = hookWifi();
    counts["hw"] = hookHardware();

    emit({ ev: "spoof-deep", enabled: true, counts: counts });
}

/* ------------------------------------------------------------------ *
 * native layer: maps / thread names / properties        (task 5)
 * ------------------------------------------------------------------ *
 * WHY LIBC AND NOT `Process.findModuleByName`
 *   The task list puts "hook Process.findModuleByName" first because it is the
 *   simplest thing to write.  It is also the one thing that cannot work: that
 *   function lives in the *agent's* JS runtime.  SecurityGuard never executes
 *   GumJS -- it is native ARM64 code in the target, and it reads
 *   /proc/self/maps through libc, exactly like every other process.  Hooking a
 *   GumJS API therefore hides nothing from it.  (It is still installed, see
 *   hookFindModule, so our own diagnostics cannot report a frida image we are
 *   pretending is not there -- but that is bookkeeping, not concealment.)
 *
 *   What the target CAN observe is the kernel's answer, so the interception has
 *   to sit on the path the kernel is reached through:
 *
 *     open()/open64()/openat()/openat64()/fopen()/fopen64()
 *         the only way to read /proc/self/maps and /proc/self/task/<tid>/comm
 *     __system_property_get()
 *         what a .so reads when it asks for ro.debuggable / ro.kernel.qemu
 *     dl_iterate_phdr()
 *         enumeration of loaded images straight from the link_map
 *
 * HOW THE FILTERED ANSWER IS DELIVERED
 *   A maps file cannot be patched in place ("delete one line" is not a write),
 *   and a fd cannot be swapped for a buffer.  So the intercepted call is turned
 *   into: read the real file -> drop the lines -> write the result into an
 *   anonymous memfd -> hand that fd (or a FILE* on it) to the caller, who sees a
 *   normal, seekable, fstat-able file of the right size.  The caller's own
 *   flags/mode/lseek behaviour is untouched because the fd IS a file.
 *
 *   Only the *content* changes: every kept line is byte-identical to what the
 *   kernel produced, so addresses, sizes and permissions still line up with
 *   whatever the process does next.
 *
 * WHAT THIS DOES NOT COVER
 *   * A read that never reaches libc: raw `syscall(SYS_openat)`, `io_uring`, or
 *     a child process (`cat /proc/<ourpid>/maps`).  The last one is real but
 *     needs exec, which this agent does not instrument.
 *   * Frida's own File API.  Measured: File.readAllText("/proc/self/maps") does
 *     NOT pass through libc's open/fopen here, so it still shows the agent's
 *     lines (nativeVerify reports this as mapsAfterJs).  That is not a hole for
 *     the target -- a guest has no GumJS runtime -- but it does mean this
 *     agent's own maps probe cannot be used to verify the filter; the java.nio
 *     read is the honest check, because libcore's openat is what the app and
 *     SecurityGuard's engine both end up in.
 *   * Newly loaded images: Frida's own dlopen bookkeeping is unaffected because
 *     we filter what the app *reads*, not what the linker knows.
 */

var SYS_MEMFD = (Process.arch === "x64") ? 319
    : (Process.arch === "arm64") ? 279
    : 356;

var NATIVE = {
    on: false,
    busy: 0,                 // re-entrancy depth: >0 means "call the original"
    hits: {},                // counters, also the log rate limiter
    words: [],               // lowercased dropWords, built once
    fn: {},                  // resolved libc entry points (NativeFunction)
    memfdName: "jit-cache",
    lastDropped: 0,
    mapsBefore: -1,
    mapsAfterJs: -1,
    mapsAfterJava: -1
};

function nativeNote(ev, key, extra, cap) {
    spoofNote(ev, "native:" + key, extra, cap);
}

function nativeCatch(where, e) {
    emit({ ev: "native-skip", where: where, err: clip(String(e), 160) });
}

function libcSym(name) {
    // Frida 17 dropped the null-module form of getExportByName()/findExportByName()
    // and added getGlobalExportByName()/findGlobalExportByName().  Both generations
    // are tried here, because this agent also has to load on a Frida 16 host.
    try {
        if (typeof Module.getGlobalExportByName === "function") {
            return Module.getGlobalExportByName(name);
        }
    } catch (e) { /* try the next spelling */ }
    try {
        if (typeof Module.findGlobalExportByName === "function") {
            return Module.findGlobalExportByName(name);
        }
    } catch (e2) { }
    try {
        if (typeof Module.getExportByName === "function") {
            return Module.getExportByName(null, name);
        }
    } catch (e3) { /* older Frida only */ }
    try {
        if (typeof Module.findExportByName === "function") {
            return Module.findExportByName(null, name);
        }
    } catch (e4) { }
    return null;
}

// Frida counts UTF-16 units; maps lines are ASCII but a path need not be, and
// the byte count is what write() wants.
function utf8Len(s) {
    var n = 0;
    for (var i = 0; i < s.length; i++) {
        var c = s.charCodeAt(i);
        if (c < 0x80) n += 1;
        else if (c < 0x800) n += 2;
        else if (c >= 0xd800 && c <= 0xdbff) { n += 4; i += 1; }
        else n += 3;
    }
    return n;
}

function readLinkPath(p) {
    try {
        var buf = Memory.alloc(4096);
        var n = Number(NATIVE.fn.readlink(Memory.allocUtf8String(p), buf, 4095));
        if (n <= 0) return null;
        return buf.readUtf8String(n);
    } catch (e) {
        return null;
    }
}

// Puts `body` in an anonymous memfd and returns its read-only-from-here fd.
// -1 means "no filtered answer available"; callers then pass the real fd
// through untouched, because a missing disguise is better than a broken read.
function memfdFor(body) {
    var fd = -1;
    try {
        var namePtr = Memory.allocUtf8String(NATIVE.memfdName);
        fd = Number(NATIVE.fn.syscall(SYS_MEMFD, namePtr, 0));
    } catch (e) {
        nativeCatch("memfd_create", e);
        return -1;
    }
    if (fd < 0) {
        nativeNote("native-memfd-fail", "syscall", { fd: fd }, 2);
        return -1;
    }
    try {
        var len = utf8Len(body);
        var buf = Memory.alloc(len + 1);
        buf.writeUtf8String(body);
        var off = 0;
        while (off < len) {
            var w = Number(NATIVE.fn.write(fd, buf.add(off), len - off));
            if (w <= 0) break;
            off += w;
        }
        NATIVE.fn.lseek(fd, 0, 0);          // SEEK_SET
        if (off !== len) {
            NATIVE.fn.close(fd);
            return -1;
        }
    } catch (e2) {
        nativeCatch("memfd_write", e2);
        NATIVE.fn.close(fd);
        return -1;
    }
    return fd;
}

// Renders the filtered answer for `kind` from the real file.  Runs with busy>0 so
// the read itself (File.readAllText -> libc open) is passed straight through.
function renderFiltered(kind, path) {
    var text;
    NATIVE.busy += 1;
    try {
        text = String(File.readAllText(path));
    } catch (e) {
        NATIVE.busy -= 1;
        nativeCatch("read:" + kind, e);
        return null;
    }
    NATIVE.busy -= 1;
    if (kind === "comm") return filterComm(text);
    return filterMaps(text);
}
// Which of the watched files is this, and under what absolute path can it be
// re-read?  Returns null for every other path -- the overwhelming majority.
// openat() may arrive with a relative path, in which case the dirfd is resolved
// through /proc/self/fd so that "self/maps" is recognised too.
function classifyPath(p, dirfd) {
    if (p === null || p === undefined) return null;
    var s = String(p);
    if (s.length === 0) return null;
    if (s.charAt(0) !== "/") {
        if (dirfd === null || dirfd === undefined || dirfd < 0) return null;
        var base = readLinkPath("/proc/self/fd/" + dirfd);
        if (base === null || base.charAt(0) !== "/") return null;
        s = base + (base.charAt(base.length - 1) === "/" ? "" : "/") + s;
    }
    if (s.indexOf("/proc/") !== 0) return null;
    // /proc/<pid>/... is the same file when <pid> is us; anything else belongs
    // to another process and is none of our business.
    var m = /^\/proc\/(\d+)\//.exec(s);
    if (m !== null) {
        if (Number(m[1]) !== Process.id) return null;
        s = "/proc/self/" + s.slice(m[0].length);
    }
    if (s.indexOf("/proc/self/") !== 0) return null;
    var rest = s.slice("/proc/self/".length);

    if (rest === "maps" || rest === "smaps") return { kind: "maps", path: s };
    var t = /^task\/\d+\/(maps|smaps|comm)$/.exec(rest);
    if (t !== null) {
        return { kind: (t[1] === "comm") ? "comm" : "maps", path: s };
    }
    return null;
}

// Drops whole lines.  Nothing is rewritten, so every kept line stays exactly what
// the kernel produced.
function filterMaps(text) {
    var words = NATIVE.words;
    var marker = "/memfd:" + NATIVE.memfdName;
    var anonRwx = CONF.spoof.native.dropAnonRwx;
    var lines = String(text).split("\n");
    var out = [];
    var dropped = 0;
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        if (line.length === 0) { out.push(line); continue; }
        var lower = line.toLowerCase();
        var hit = false;
        for (var w = 0; w < words.length; w++) {
            if (lower.indexOf(words[w]) >= 0) { hit = true; break; }
        }
        if (!hit && lower.indexOf(marker) >= 0) hit = true;
        if (!hit && anonRwx && line.indexOf(" rwx") >= 0 && line.indexOf("/") < 0) {
            hit = true;
        }
        if (hit) { dropped += 1; continue; }
        out.push(line);
    }
    NATIVE.lastDropped = dropped;
    return out.join("\n");
}

// A thread name is the other free tell: /proc/self/task/<tid>/comm needs no
// permission, and "gum-js-loop" is unambiguous.
function filterComm(text) {
    var v = String(text).replace(/[\r\n]+$/, "");
    var lower = v.toLowerCase();
    var names = CONF.spoof.native.threadNames;
    for (var i = 0; i < names.length; i++) {
        if (lower.indexOf(names[i]) >= 0) {
            NATIVE.lastDropped = 1;
            return CONF.spoof.native.threadNameReplace + "\n";
        }
    }
    NATIVE.lastDropped = 0;
    return text;
}

// How many lines of `text` still carry a dropped word.  Used only to prove the
// filter, so it counts the configured words verbatim (libnb included).
function countMapsHits(text) {
    var words = NATIVE.words;
    var lines = String(text).split("\n");
    var n = 0;
    for (var i = 0; i < lines.length; i++) {
        var lower = lines[i].toLowerCase();
        for (var w = 0; w < words.length; w++) {
            if (lower.indexOf(words[w]) >= 0) { n += 1; break; }
        }
    }
    return n;
}

/* ------------ interception: open()/openat()/fopen() ------------- */

// Interceptor.attach is used instead of Interceptor.replace on purpose: attach
// always runs the real call and hands us `retval` to swap afterwards, so a bug
// here can only lose the disguise, never break an open() the app depends on.
function installOpenHook(name, addr, isAt) {
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.hit = null;
                try {
                    if (NATIVE.busy > 0) return;
                    var pathPtr = isAt ? args[1] : args[0];
                    if (pathPtr.isNull()) return;
                    // Cheap prefilter, because this runs on EVERY open(): relative
                    // paths and non-/proc paths cost one byte read and six bytes
                    // compared, and never allocate a JS string.
                    if (pathPtr.readU8() !== 0x2f) return;
                    if (pathPtr.readUtf8String(6) !== "/proc/") return;
                    this.hit = classifyPath(pathPtr.readUtf8String(),
                        isAt ? args[0].toInt32() : null);
                } catch (e) {
                    this.hit = null;
                }
            },
            onLeave: function (retval) {
                try {
                    if (!this.hit || NATIVE.busy > 0) return;
                    var fd = retval.toInt32();
                    if (fd < 0) return;                  // the real call failed
                    var body = renderFiltered(this.hit.kind, this.hit.path);
                    if (body === null) return;
                    var nfd = memfdFor(body);
                    if (nfd < 0) return;
                    NATIVE.fn.close(fd);
                    retval.replace(nfd);
                    nativeNote("native-maps-filter", name + ":" + this.hit.kind,
                        { via: name, path: esc(clip(this.hit.path, 90)),
                          dropped: NATIVE.lastDropped }, 6);
                } catch (e) {
                    nativeCatch("open:" + name, e);
                }
            }
        });
        return 1;
    } catch (e2) {
        nativeCatch("attach:" + name, e2);
        return 0;
    }
}

function installOpenFamily() {
    var names = ["open", "open64", "openat", "openat64"];
    var seen = {};
    var n = 0;
    for (var i = 0; i < names.length; i++) {
        var name = names[i];
        var addr = libcSym(name);
        if (addr === null) continue;
        // On 64-bit bionic open() and open64() are the same function; attaching
        // twice would run the whole filter twice for one call.
        var key = addr.toString();
        if (seen[key]) continue;
        seen[key] = true;
        n += installOpenHook(name, addr, name.indexOf("openat") === 0);
    }
    return n;
}

// fopen() must be covered separately: it returns a FILE*, and code that parses
// maps with fgets()/fscanf() never touches the fd API again.  The filtered copy
// is opened through /proc/self/fd/<memfd> so the FILE* has a real path behind it.
function installFopenHook(name, addr) {
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.hit = null;
                try {
                    if (NATIVE.busy > 0) return;
                    var pathPtr = args[0];
                    if (pathPtr.isNull()) return;
                    if (pathPtr.readU8() !== 0x2f) return;
                    if (pathPtr.readUtf8String(6) !== "/proc/") return;
                    this.hit = classifyPath(pathPtr.readUtf8String(), null);
                    // A writable stream is not a read of the kernel's answer.
                    var mode = args[1].isNull() ? "r" : args[1].readUtf8String();
                    this.writable = (String(mode).indexOf("w") >= 0 ||
                                     String(mode).indexOf("+") >= 0);
                } catch (e) {
                    this.hit = null;
                }
            },
            onLeave: function (retval) {
                try {
                    if (!this.hit || this.writable || NATIVE.busy > 0) return;
                    if (retval.isNull()) return;
                    var body = renderFiltered(this.hit.kind, this.hit.path);
                    if (body === null) return;
                    var fd = memfdFor(body);
                    if (fd < 0) return;
                    var via = Memory.allocUtf8String("/proc/self/fd/" + fd);
                    var nfp = NATIVE.fn.fopen(via, Memory.allocUtf8String("r"));
                    if (nfp.isNull()) {                 // reopen failed: keep the real one
                        NATIVE.fn.close(fd);
                        return;
                    }
                    NATIVE.fn.close(fd);                // the FILE* holds its own reference
                    NATIVE.fn.fclose(retval);
                    retval.replace(nfp);
                    nativeNote("native-maps-filter", name + ":" + this.hit.kind,
                        { via: name, path: esc(clip(this.hit.path, 90)),
                          dropped: NATIVE.lastDropped }, 6);
                } catch (e) {
                    nativeCatch("fopen:" + name, e);
                }
            }
        });
        return 1;
    } catch (e2) {
        nativeCatch("attach:" + name, e2);
        return 0;
    }
}

function installFopenFamily() {
    var names = ["fopen", "fopen64"];
    var seen = {};
    var n = 0;
    for (var i = 0; i < names.length; i++) {
        var addr = libcSym(names[i]);
        if (addr === null) continue;
        var key = addr.toString();
        if (seen[key]) continue;
        seen[key] = true;
        n += installFopenHook(names[i], addr);
    }
    return n;
}

/* -------- interception: __system_property_get() / dl_iterate_phdr() -------- */

// SecurityGuard's engine is a .so: when it asks for ro.debuggable it calls this,
// and the Java SystemProperties hook above never sees it.  Answering here is what
// makes the native view agree with the Java view instead of contradicting it.
function installPropHook() {
    var addr = libcSym("__system_property_get");
    if (addr === null) return 0;
    var table = CONF.spoof.native.props;
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.key = null;
                try {
                    if (NATIVE.busy > 0) return;
                    if (args[0].isNull() || args[1].isNull()) return;
                    // Cheap prefilter: every key in the table starts with "ro."
                    // or "service.", and this runs for every property read in the
                    // process, so one byte decides before any string is built.
                    var b0 = args[0].readU8();
                    if (b0 !== 0x72 && b0 !== 0x73) return;
                    var k = args[0].readUtf8String();
                    if (k === null || table[k] === undefined) return;
                    this.key = k;
                    this.buf = args[1];
                } catch (e) {
                    this.key = null;
                }
            },
            onLeave: function (retval) {
                try {
                    if (this.key === null) return;
                    var v = table[this.key];
                    this.buf.writeUtf8String(v);
                    retval.replace(v.length);
                    nativeNote("native-prop", this.key,
                        { key: esc(clip(this.key, 60)), val: esc(clip(String(v), 60)) }, 4);
                } catch (e) {
                    nativeCatch("__system_property_get:" + this.key, e);
                }
            }
        });
        return 1;
    } catch (e2) {
        nativeCatch("attach:__system_property_get", e2);
        return 0;
    }
}

// dl_iterate_phdr() walks the linker's link_map, which is a second, independent
// list of loaded images.  The callback pointer is swapped for a trampoline for
// the duration of one walk, so images whose name matches are skipped without
// touching how the walk itself works.  The stack exists because a callback is
// allowed to call dl_iterate_phdr again.
var DL = { stack: [], tramp: null, fns: {}, n: 0 };

function dlImageName(info) {
    try {
        var p = info.add(Process.pointerSize).readPointer();   // dlpi_name
        if (p.isNull()) return null;
        return p.readUtf8String();
    } catch (e) {
        return null;
    }
}

// A bare NativePointer is not callable in Frida 17 ("TypeError: not a function"),
// so each distinct callback pointer gets one cached NativeFunction.  Without this
// the trampoline threw on every image and every walk silently saw none -- which
// is a functional break, not just a lost disguise.
function dlCallback(cbPtr) {
    var key = cbPtr.toString();
    var fn = DL.fns[key];
    if (fn === undefined) {
        fn = new NativeFunction(cbPtr, "int", ["pointer", "ulong", "pointer"]);
        if (DL.n < 32) {                 // bounded: a process has a few users
            DL.fns[key] = fn;
            DL.n += 1;
        }
    }
    return fn;
}

function fridaImage(name) {
    if (name === null || name === undefined) return false;
    var ln = String(name).toLowerCase();
    var w = NATIVE.words;
    for (var i = 0; i < w.length; i++) {
        if (ln.indexOf(w[i]) >= 0) return true;
    }
    return false;
}

function installDlIterateHook() {
    var addr = libcSym("dl_iterate_phdr");
    if (addr === null) return 0;
    if (DL.tramp === null) {
        DL.tramp = new NativeCallback(function (info, size, data) {
            var top = (DL.stack.length > 0) ? DL.stack[DL.stack.length - 1] : null;
            if (top === null || top.cb.isNull()) return 0;
            try {
                if (NATIVE.busy === 0 && fridaImage(dlImageName(info))) {
                    top.dropped += 1;
                    return 0;                 // skip this image, keep walking
                }
            } catch (e) { /* pass it through */ }
            return dlCallback(top.cb)(info, size, top.data);
        }, "int", ["pointer", "ulong", "pointer"]);
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.pushed = false;
                try {
                    if (NATIVE.busy > 0) return;
                    if (args[0].isNull()) return;
                    DL.stack.push({ cb: args[0], data: args[1], dropped: 0 });
                    args[0] = DL.tramp;
                    this.pushed = true;
                } catch (e) { /* leave the call alone */ }
            },
            onLeave: function () {
                try {
                    if (!this.pushed || DL.stack.length === 0) return;
                    var top = DL.stack.pop();
                    if (top.dropped > 0) {
                        nativeNote("native-dl-hide", "dl_iterate_phdr",
                            { dropped: top.dropped }, 4);
                    }
                } catch (e) { /* nothing to report */ }
            }
        });
        return 1;
    } catch (e2) {
        nativeCatch("attach:dl_iterate_phdr", e2);
        return 0;
    }
}

// Task 5 "plan A", installed for the reason given in the section header: it can
// only redirect our own JS, so it is a guard on our diagnostics, not a
// concealment technique.
function hookFindModule() {
    if (typeof Process.findModuleByName !== "function") return 0;
    var orig = Process.findModuleByName;
    try {
        Process.findModuleByName = function (name) {
            var m = orig.call(Process, name);
            try {
                if (m !== null && m !== undefined && fridaImage(String(name))) {
                    nativeNote("native-findmodule", String(name),
                        { name: esc(clip(String(name), 60)) }, 2);
                    return null;
                }
            } catch (e) { /* return what we found */ }
            return m;
        };
        return 1;
    } catch (e2) {
        nativeCatch("Process.findModuleByName", e2);
        return 0;
    }
}

// The app's own path to the same file: libcore -> openat, with no GumJS frame in
// between, which is what makes this a second opinion rather than a repeat.
function readMapsViaJava() {
    var P = Java.use("java.nio.file.Paths");
    var path = P.get("/proc/self/maps", Java.array("java.lang.String", []));
    var bytes = Java.use("java.nio.file.Files").readAllBytes(path);
    return String(Java.use("java.lang.String").$new(bytes, "UTF-8"));
}

// Direct read through the *native* property API.  Called before the prop hook is
// installed it records the truth; called after, it proves the answer changed on
// the surface a .so actually uses.
function readPropNative(key) {
    var addr = libcSym("__system_property_get");
    if (addr === null) return "?";
    try {
        var fn = new NativeFunction(addr, "int", ["pointer", "pointer"]);
        var buf = Memory.alloc(92);                // PROP_VALUE_MAX
        var n = fn(Memory.allocUtf8String(key), buf);
        if (n <= 0) return "";
        return buf.readUtf8String();
    } catch (e) {
        return "?" + clip(String(e), 40);
    }
}

var PROP_PROBES = ["ro.kernel.qemu", "ro.debuggable", "ro.serialno",
                   "ro.dalvik.vm.native.bridge"];

function installNative() {
    var c = CONF.spoof.native;
    if (!c || !c.enabled) {
        emit({ ev: "native-boot", enabled: false });
        return;
    }
    NATIVE.words = [];
    for (var i = 0; i < c.dropWords.length; i++) {
        NATIVE.words.push(String(c.dropWords[i]).toLowerCase());
    }
    NATIVE.memfdName = c.memfdName || "jit-cache";

    // Entry points the filter itself needs.  None of them is hooked, so a
    // NativeFunction here always reaches libc.
    var need = [["close", "int", ["int"]],
                ["write", "long", ["int", "pointer", "long"]],
                ["lseek", "long", ["int", "long", "int"]],
                ["syscall", "long", ["long", "pointer", "long"]],
                ["readlink", "long", ["pointer", "pointer", "long"]],
                ["fopen", "pointer", ["pointer", "pointer"]],
                ["fclose", "int", ["pointer"]]];
    var missing = [];
    for (var j = 0; j < need.length; j++) {
        var addr = libcSym(need[j][0]);
        if (addr === null) { missing.push(need[j][0]); continue; }
        try {
            NATIVE.fn[need[j][0]] = new NativeFunction(addr, need[j][1], need[j][2]);
        } catch (e0) {
            missing.push(need[j][0]);
        }
    }
    if (missing.length > 0) {
        // No memfd means no filtered answer can be delivered.  Saying so is
        // better than installing hooks that silently pass everything through.
        emit({ ev: "native-boot", enabled: false, missing: missing });
        return;
    }

    // Baselines, all taken before the first attach.
    try {
        NATIVE.mapsBefore = countMapsHits(String(File.readAllText("/proc/self/maps")));
    } catch (e1) {
        NATIVE.mapsBefore = -1;
    }
    var propBefore = {};
    for (var k = 0; k < PROP_PROBES.length; k++) {
        propBefore[PROP_PROBES[k]] = readPropNative(PROP_PROBES[k]);
    }

    var counts = {};
    counts["open"] = installOpenFamily();
    counts["fopen"] = installFopenFamily();
    counts["prop"] = installPropHook();
    counts["dl"] = c.hookDlIterate ? installDlIterateHook() : 0;
    counts["findModule"] = c.hookFindModule ? hookFindModule() : 0;

    NATIVE.on = true;
    emit({
        ev: "native-boot",
        enabled: true,
        counts: counts,
        mapsBefore: NATIVE.mapsBefore,
        propBefore: propBefore,
        words: NATIVE.words.length,
        props: countKeys(c.props),
        memfd: NATIVE.memfdName
    });
    setTimeout(nativeVerify, 2500);
}

// Proves both filters through the surfaces that matter: a maps read through JS,
// one through java.nio (libcore), and the native property API.
function nativeVerify() {
    var o = { ev: "native-verify" };
    o.mapsBefore = NATIVE.mapsBefore;
    try {
        o.mapsAfterJs = countMapsHits(String(File.readAllText("/proc/self/maps")));
    } catch (e1) {
        o.mapsAfterJs = "?" + clip(String(e1), 50);
    }
    try {
        o.mapsAfterJava = countMapsHits(readMapsViaJava());
    } catch (e2) {
        o.mapsAfterJava = "?" + clip(String(e2), 50);
    }
    var propAfter = {};
    for (var k = 0; k < PROP_PROBES.length; k++) {
        propAfter[PROP_PROBES[k]] = readPropNative(PROP_PROBES[k]);
    }
    o.propAfter = propAfter;
    o.hits = SPOOF.hits;
    emit(o);
}

// Reads task 4's answers back through the hooked surface, so the record shows what
// the app receives rather than that a hook was attempted.
function verifyDeep(o) {
    var ctx = appContext();
    try {
        o.dAndroidId = String(Java.use("android.provider.Settings$Secure")
            .getString(ctx.getContentResolver(), "android_id"));
    } catch (e1) { o.dAndroidId = "?"; }
    try {
        o.dSerial = String(Java.use("android.os.Build").getSerial());
    } catch (e2) { o.dSerial = "?"; }
    try {
        var tm = svc(ctx, "phone", "android.telephony.TelephonyManager");
        o.dIccid = String(tm.getSimSerialNumber());
        o.dImsi = String(tm.getSubscriberId());
        o.dSimState = tm.getSimState();
        o.dOperator = String(tm.getSimOperator());
    } catch (e3) { o.dIccid = "?"; }
    try {
        var sm = svc(ctx, "sensor", "android.hardware.SensorManager");
        var l = sm.getSensorList(-1);
        o.dSensors = l.size();
        if (l.size() > 0) {
            var s0 = Java.cast(l.get(0), Java.use("android.hardware.Sensor"));
            o.dSensor0 = String(s0.getName()) + "|" + String(s0.getVendor()) +
                "|min" + s0.getMinDelay() + "|max" + s0.getMaximumRange();
        }
    } catch (e4) { o.dSensors = "?" + clip(String(e4), 70); }
    try {
        var F = Java.use("android.content.IntentFilter");
        var it = ctx.registerReceiver(null, F.$new("android.intent.action.BATTERY_CHANGED"));
        o.dBattery = it.getIntExtra("level", -1) + "/" + it.getIntExtra("status", -1) +
            "/plugged" + it.getIntExtra("plugged", -1);
        o.dCapacity = svc(ctx, "batterymanager", "android.os.BatteryManager").getIntProperty(4);
    } catch (e5) { o.dBattery = "?"; }
    try {
        o.dCores = Java.use("java.lang.Runtime").getRuntime().availableProcessors();
    } catch (e6) { o.dCores = "?"; }
    try {
        o.dHeap = String(Java.use("android.os.Debug").getNativeHeapSize());
    } catch (e7) { o.dHeap = "?"; }
    try {
        var mi = Java.use("android.app.ActivityManager$MemoryInfo").$new();
        svc(ctx, "activity", "android.app.ActivityManager").getMemoryInfo(mi);
        o.dTotalMem = String(mi.totalMem.value);
    } catch (e8) { o.dTotalMem = "?"; }
    try {
        o.dWifiMac = String(svc(ctx, "wifi", "android.net.wifi.WifiManager")
            .getConnectionInfo().getMacAddress());
    } catch (e9) { o.dWifiMac = "?"; }
}

function installSpoof() {
    if (!CONF.spoof.enabled) {
        emit({ ev: "spoof-boot", enabled: false });
        return;
    }
    var counts = {};

    // Truth first: capturePre() must run before ANY hook exists, otherwise the
    // "before" record would show already-disguised values -- Build.SERIAL is the
    // obvious trap, since hookBuildFields runs a few lines below.
    try { capturePre(); } catch (e0) { deepCatch("capturePre", e0); }

    if (CONF.spoof.hideRoot || CONF.spoof.hideFrida) {
        try {
            var File = Java.use("java.io.File");
            if (CONF.spoof.hideRoot) {
                counts["file.exists"] = hookFilePredicate(File, "exists");
                counts["file.isFile"] = hookFilePredicate(File, "isFile");
            }
            if (CONF.spoof.hideFrida) {
                counts["file.list"] = hookFileListing(File);
            }
        } catch (e1) {
            spoofSkip("java.io.File", e1);
        }
    }

    if (CONF.spoof.props) {
        try {
            var SP = Java.use("android.os.SystemProperties");
            counts["props.get"] = hookPropGetters(SP);
            counts["props.scalar"] = hookPropScalars(SP);
        } catch (e2) {
            spoofSkip("android.os.SystemProperties", e2);
        }
    }

    if (CONF.spoof.build) {
        try {
            counts["build.fields"] = hookBuildFields(Java.use("android.os.Build"));
        } catch (e3) {
            spoofSkip("android.os.Build", e3);
        }
    }

    if (CONF.spoof.telephony) {
        var TM = null;
        try { TM = Java.use("android.telephony.TelephonyManager"); } catch (e4) {
            spoofSkip("android.telephony.TelephonyManager", e4);
        }
        if (TM !== null) {
            var t = 0;
            t += hookTelephonyGetter(TM, "getDeviceId", CONF.spoof.imei);
            t += hookTelephonyGetter(TM, "getImei", CONF.spoof.imei);
            t += hookTelephonyGetter(TM, "getMeid", CONF.spoof.meid);
            counts["telephony"] = t;
        }
    }

    if (CONF.spoof.webviewBlock && CONF.spoof.webviewBlock.enabled) {
        try {
            counts["webview"] = hookWebview(Java.use("android.webkit.WebView"));
        } catch (e5) {
            spoofSkip("android.webkit.WebView", e5);
        }
    }

    // Task 4 (Java surfaces) and task 5 (libc surfaces).  Deep runs first: it
    // reads its baselines through the unhooked surface, and the native layer's
    // prop table is asserted against the same values.
    try {
        installDeep();
    } catch (e6) {
        emit({ ev: "spoof-failed", where: "deep", err: clip(String(e6), 300) });
    }
    try {
        installNative();
    } catch (e7) {
        emit({ ev: "spoof-failed", where: "native", err: clip(String(e7), 300) });
    }

    emit({
        ev: "spoof-boot",
        enabled: true,
        counts: counts,
        rootWords: CONF.spoof.rootWords.length,
        props: countKeys(CONF.spoof.propMap),
        buildFields: countKeys(CONF.spoof.buildFields),
        webview: !!(CONF.spoof.webviewBlock && CONF.spoof.webviewBlock.enabled),
        deep: !!(CONF.spoof.deep && CONF.spoof.deep.enabled),
        native: !!(CONF.spoof.native && CONF.spoof.native.enabled)
    });

    // Read the disguise back through the *hooked* surface a little later: boot
    // still has the SG scan ahead of it, and the fields have to be in place
    // before the first fingerprint is collected.
    setTimeout(spoofVerify, 1500);
}

// Reads the disguise back THROUGH the hooked surface, so the record proves what
// the app will receive -- not merely that a write was attempted.
function spoofVerify() {
    if (appContext() === null && SPOOF.verifyTries < 4) {
        // Attach to an early process / spawn: retry instead of recording "?".
        SPOOF.verifyTries += 1;
        emit({ ev: "spoof-verify-retry", n: SPOOF.verifyTries });
        setTimeout(spoofVerify, 2000);
        return;
    }
    var o = { ev: "spoof-verify" };
    try {
        o.fingerprint = esc(String(Java.use("android.os.Build").FINGERPRINT.value));
    } catch (e1) {
        o.fingerprint = "?";
    }
    try {
        o.model = esc(String(Java.use("android.os.Build").MODEL.value));
    } catch (e2) {
        o.model = "?";
    }
    try {
        o.manufacturer = esc(String(Java.use("android.os.Build").MANUFACTURER.value));
    } catch (e3) {
        o.manufacturer = "?";
    }
    try {
        // get() is hooked, so this is exactly what the app would be told.
        o.debuggable = esc(String(Java.use("android.os.SystemProperties")
            .get("ro.debuggable")));
    } catch (e4) {
        o.debuggable = "?";
    }
    try {
        var F = Java.use("java.io.File");
        o.suExists = F.$new("/system/bin/su").exists();
        o.magiskExists = F.$new("/sbin/.magisk").exists();
        o.usrVisible = F.$new("/system/usr").exists();   // must stay untouched
    } catch (e5) {
        o.suExists = "?";
    }
    // Task 4's answers, read back through the hooks the app will hit.
    verifyDeep(o);
    o.hits = SPOOF.hits;
    emit(o);
}

/* ------------------------------------------------------------------ *
 * auth diagnostic (task 1): client-gated or server-denied?
 * ------------------------------------------------------------------ *
 * WHY THIS SECTION EXISTS
 *   The disguise removed the risk-engine wall and the feed stays up, but the
 *   search action still ends in "please log in".  Two very different causes
 *   produce that same screen:
 *
 *     client-gated   some UI/account class asks "am I logged in?", gets false,
 *                    and pushes the login page by itself.  No search call is
 *                    ever sent.
 *     server-denied  the search call IS sent, the server answers
 *                    FAIL_SYS_SESSION_EXPIRED / FAIL_SYS_TOKEN_EMPTY / 401,
 *                    and login is how the client renders that error.
 *
 *   Environment disguise cannot fix either one, and guessing between them is
 *   how a session gets wasted.  This section records both sides and prints one
 *   verdict, so the answer is evidence instead of intuition.
 *
 * WHAT IT RECORDS (every event name starts with "auth.")
 *   auth.classes   the real class names that look like account/login code.
 *                  The apk is obfuscated, so documentation is useless here;
 *                  the VM's loaded-class list is the only honest source.
 *   auth.state     every "am I logged in?" answer, plus the first frames of
 *                  the caller's Java stack -- that is *who* is asking.
 *   auth.mtop      api + ret code + HTTP status of each mtop response.
 *   auth.req       whether the outgoing mtop request carried a Cookie at all,
 *                  and whether it carried _m_h5_tk / _tb_token_.
 *   auth.dialog    Dialog.show() on a login-looking class.  The bypass
 *                  intercepts Activity starts only, so this is where a
 *                  dialog-style login sheet shows up.
 *   auth.verdict   one computed conclusion and the numbers behind it.
 *
 * READ-ONLY BY DEFAULT
 *   Nothing here changes a login decision unless CONF.diag.forceLogin is on,
 *   so a diagnostic run cannot alter what it measures.  forceLogin is task 3
 *   "plan B" and is a documented dead end: a faked local flag creates no
 *   Cookie, so every signed call is still rejected server-side.
 *
 * SAFETY
 *   Same rules as the rest of this file: every hook is wrapped, the original
 *   is always called (unless forceLogin is on), no return *type* ever changes,
 *   and every loop is bounded.  A wrong guess here costs log lines, never a
 *   broken login path.
 */

var AUTH = {
    seen: {},            // fullName -> true (inventory, dedupes rescans)
    classes: 0,
    targets: [],         // "class#method" pairs actually hooked
    stateHooks: 0,
    mtopHooks: 0,
    reqHooks: 0,
    dialogHooks: 0,
    events: 0,
    bools: 0,            // how many login-state answers were recorded
    lastBool: null,      // last boolean answer seen
    user: null,          // first non-empty id/nick the app read back
    stacks: 0,
    reqs: 0,             // mtop requests observed
    reqNoCookie: 0,      // ...of which carried no Cookie header
    reqSeen: {},         // api -> true, one row per api
    mtopRows: [],        // {api, ret, code, ok}, capped
    mtopSeen: {},        // api|ret|code -> true
    searches: 0,         // rows whose api looks like search
    deny: 0,             // rows with a session/token denial
    dialogs: 0,
    rec: false           // re-entrancy guard for the response reader
};

// Server verdicts that mean "this call was refused for lack of login".  The
// list is about the code *family* mtop uses, not one fixed string: the text
// after "::" is localised.
var AUTH_DENY_RE = /(FAIL_SYS_(SESSION|TOKEN|ILLEGAL|LOGIN|USER|SID)|SESSION_EXPIRED|TOKEN_EMPTY|ILLEGAL_ACCESS|NOT_LOGIN|NEED_LOGIN|USER_NOT_LOGIN|NO_LOGIN)/i;

// Api names that belong to the search path.  Used only to answer "did the
// client even ask the server?" -- an api list is never asserted to be
// complete, and every observed name is logged in full anyway.
var AUTH_SEARCH_RE = /(search|suggest|searchtips)/i;

// Bounded emit.  Unlike emit() itself this counts, so the cap can be reported
// in the verdict ("we stopped recording at 400" is a fact worth having).
function authNote(rec) {
    if (AUTH.events >= CONF.diag.maxEvents) return;
    AUTH.events += 1;
    rec.n = AUTH.events;
    emit(rec);
}

// Six frames of the caller's Java stack.  This allocates (a Throwable plus a
// full stack render) so it is only sampled CONF.diag.stackSamples times: the
// first calls are the ones that tell us which screen asks the question.
function authStack() {
    try {
        var T = Java.use("java.lang.Throwable");
        var L = Java.use("android.util.Log");
        var text = String(L.getStackTraceString(T.$new()));
        var lines = text.split("\n");
        var out = [];
        for (var i = 0; i < lines.length && out.length < 6; i++) {
            var t = lines[i].replace(/^\s+at\s+/, "").replace(/\s+$/, "");
            if (t.length === 0) continue;
            if (t.indexOf("java.lang.Throwable") >= 0) continue;
            if (t.indexOf("android.util.Log") >= 0) continue;
            if (t.indexOf("dalvik.system.VMStack") >= 0) continue;
            out.push(clip(t, 90));
        }
        return out;
    } catch (e) {
        return null;
    }
}

/* ---------------- inventory: what account/login code is loaded? ---------- */

// Names that belong to the *state* machinery rather than to a transport or a
// UI helper.  Used only to decide which names survive CONF.diag.maxClasses.
var AUTH_HOT_RE = /(login4android\.(login|session|api)|LoginController|LoginState|LoginContext|UserInfo|CookieBridge|AutoLogin|SessionManager)/;

function authScore(n) {
    var s = 0;
    if (AUTH_HOT_RE.test(n)) s += 4;
    if (n.indexOf("$") < 0) s += 2;                       // top-level beats inner
    if (/^(com\.taobao|com\.ali\.user)/.test(n)) s += 1;
    return s;
}

// Names only, no hooks yet.  Runs at boot and again on every rescan, because
// an obfuscated app loads the account module lazily -- right after the user
// presses something, which is exactly the moment we want to be watching.
function authClasses() {
    var all;
    try {
        all = Java.enumerateLoadedClassesSync();
    } catch (e) {
        emit({ ev: "auth-fail", where: "enumerate", err: clip(String(e), 200) });
        return 0;
    }
    var fresh = [];
    var cands = [];
    for (var i = 0; i < all.length; i++) {
        var n = all[i];
        if (!CONF.diag.pkgRe.test(n)) continue;
        if (!CONF.diag.classRe.test(n)) continue;
        if (AUTH.seen[n]) continue;
        cands.push(n);
    }
    // Most login-specific first.  Measured on a live attach: an unsorted slice
    // of 60 filled up with anet.channel.Session* classes and left
    // LoginController out -- the cap would then hide exactly what we came for.
    // Ordering by interest, then by class depth, makes the kept ones the useful
    // ones; a name that is skipped is simply picked up on the next rescan.
    cands.sort(function (a, b) {
        var sa = authScore(a), sb = authScore(b);
        if (sa !== sb) return sb - sa;
        if (a.length !== b.length) return a.length - b.length;
        return a < b ? -1 : (a > b ? 1 : 0);
    });
    for (var j = 0; j < cands.length; j++) {
        if (AUTH.classes + fresh.length >= CONF.diag.maxClasses) break;
        AUTH.seen[cands[j]] = true;
        fresh.push(esc(cands[j]));
    }
    if (fresh.length > 0) {
        AUTH.classes += fresh.length;
        emit({ ev: "auth.classes", fresh: fresh.length, total: AUTH.classes, list: fresh });
    }
    return fresh.length;
}

/* ---------------- the client's own answer: "am I logged in?" ------------- */

// One overload.  `isBool` picks which of the two value shapes is accepted;
// the signature check below is what keeps an unrelated method with a tempting
// name out of the hook set.
function installAuthState(ov, cn, m, isBool) {
    var orig = ov;
    ov.implementation = function () {
        var r = orig.call(this);
        try {
            AUTH.bools += 1;
            var val = isBool ? (r === true) : String(r === null ? "<null>" : r);
            if (isBool) {
                AUTH.lastBool = val;
            } else if (AUTH.user === null && val.length > 0 && val !== "<null>") {
                AUTH.user = clip(val, 40);
            }
            var rec = {
                ev: "auth.state",
                cls: esc(cn),
                m: esc(m),
                ret: isBool ? val : esc(clip(val, 60)),
                n: AUTH.bools
            };
            if (AUTH.stacks < CONF.diag.stackSamples) {
                AUTH.stacks += 1;
                rec.stack = authStack();
            }
            authNote(rec);
            // Task 3 plan B.  A boolean method is safe to force; the String
            // getters are left alone on purpose, because inventing an id makes
            // every downstream check fail in a *different* place.
            if (isBool && CONF.diag.forceLogin) return CONF.diag.loginFlag;
        } catch (e) { }
        return r;
    };
}

// All name candidates of one list on one class.  Returns how many overloads
// were hooked.  Names that this build does not declare simply do not resolve,
// which is why the candidate lists can be generous.
function hookAuthNames(K, cn, names, isBool) {
    var n = 0;
    for (var i = 0; i < names.length; i++) {
        var m = names[i];
        var ovs;
        try {
            ovs = K[m].overloads;
        } catch (e) {
            continue;
        }
        for (var j = 0; j < ovs.length; j++) {
            if (AUTH.stateHooks + n >= CONF.diag.maxHooks) return n;
            var ov = ovs[j];
            var rt, argc;
            try {
                rt = ov.returnType.className;
                argc = ov.argumentTypes.length;
            } catch (e2) {
                continue;
            }
            // Zero-argument only: a state getter that needs an argument is a
            // lookup ("is user X logged in"), not the app's own state.
            if (argc !== 0) continue;
            if (isBool && rt !== "boolean") continue;
            if (!isBool && rt !== "java.lang.String") continue;
            var key = "auth:" + cn + "#" + m;
            if (hookedKeys[key]) continue;
            hookedKeys[key] = true;
            try {
                installAuthState(ov, cn, m, isBool);
                n += 1;
                if (AUTH.targets.length < 40) {
                    AUTH.targets.push(esc(cn) + "#" + esc(m));
                }
            } catch (e3) {
                emit({ ev: "auth-fail", where: "hook", cls: esc(cn), m: esc(m), err: clip(String(e3), 160) });
            }
        }
    }
    return n;
}

function hookAuthState() {
    var names = [];
    for (var k in AUTH.seen) {
        if (Object.prototype.hasOwnProperty.call(AUTH.seen, k)) names.push(k);
    }
    var n = 0;
    for (var i = 0; i < names.length; i++) {
        if (AUTH.stateHooks + n >= CONF.diag.maxHooks) break;
        var K;
        try {
            K = Java.use(names[i]);
        } catch (e) {
            continue;
        }
        n += hookAuthNames(K, names[i], CONF.diag.boolMethods, true);
        n += hookAuthNames(K, names[i], CONF.diag.stringMethods, false);
    }
    if (n > 0) {
        AUTH.stateHooks += n;
        emit({
            ev: "auth.state-hooks",
            installed: n,
            total: AUTH.stateHooks,
            classes: names.length,
            targets: AUTH.targets.slice()      // what a run may actually observe
        });
    }
    return n;
}

/* ---------------- the server's answer: mtop response --------------------- */

// Read every field of one response once and record a deduped row.  Guarded by
// AUTH.rec because this is called from inside getRetCode() *and* from inside
// isApiSuccess(), and those two call each other below.
function authMtopRecord(self) {
    if (AUTH.rec) return;
    AUTH.rec = true;
    try {
        var api = "?", ret = "", retMsg = "", code = null, ok = null;
        try { api = String(self.getApi()); } catch (e) { }
        try { ret = String(self.getRetCode()); } catch (e2) { }
        try { retMsg = String(self.getRetMsg()); } catch (e3) { }
        try { code = String(self.getResponseCode()); } catch (e4) { }
        try { ok = String(self.isApiSuccess()); } catch (e5) { }

        var key = api + "|" + ret + "|" + code;
        if (AUTH.mtopSeen[key]) return;
        AUTH.mtopSeen[key] = true;

        AUTH.mtopRows.push({ api: api, ret: ret, code: code, ok: ok });
        if (AUTH.mtopRows.length > 80) AUTH.mtopRows.shift();
        if (AUTH_DENY_RE.test(ret)) AUTH.deny += 1;
        if (AUTH_SEARCH_RE.test(api)) AUTH.searches += 1;

        authNote({
            ev: "auth.mtop",
            api: esc(clip(api, 70)),
            ret: esc(clip(ret, 90)),
            msg: esc(clip(retMsg, 70)),
            http: code,
            ok: ok
        });
    } finally {
        AUTH.rec = false;
    }
}

// Only the entry points are hooked.  A getter that is *read* from inside a
// hook must not be hooked itself, or the read re-enters the hook and the guard
// above would drop the outer record -- we would then log the inner call only.
function hookAuthMtopName(K, cn, m) {
    var ovs;
    try {
        ovs = K[m].overloads;
    } catch (e) {
        return 0;
    }
    var n = 0;
    for (var i = 0; i < ovs.length; i++) {
        var ov = ovs[i];
        try {
            if (ov.argumentTypes.length !== 0) continue;
        } catch (e2) {
            continue;
        }
        var key = "authm:" + cn + "#" + m + "/" + i;
        if (hookedKeys[key]) continue;
        hookedKeys[key] = true;
        var orig = ov;
        ov.implementation = function () {
            var r = orig.call(this);
            try {
                authMtopRecord(this);
            } catch (e) { }
            return r;
        };
        n += 1;
    }
    return n;
}

function hookAuthMtop() {
    var cn = "mtopsdk.mtop.domain.MtopResponse";
    var K;
    try {
        K = Java.use(cn);
    } catch (e) {
        return 0;
    }
    var n = 0;
    for (var i = 0; i < CONF.diag.mtopEntry.length; i++) {
        n += hookAuthMtopName(K, cn, CONF.diag.mtopEntry[i]);
    }
    if (n > 0) {
        AUTH.mtopHooks = n;
        emit({ ev: "auth.mtop-hooks", cls: esc(cn), overloads: n });
    }
    return n;
}

/* ---------------- the outgoing request: was a Cookie even sent? ---------- */

// anet header entries are not uniform across versions: some expose
// getName()/getValue(), some are Map.Entry (getKey/getValue), some only fields.
// The last resort is the toString() of
// Collections$UnmodifiableMap$UnmodifiableEntry, which is literally
// "name=value".
function authHeaderPairs(req) {
    var out = [];
    var list;
    try {
        list = req.getHeaders();
    } catch (e) {
        return out;
    }
    if (list === null || list === undefined) return out;
    var n = 0;
    try {
        n = list.size();
    } catch (e2) {
        try {
            n = list.entrySet().size();
        } catch (e3) {
            return out;
        }
    }
    for (var i = 0; i < n && i < 64; i++) {
        var e = null;
        try {
            e = list.get(i);
        } catch (e4) {
            try {
                e = list.entrySet().toArray()[i];
            } catch (e5) {
                break;
            }
        }
        if (e === null || e === undefined) continue;

        var name = null, val = "";
        try { name = String(e.getName()); } catch (e6) { }
        if (name === null || name === "undefined" || name === "null") {
            name = null;
            try { name = String(e.getKey()); } catch (e7) { }
            if (name === "undefined" || name === "null") name = null;
        }
        if (name === null) {
            var s = "";
            try { s = String(e); } catch (e8) { s = ""; }
            var eq = s.indexOf("=");
            if (eq <= 0) continue;
            name = s.slice(0, eq);
            val = s.slice(eq + 1);
        }
        if (val === "") {
            try { val = String(e.getValue()); } catch (e9) { val = ""; }
        }
        out.push([name, val]);
    }
    return out;
}

// One row per mtop api: the drive repeats the same calls, and the question is
// only whether the *guest* requests carry a Cookie at all.
function authReqRecord(req) {
    if (req === null || req === undefined) return;
    var url;
    try {
        url = String(req.getUrlString());
    } catch (e) {
        try {
            url = String(req.getUrl());
        } catch (e2) {
            return;
        }
    }
    if (url.indexOf("mtop") < 0) return;
    var m = /[?&]api=([^&]+)/.exec(url);
    if (m === null) return;
    var api = decodeURIComponent(m[1]);

    AUTH.reqs += 1;
    var pairs = authHeaderPairs(req);
    var hasCookie = false, cookieLen = 0, hasH5tk = false, hasSid = false;
    for (var i = 0; i < pairs.length; i++) {
        var nm = lower(pairs[i][0]);
        if (nm === "cookie") {
            hasCookie = pairs[i][1].length > 0;
            cookieLen = pairs[i][1].length;
            hasSid = pairs[i][1].indexOf("_tb_token_") >= 0;
        }
        if (nm === "_m_h5_tk") hasH5tk = true;
    }
    if (!hasCookie) AUTH.reqNoCookie += 1;
    if (AUTH.reqSeen[api]) return;
    AUTH.reqSeen[api] = true;
    authNote({
        ev: "auth.req",
        api: esc(clip(api, 70)),
        cookie: hasCookie,
        cookieLen: cookieLen,
        h5tk: hasH5tk,
        sid: hasSid,
        hdr: pairs.length
    });
}

function hookAuthRequest() {
    var cn = "anet.channel.request.Request$Builder";
    var K;
    try {
        K = Java.use(cn);
    } catch (e) {
        return 0;
    }
    var ov;
    try {
        ov = K.build.overload();
    } catch (e2) {
        return 0;
    }
    var key = "authr:" + cn + "#build()";
    if (hookedKeys[key]) return 0;
    hookedKeys[key] = true;
    var orig = ov;
    ov.implementation = function () {
        var r = orig.call(this);
        try {
            authReqRecord(r);
        } catch (e) { }
        return r;
    };
    AUTH.reqHooks += 1;
    emit({ ev: "auth.req-hook", cls: esc(cn), fn: "build" });
    return 1;
}

/* ---------------- the popup itself: a Dialog, not an Activity? ----------- */

// The forced-login bypass only sees Activity.startActivity*(), so a dialog
// login sheet reaches the screen without a single bypass event.  Naming the
// dialog class is therefore the direct answer to "the bypass did nothing --
// why?".  Every show() is counted; only login-looking classes are logged.
function hookAuthDialog() {
    var cn = "android.app.Dialog";
    var K;
    try {
        K = Java.use(cn);
    } catch (e) {
        return 0;
    }
    var ov;
    try {
        ov = K.show.overload();
    } catch (e2) {
        return 0;
    }
    var key = "authd:" + cn + "#show()";
    if (hookedKeys[key]) return 0;
    hookedKeys[key] = true;
    var orig = ov;
    ov.implementation = function () {
        try {
            AUTH.dialogs += 1;
            var name = "";
            try { name = String(this.$className); } catch (e) { name = ""; }
            if (name.length > 0 && CONF.diag.dialogRe.test(name)) {
                authNote({ ev: "auth.dialog", cls: esc(name), n: AUTH.dialogs });
            }
        } catch (e2) { }
        return orig.call(this);
    };
    AUTH.dialogHooks += 1;
    emit({ ev: "auth.dialog-hook", cls: esc(cn), fn: "show" });
    return 1;
}

/* ---------------- the verdict: one line a human can act on --------------- */

function authVerdict(stage) {
    var why = [];
    var verdict;
    if (AUTH.deny > 0) {
        verdict = "server-denied";
        why.push(AUTH.deny + " mtop response(s) carried a session/token denial code");
        why.push("the call was sent and refused -- disguise cannot fix this, only a login can");
    } else if (AUTH.lastBool === false && AUTH.searches === 0) {
        verdict = "client-gated";
        why.push("a login-state getter answered false");
        why.push("no search-ish mtop api was ever answered, so nothing was asked of the server");
    } else if (AUTH.mtopRows.length === 0) {
        verdict = "inconclusive";
        why.push("no mtop response was observed (hook installed too late, or this build does not route through MtopResponse)");
    } else if (AUTH.lastBool === null) {
        verdict = "inconclusive";
        why.push("mtop traffic seen but no login-state getter was ever called");
        why.push("read auth.mtop rows: a non-zero denial family there still means server-side");
    } else {
        verdict = "inconclusive";
        why.push("mtop traffic seen (" + AUTH.mtopRows.length + " distinct api/ret pairs) with no denial code");
        why.push("if a wall still appeared, it was not produced by a rejected signed call");
    }
    emit({
        ev: "auth.verdict",
        stage: stage || "final",
        verdict: verdict,
        why: why,
        stateCalls: AUTH.bools,
        lastBool: AUTH.lastBool,
        user: AUTH.user === null ? null : esc(AUTH.user),
        classes: AUTH.classes,
        stateHooks: AUTH.stateHooks,
        reqs: AUTH.reqs,
        reqNoCookie: AUTH.reqNoCookie,
        mtop: AUTH.mtopRows.length,
        searchApis: AUTH.searches,
        denied: AUTH.deny,
        dialogs: AUTH.dialogs,
        forced: CONF.diag.forceLogin
    });
}

// Idempotent on purpose: boot() calls it, and every rescan calls it again to
// catch account classes that were loaded after the first pass (an obfuscated
// app loads that module on demand).  Every install function guards itself with
// hookedKeys, so a second call adds hooks, never duplicates them.
function installAuthDiag() {
    if (!CONF.diag.enabled) {
        emit({ ev: "auth-boot", enabled: false });
        return 0;
    }
    var nClasses = 0, nState = 0, nMtop = 0, nReq = 0, nDlg = 0;
    try { nClasses = authClasses(); } catch (e) {
        emit({ ev: "auth-fail", where: "classes", err: clip(String(e), 200) });
    }
    try { nState = hookAuthState(); } catch (e2) {
        emit({ ev: "auth-fail", where: "state", err: clip(String(e2), 200) });
    }
    try { nMtop = hookAuthMtop(); } catch (e3) {
        emit({ ev: "auth-fail", where: "mtop", err: clip(String(e3), 200) });
    }
    try { nReq = hookAuthRequest(); } catch (e4) {
        emit({ ev: "auth-fail", where: "request", err: clip(String(e4), 200) });
    }
    try { nDlg = hookAuthDialog(); } catch (e5) {
        emit({ ev: "auth-fail", where: "dialog", err: clip(String(e5), 200) });
    }
    if (!AUTH.booted) {
        AUTH.booted = true;
        emit({
            ev: "auth-boot",
            enabled: true,
            classes: AUTH.classes,
            stateHooks: AUTH.stateHooks,
            mtopHooks: AUTH.mtopHooks,
            reqHook: AUTH.reqHooks,
            dialogHook: AUTH.dialogHooks,
            forceLogin: CONF.diag.forceLogin,
            verdictAtMs: CONF.diag.verdictAtMs
        });
        // Two summaries, because the window is chosen by --seconds: the early
        // one makes a 30 s run answerable, the late one is the one to read when
        // the drive had time to walk the feed.  `stage` says which is which.
        setTimeout(function () {
            try { authVerdict("early"); } catch (e) {
                emit({ ev: "auth-fail", where: "verdict-early", err: clip(String(e), 200) });
            }
        }, CONF.diag.earlyVerdictMs);
        setTimeout(function () {
            try { authVerdict("final"); } catch (e) {
                emit({ ev: "auth-fail", where: "verdict", err: clip(String(e), 200) });
            }
        }, CONF.diag.verdictAtMs);
    }
    return nClasses + nState + nMtop + nReq + nDlg;
}

/* ------------------------------------------------------------------ *
 * boot
 * ------------------------------------------------------------------ *
 * Everything below runs inside Java.perform(): Java.use() and
 * Java.enumerateLoadedClassesSync() both need an attached VM.
 *
 * Order matters:
 *   1. install the loader watchers first, so a match resolved while the
 *      first scan is still walking the class list is not missed;
 *   2. scan once immediately;
 *   3. arm one timer per CONF.rescanAtMs offset and print the coverage
 *      summary on the last pass only -- repeating it on every pass would
 *      bury the interesting one in near-identical copies.
 */

var timers = [];

// Named factory rather than an inline closure, so `ms` / `isLast` are bound
// per timer instead of all sharing the loop's `var` (same trap as watchOne).
function makeRescan(ms, isLast) {
    return function () {
        var tag = "t" + ms;
        var fresh = rescan(tag);
        emit({ ev: "rescan", tag: tag, fresh: fresh, seen: countKeys(seenTargets) });
        // The account module loads on demand, so the task-1 inventory and its
        // hooks are re-run on every pass.  installAuthDiag is idempotent: each
        // install function is guarded by hookedKeys, so a later call only adds
        // what is new.
        if (CONF.diag.enabled) {
            try {
                installAuthDiag();
            } catch (e) {
                emit({ ev: "auth-fail", where: "rescan", err: clip(String(e), 160) });
            }
        }
        if (isLast) coverage();
    };
}

// One timer per configured offset -- a fixed series of passes (2s, 5s, 10s,
// 20s, 30s), which is what the "did it load late?" question actually needs,
// rather than a drifting repeating heartbeat.
function armRescans() {
    for (var i = 0; i < CONF.rescanAtMs.length; i++) {
        var ms = CONF.rescanAtMs[i];
        timers.push(setTimeout(makeRescan(ms, i === CONF.rescanAtMs.length - 1), ms));
    }
}

function boot() {
    emit({
        ev: "boot",
        pkg: esc(CONF.pkgDot),
        expected: CONF.expected.length,
        filter: CONF.filter,
        stubN: CONF.stub.length,
        watchLoads: CONF.watchLoads,
        rescanAtMs: CONF.rescanAtMs
    });

    if (CONF.watchLoads) watchLoads();

    // Arm the login-wall bypass before anything else: with run_agent.py the
    // script is loaded *before* device.resume(), so these hooks are already in
    // place for the very first forced jump.
    try {
        installBypass();
    } catch (e) {
        emit({ ev: "bypass-failed", err: clip(String(e), 300) });
    }

    // Then the disguise.  SecurityGuard samples Build / SystemProperties /
    // File.exists the moment it builds its first fingerprint, which happens
    // during the cold start this script is deliberately loaded ahead of.
    try {
        installSpoof();
    } catch (e2) {
        emit({ ev: "spoof-failed", err: clip(String(e2), 300) });
    }

    // Task 1: record *why* a login wall appears -- a client-side "am I logged
    // in?" answer, or a server refusal of a signed call.  Installed here, before
    // the first screen exists, so the account classes that are already resident
    // get their state getters hooked before anything asks them.
    try {
        installAuthDiag();
    } catch (e3) {
        emit({ ev: "auth-failed", err: clip(String(e3), 300) });
    }

    // The six are normally already loaded when we attach, so nothing will call
    // loadClass() for them afterwards: their loader has to be found up front.
    var swept = sweepLoaders(0);
    emit({ ev: "loaders", found: swept, kept: loaderFactories.length });

    emit({
        ev: "rescan",
        tag: "boot",
        fresh: rescan("boot"),
        seen: countKeys(seenTargets)
    });

    armRescans();
}

Java.perform(function () {
    try {
        boot();
    } catch (e) {
        emit({ ev: "boot-failed", err: clip(String(e), 400) });
    }
});

