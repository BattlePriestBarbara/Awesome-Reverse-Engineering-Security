// trace_native.js - log the crypto/licence entry points we identified in the APK.
//
// libmd.so is NOT stripped and exports its logic, so these names resolve directly:
//   _Z19genECDHsharedsecretP9ec_key_stPhj   (ECDH shared secret)
//   _Z13genECDHpubkeySsPhRj                 (ECDH public key gen)
//   _Z18aes_256_cbc_encodePKhRKSs / _decode (AES-256-CBC)
//   _Z13pemString2keySs                     (PEM -> EC key)
//   Java_com_openssl_md_JniHand_*           (JNI entry points)
// libidl_license.so / libocr-sdk.so 的授权校验入口也可按同样方式挂。
//
// Usage:  D:\frida\frida.cmd -U -f com.hicorenational.antifraud -l D:\frida\hooks\trace_native.js

const TARGETS = [
    ["libmd.so", "_Z19genECDHsharedsecretP9ec_key_stPhj"],
    ["libmd.so", "_Z13genECDHpubkeySsPhRj"],
    ["libmd.so", "_Z18aes_256_cbc_encodePKhRKSs"],
    ["libmd.so", "_Z18aes_256_cbc_decodePKhRKSs"],
    ["libmd.so", "_Z13pemString2keySs"],
    ["libmd.so", "Java_com_openssl_md_JniHand_getAppPubKey"],
    ["libmd.so", "Java_com_openssl_md_JniHand_paramJsonEncode"],
    ["libmd.so", "Java_com_openssl_md_JniHand_paramJsonDecode"],
    ["libidl_license.so", "Java_com_baidu_idl_license_License_initLicenseWithToken"],
    ["libidl_license.so", "Java_com_baidu_idl_license_License_getLicenseState"],
    ["libocr-sdk.so", "Java_com_baidu_ocr_sdk_jni_JniInterface_getToken"],
    ["libocr-sdk.so", "Java_com_baidu_ocr_sdk_jni_JniInterface_getTokenFromLicense"]
];

function hexdumpPtr(ptr, length) {
    try { return hexdump(ptr, { length: length, ansi: false }); }
    catch (e) { return "<unreadable>"; }
}

// Frida 17 removed both Module.findExportByName() and Module.getExportByName(); resolve
// through the owning module instead (see hooks/api_probe.js for the full API survey).
function findExport(moduleName, symbol) {
    try {
        if (typeof Module.findExportByName === "function") {
            return Module.findExportByName(moduleName, symbol);
        }
        return Process.getModuleByName(moduleName).getExportByName(symbol);
    } catch (e) {
        return null;
    }
}

// The app's own libraries are ARM and only get dlopen()ed once the app starts touching its
// own classes, i.e. AFTER our script is loaded (frida loads the agent while the spawned
// process is still suspended). Hooking once at load time therefore finds nothing, so we
// retry on a schedule and hook whatever has appeared since the previous pass.
const hooked = new Set();

function hookTargets() {
    let pending = 0;
    TARGETS.forEach(([moduleName, symbol]) => {
        const key = moduleName + "!" + symbol;
        if (hooked.has(key)) return;
        const address = findExport(moduleName, symbol);
        if (!address || address.isNull()) {
            if (Process.findModuleByName(moduleName)) pending++;
            return; // module not loaded (yet) or symbol missing in this ABI
        }
        hooked.add(key);
        console.log("[+] hooked " + key + " @ " + address);
        Interceptor.attach(address, {
            onEnter(args) {
                this.tag = key;
                console.log("--> " + this.tag);
                for (let i = 0; i < 4; i++) {
                    const p = args[i];
                    if (p.isNull()) { console.log("      arg" + i + " = NULL"); continue; }
                    // 数值型参数直接打印；指针型先打印地址再尝试读 32 字节
                    console.log("      arg" + i + " = " + p);
                    try {
                        const head = p.readByteArray(32);
                        if (head) console.log(hexdump(p, { length: 32, ansi: false }));
                    } catch (e) { }
                }
            },
            onLeave(retval) {
                console.log("<-- " + this.tag + " ret=" + retval);
                try {
                    const data = retval.readByteArray(32);
                    if (data) console.log(hexdump(retval, { length: 32, ansi: false }));
                } catch (e) { }
            }
        });
    });
    return { pending: pending, done: hooked.size, total: TARGETS.length };
}

// FRIDA 17: `Java` 只在编译进 frida-java-bridge 时才存在，因此先做特性检测。Java 与否都不影响
// native 挂钩，这里只用它决定是否额外打印一次 Java 侧提示。
const hasJava = (typeof Java !== "undefined") && Java.available;
if (!hasJava) {
    console.log("[!] Java bridge unavailable (Frida 17) - native tracing only");
}

// 调度：早期密集重试（壳 dlopen 自家库通常在 resume 后 0.5-3s），之后放慢。
[0, 200, 500, 1000, 1500, 2500, 4000, 6000, 9000, 14000, 20000].forEach(delay => {
    setTimeout(function () {
        const status = hookTargets();
        if (delay === 0 || status.pending || status.done < status.total) {
            console.log("[*] hook pass t+" + delay + "ms: hooked " + status.done + "/" +
                status.total + ", module loaded but symbol missing " + status.pending);
        }
        if (delay === 20000) {
            ["libmd.so", "libidl_license.so", "libocr-sdk.so", "libjiagu_vip_64.so"]
                .forEach(function (name) {
                    const module = Process.findModuleByName(name);
                    console.log((module ? "[*] loaded: " : "[*] not loaded: ") + name +
                        (module ? " base=" + module.base : ""));
                });
        }
    }, delay);
});

// 本样本的 ARM 库是懒加载的（进到对应功能界面才 dlopen），所以再监听一次 dlopen：
// 目标库一出现就立刻挂钩，而不用等下一轮轮询。
["android_dlopen_ext", "dlopen"].forEach(function (fn) {
    const addr = findExport("libdl.so", fn) || findExport("libc.so", fn);
    if (!addr) {
        console.log("[!] " + fn + " not found - relying on the polling passes");
        return;
    }
    Interceptor.attach(addr, {
        onEnter(args) {
            let path = null;
            try { path = args[0].readCString(); } catch (e) { }
            this.path = path;
        },
        onLeave(retval) {
            if (!this.path) return;
            if (/libmd|libidl_license|libocr-sdk|libcwlive|libcocklogic/i.test(this.path)) {
                console.log("[dlopen] " + this.path + " -> " + retval);
                const status = hookTargets();
                console.log("[*] after dlopen: hooked " + status.done + "/" + status.total);
            }
        }
    });
    console.log("[+] watching " + fn);
});
