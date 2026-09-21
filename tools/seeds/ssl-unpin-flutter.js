/**
 * ssl-unpin-flutter.js: Flutter BoringSSL Certificate Validation Bypass
 * MOSRAI seed script
 *
 * Why this exists:
 *   Flutter apps do NOT use the platform's HTTP stack. They ship their own
 *   BoringSSL inside libflutter.so (Android) or Flutter.framework (iOS).
 *   Generic Java/ObjC SSL hooks have zero effect. The ONLY reliable approach
 *   is to patch the native ssl_crypto_x509_session_verify_cert_chain function
 *   inside the Flutter engine binary so it always returns 1 (success).
 *
 * Approach:
 *   1. Locate the Flutter engine module (libflutter.so / Flutter framework).
 *   2. Pattern-scan for ssl_crypto_x509_session_verify_cert_chain.
 *      Multiple byte patterns are tried for different Flutter/Dart versions.
 *   3. Replace the function entry to return 1 (ARM64: MOV X0,#1; RET).
 *
 * Supported architectures:
 *   - Android arm64 (libflutter.so)
 *   - iOS arm64 (Flutter.framework/Flutter)
 *
 * Usage:
 *   frida -U -f <package-or-bundle> -l ssl-unpin-flutter.js --no-pause
 *
 * Known limitations:
 *   - ARM32 / x86 / x86_64 builds are NOT covered (rare in production).
 *   - If the Flutter engine is heavily custom-built or the byte pattern was
 *     changed, the scan may fail: check the logs and add a new pattern.
 *   - Some Flutter versions inline the verification; the function boundary
 *     may shift. The multi-pattern approach mitigates but does not eliminate
 *     this risk.
 *   - Does not intercept dart:io SecurityContext additions made in Dart code
 *     (but those are almost never the pinning mechanism in production apps).
 */

"use strict";

var TAG = "[ssl-unpin-flutter]";

// ===================================================================
// ARM64 replacement shellcode: MOV X0, #0x1 ; RET
//   20 00 80 D2    mov x0, #1
//   C0 03 5F D6    ret
// ===================================================================
var ARM64_RETURN_TRUE = [0x20, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6];

// ===================================================================
// Byte patterns for ssl_crypto_x509_session_verify_cert_chain
//
// These are the first N bytes of the function prologue across known
// Flutter engine versions. Each entry:
//   pattern : hex string for Memory.scan (Frida wildcard ?? for variable bytes)
//   offset  : bytes from match start to the actual function entry
//   label   : human-readable version hint
//
// Order: newest first. The first match wins.
// ===================================================================
var PATTERNS = [
    {
        // Flutter 3.24.x / Dart 3.5 (2024-Q3+)
        // ssl_crypto_x509_session_verify_cert_chain prologue
        pattern: "FF 83 01 D1 FD 7B 06 A9 F4 4F 05 A9 F6 57 04 A9 F8 5F 03 A9 FA 67 02 A9 FC 6F 01 A9 08 0A 80 D2",
        offset: 0,
        label: "Flutter 3.24 / Dart 3.5"
    },
    {
        // Flutter 3.22.x / Dart 3.4
        pattern: "FF 43 01 D1 FD 7B 04 A9 F4 4F 03 A9 F6 57 02 A9 F8 5F 01 A9 FA 67 00 A9 08 0A 80 D2",
        offset: 0,
        label: "Flutter 3.22 / Dart 3.4"
    },
    {
        // Flutter 3.16–3.19 / Dart 3.2–3.3
        pattern: "FF C3 00 D1 FD 7B 03 A9 F4 4F 02 A9 F6 57 01 A9 F8 5F 00 A9 08 0A 80 D2",
        offset: 0,
        label: "Flutter 3.16-3.19"
    },
    {
        // Flutter 3.10–3.13 / Dart 3.0–3.1
        pattern: "FF 83 01 D1 FD 7B 06 A9 FD 83 01 91 F4 4F 05 A9 F6 57 04 A9 F8 5F 03 A9 FA 67 02 A9 FC 6F 01 A9",
        offset: 0,
        label: "Flutter 3.10-3.13"
    },
    {
        // Flutter 3.3–3.7 / Dart 2.18–2.19
        pattern: "FF 43 01 D1 FD 7B 04 A9 FD 03 01 91 F4 4F 03 A9 F6 57 02 A9 F8 5F 01 A9 FA 67 00 A9",
        offset: 0,
        label: "Flutter 3.3-3.7"
    },
    {
        // Flutter 2.x legacy (Dart 2.14–2.17)
        pattern: "FF C3 00 D1 FD 7B 03 A9 FD C3 00 91 F4 4F 02 A9 F6 57 01 A9 F8 5F 00 A9",
        offset: 0,
        label: "Flutter 2.x (legacy)"
    }
];

// ===================================================================
// Fallback: scan for a distinctive instruction sequence near the
// x509 verification function: the "mov w8, #0x5" (prepare
// X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) followed by
// comparison patterns that appear in the cert-chain loop.
// ===================================================================
var FALLBACK_PATTERNS = [
    {
        // Pattern around the "return 0" (verification-failed) path.
        // We look for the CBNZ -> verify-fail branch and patch the
        // function entry instead.
        pattern: "08 0A 80 D2 ?? ?? ?? ?? ?? ?? ?? 35",
        scanSize: 0x400,
        label: "Fallback: mov w8,#0x5 near cbz/cbnz"
    }
];

// ===================================================================
// Core logic
// ===================================================================
function findFlutterModule() {
    // Android: libflutter.so
    var m = Process.findModuleByName("libflutter.so");
    if (m) {
        console.log(TAG + " Found libflutter.so at base " + m.base + " size " + m.size);
        return m;
    }

    // iOS: Flutter framework
    m = Process.findModuleByName("Flutter");
    if (m) {
        console.log(TAG + " Found Flutter.framework at base " + m.base + " size " + m.size);
        return m;
    }

    // Some apps rename the library
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var name = modules[i].name.toLowerCase();
        if (name.indexOf("flutter") !== -1 || name.indexOf("libflutter") !== -1) {
            console.log(TAG + " Found Flutter module (alt name): " + modules[i].name + " at " + modules[i].base);
            return modules[i];
        }
    }

    return null;
}

function patchFunction(addr) {
    console.log(TAG + " Patching function at " + addr);
    Memory.protect(addr, ARM64_RETURN_TRUE.length, "rwx");
    for (var i = 0; i < ARM64_RETURN_TRUE.length; i++) {
        addr.add(i).writeU8(ARM64_RETURN_TRUE[i]);
    }
    console.log(TAG + " Patched: ssl_crypto_x509_session_verify_cert_chain now returns 1 (trust all).");
}

function scanWithPatterns(flutterModule) {
    var base = flutterModule.base;
    var size = flutterModule.size;

    // Try primary patterns
    for (var i = 0; i < PATTERNS.length; i++) {
        var entry = PATTERNS[i];
        console.log(TAG + " Trying pattern: " + entry.label);

        var matches = Memory.scanSync(base, size, entry.pattern);
        if (matches.length > 0) {
            var target = matches[0].address.add(entry.offset);
            console.log(TAG + " MATCH (" + entry.label + ") at " + matches[0].address +
                         " (offset from base: 0x" + matches[0].address.sub(base).toString(16) + ")");
            if (matches.length > 1) {
                console.log(TAG + " [!] Multiple matches (" + matches.length + "): using first. " +
                             "If bypass fails, the target may be a different match.");
            }
            patchFunction(target);
            return true;
        }
    }

    // Try fallback patterns: these match near (not at) the function entry.
    // We walk backwards from the match to find the function prologue.
    for (var j = 0; j < FALLBACK_PATTERNS.length; j++) {
        var fb = FALLBACK_PATTERNS[j];
        console.log(TAG + " Trying fallback: " + fb.label);

        var fbMatches = Memory.scanSync(base, size, fb.pattern);
        if (fbMatches.length > 0) {
            // Walk backward up to scanSize bytes looking for a standard ARM64
            // function prologue (STP X29, X30, ...)
            var matchAddr = fbMatches[0].address;
            console.log(TAG + " Fallback hit at " + matchAddr + ": searching backward for prologue.");

            for (var back = 4; back <= fb.scanSize; back += 4) {
                var candidate = matchAddr.sub(back);
                var insnWord = candidate.readU32();
                // STP Xn, Xn, [SP, #imm]!: encoding mask for the common prologue
                // We look for the full FF xx xx D1 pattern (SUB SP, SP, #imm)
                if ((insnWord & 0xFF0003FF) === 0xD10003FF) {
                    console.log(TAG + " Probable function prologue at " + candidate +
                                 " (offset from base: 0x" + candidate.sub(base).toString(16) + ")");
                    patchFunction(candidate);
                    return true;
                }
            }
            console.log(TAG + " [!] Could not locate prologue from fallback match.");
        }
    }

    return false;
}

// ===================================================================
// Entry point: wait for module to load if needed
// ===================================================================
function attemptBypass() {
    var flutterModule = findFlutterModule();
    if (!flutterModule) {
        console.log(TAG + " [!] Flutter engine module not found.");
        console.log(TAG + "     If this is a Flutter app, the engine may not be loaded yet.");
        console.log(TAG + "     Retrying with delayed module enumeration...");
        return false;
    }

    if (Process.arch !== "arm64") {
        console.log(TAG + " [!] Architecture " + Process.arch + " is not supported by this seed.");
        console.log(TAG + "     Only arm64 is covered. You will need a custom pattern for " + Process.arch + ".");
        return false;
    }

    var success = scanWithPatterns(flutterModule);
    if (!success) {
        console.log(TAG + " [!] No pattern matched in the Flutter engine.");
        console.log(TAG + "     The Flutter/Dart version may be newer than the known patterns.");
        console.log(TAG + "     Action: dump the libflutter.so, find ssl_crypto_x509_session_verify_cert_chain");
        console.log(TAG + "     using Ghidra/IDA, extract the prologue bytes, and add a new PATTERNS entry.");

        // Last resort: try to find exported symbol (debug/profile builds sometimes export it)
        var sym = Module.findExportByName(flutterModule.name, "ssl_crypto_x509_session_verify_cert_chain");
        if (sym) {
            console.log(TAG + " Found exported symbol at " + sym + ": patching.");
            patchFunction(sym);
            return true;
        }
    }

    return success;
}

// Try immediately
var done = attemptBypass();

// If module wasn't loaded yet, set up a delayed retry
if (!done) {
    console.log(TAG + " Setting up delayed retry (1.5s) for late-loading Flutter engine...");
    setTimeout(function () {
        var retry = attemptBypass();
        if (!retry) {
            console.log(TAG + " [FAIL] Could not bypass Flutter SSL pinning.");
            console.log(TAG + "        Verify this is a Flutter app and the architecture is arm64.");
            console.log(TAG + "        For manual analysis: frida -U <pid> then Module.enumerateModules()");
        } else {
            console.log(TAG + " --- Flutter SSL bypass installed (delayed) ---");
        }
    }, 1500);
}

if (done) {
    console.log(TAG + " --- Flutter SSL bypass installed ---");
}
