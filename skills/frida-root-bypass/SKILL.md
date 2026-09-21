---
name: frida-root-bypass
description: Use when an Android app detects root/debuggable state and kills itself via System.exit(0). Covers hooking System.exit, Debug.isDebuggerConnected, RootBeer methods, and custom root detection classes to neutralize all checks at Java layer. Triggers - "root detected", "app is debuggable", "System.exit bypass", "frida root bypass", "RootBeer bypass"
platform: [android]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---

# SKILL: Root/debug detection bypass with Frida (Java layer)

> **Trigger**: "root detected", "app is debuggable", "System.exit bypass", "frida root bypass", "RootBeer bypass".
> **Covers**: neutralizing root, debuggable, debugger-connected checks that kill the app at startup.

## When to use
- The app shows "Root detected!" / "App is debuggable!" and calls `System.exit(0)`.
- `Debug.isDebuggerConnected()` in an AsyncTask kills the app if you attach a debugger.
- RootBeer (`com.scottyab.rootbeer` or obfuscated classes `b.a.a.b`) detects `su`.

## Universal template

```javascript
// frida -U -f <package> -l bypass.js </dev/null
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.exit.implementation = function (c) {
        console.log('[+] System.exit(' + c + ') neutralized');
    };

    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function () { return false; };

    // Hook the root detection classes (names vary per app; decompile and adjust):
    // typical shapes are a class with static boolean methods a/b/c, or a utility
    // class with checkRoot1/2/3; RootBeer obfuscates to something like b.a.a.b.
    try {
        var RD = Java.use('<detection.class>');  // adjust the name
        RD.a.implementation = function () { return false; };
        RD.b.implementation = function () { return false; };
        RD.c.implementation = function () { return false; };
    } catch (e) {}

    // Debuggable flag check: (flags & 2) != 0
    try {
        var DC = Java.use('<debug.detection.class>');  // adjust
        DC.a.implementation = function (ctx) { return false; };
    } catch (e) {}
});
```

## How to find the exact names

1. Decompile with jadx.
2. In `MainActivity.onCreate`, look at the `if (... ) { a("Root detected!"); }`.
3. Follow the calls to the detection class (its name is usually obfuscated).
4. For RootBeer: `new b.a.a.b(ctx); if (rb.j() || (rb.a() && rb.e()))` -> hook `j`, `a`, `e`.

## RootBeer (b.a.a.b) - aggressive bypass

```javascript
var RB = Java.use('b.a.a.b');
['j','a','e','c','d','f','g','h','i','b'].forEach(function (m) {
    try {
        RB[m].overloads.forEach(function (ov) {
            ov.implementation = function () { return false; };
        });
    } catch (e) {}
});
```

## Problem: the app crashes before the hook applies

If `onCreate` runs and crashes (e.g. `1337/0`) before `Java.perform` installs the hooks:
- **Option A**: Frida `-f` (spawn) pauses the app before the first bytecode. The hooks in `Java.perform` should apply in time. If not, use `--pause` and manual `%%resume`.
- **Option B**: Patch the smali with apktool (see `SKILL_apk_patch_resign.md`).
- **Option C**: If the crash is native (SIGSEGV in `lib*.so`), use LIEF (see `SKILL_lief_patch_antifrida.md`).

## Frida 17.x - changed API

```javascript
// OLD (Frida <16): Module.findExportByName('libfoo.so', 'sym')
// NEW (Frida 17+):
function findExp(modName, expName) {
    var m = Process.findModuleByName(modName);
    if (!m) return null;
    if (typeof m.findExportByName === 'function') return m.findExportByName(expName);
    if (typeof Module.getExportByName === 'function') return Module.getExportByName(modName, expName);
    return null;
}
```

## Run (mac + Genymotion)

```bash
# frida-server must be running on the device: adb shell "ps -A | grep frida"
# Spawn + script + automatic exit:
timeout 20 frida -U -f <package> -l bypass.js </dev/null 2>&1 | grep -E "neutralized|bypass"
```

## Expected output
The app starts without showing "Root detected" or crashing, letting you interact with / hook the secret logic.
