---
name: anti-root-bypass-static
description: Use when an APK shows "Device is rooted" or "App is debuggable" and exits, blocking dynamic testing. Covers four strategies: ignore the check and analyze statically, patch smali to NOP the exit, Frida hook the check method, or use Magisk Hide/Shamiko: choosing the lightest one that works. Triggers - "root detected bypass", "anti-root android", "device is rooted", "anti-debug bypass apk", "System.exit root check"
platform: [android]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---

# Skill: android-anti-root-anti-debug-bypass-static

# Anti-root / anti-debug bypass in APKs (via static analysis)

**When to use:** an APK shows "Device is rooted" / "App is debuggable" and exits, blocking dynamic testing. Often static analysis of the `.so` or the DEX is enough and there is no need to bypass anything.

## Common signs (Java)
In `MainActivity.onCreate` or an `Application`:
- `getApplicationInfo().flags & 2` → checks `FLAG_DEBUGGABLE`
- `System.getenv("PATH")` + searches for `su` in each directory
- `Build.TAGS.contains("test-keys")`
- List of paths: `/system/app/Superuser.apk`, `/system/xbin/daemonsu`, `/dev/com.koushikdutta.superuser.daemon/`, etc.
- `PackageManager.getPackageInfo("com.topjohnwu.magisk", ...)` (Magisk)
- Reading `/proc/self/maps` looking for `frida`, `xposed`, `substrate`
- `android.os.Debug.isDebuggerConnected()`

## Strategy 1: Ignore it (static-first)
If the validation logic is in an extracted `.so`, the anti-root does not prevent analyzing it. No runtime needed.

## Strategy 2: Patch the smali
```bash
apktool d -o out app.apk
# In smali/.../MainActivity.smali, find the branch that calls System.exit()
# Change the conditional or NOP the call to u("Device is rooted")
apktool b out -o app.patched.apk
# re-sign
apksigner sign --ks ~/.android/debug.keystore app.patched.apk
```

## Strategy 3: Frida hook at runtime
```js
Java.perform(function() {
  var M = Java.use('party.thcon.y2021.level1.MainActivity');
  M.u.implementation = function(s) { console.log('blocked anti-root:', s); };
});
```
For native checks (`ptrace(PTRACE_TRACEME)`, `/proc/self/status` TracerPid):
```js
Interceptor.attach(Module.findExportByName(null, 'ptrace'), {
  onEnter: function(args) { args[0] = ptr(0); }  // neutralize
});
```

## Strategy 4: Magisk Hide / Shamiko / Zygisk
If the app uses SafetyNet or more serious checks, hide root with Magisk DenyList or hiding modules.

## Note
In static reversing, **strategy 1** is usually enough: local validation is almost always client-side.
