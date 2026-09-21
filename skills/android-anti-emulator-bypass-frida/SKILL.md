---
name: android-anti-emulator-bypass-frida
description: Use when an Android app crashes on launch in an emulator or with a debugger attached. The app checks Build.BRAND, Build.FINGERPRINT, Build.MODEL, or Debug.isDebuggerConnected() and triggers a crash. Hook all boolean check methods with Frida to return false. Triggers - "anti-emulator", "emulator detection", "Build.FINGERPRINT", "isDebuggerConnected", "app crashes emulator", "anti-debug bypass", "Frida emulator bypass", "goldfish ranchu"
platform: [android]
stack: [native]
category: recon
tier: A
related: []
---


# android-anti-emulator-bypass-frida

Bypass anti-emulator/anti-debugger checks in Android apps with Frida.

## When to use

- The app crashes when opened in Genymotion / Android Studio Emulator /
  with a debugger attached.
- In the code (jadx/smali) there are methods that check `Build.*` and
  `Debug.isDebuggerConnected()`, followed by `int i = 0/0` or
  `throw new RuntimeException()`.
- The checks are in `onClick`, `onCreate`, or methods called before the
  interesting logic.

## Typical detection patterns

| Method | Check | Detects |
|---|---|---|
| `Build.BRAND.startsWith("sdk")` | Genymotion/emulator | `Build.BRAND` |
| `Build.FINGERPRINT.startsWith("generic"/"unknown")` | Emulator | `Build.FINGERPRINT` |
| `Build.HARDWARE.contains("goldfish"/"ranchu")` | Emulator | `Build.HARDWARE` |
| `Build.MODEL.contains("google_sdk"/"Emulator"/"Android SDK built for x86")` | Emulator | `Build.MODEL` |
| `Build.MANUFACTURER.contains("Genymotion")` | Genymotion | `Build.MANUFACTURER` |
| `Build.PRODUCT.contains("sdk"/"simulator"/"emulator")` | Emulator | `Build.PRODUCT` |
| `Debug.isDebuggerConnected()` | Debugger/jdwp | `Debug` |

## Bypass with Frida

```javascript
Java.perform(function () {
    var M = Java.use('com.example.app.MainActivity');
    // Hook ALL methods that return boolean and perform the check
    ['V0', 'P0', 'R0', 'S0', 'U0'].forEach(function (m) {
        M[m].implementation = function () {
            return false;  // always false = not detected
        };
    });
    console.log('[*] Anti-emulator hooks installed');
});
```

> **Important:** hook ALL the checks. If you leave one unhooked, the app
> crashes. The names are obfuscated by proguard (V0, P0, R0...),
> identify the methods that return `boolean` and are called in an
> `if (|| || ||)` followed by a crash.

## Identify the methods to hook

In jadx/smali, search for:

```java
if (V0() || P0() || R0() || S0() || U0()) {
    int i = 0 / 0;  // ArithmeticException
}
```

```smali
invoke-virtual {p0, ...}, Lcom/.../MainActivity;->V0()Z
move-result v0
if-eqz v0, :cond_crash
invoke-virtual {p0, ...}, Lcom/.../MainActivity;->P0()Z
...
:cond_crash
const/4 v0, 0x0
div-int/2addr v0, v0  # 0/0
```

## Verification

After installing the hooks, the app should not crash. Verify that the
methods are called (add `console.log` to the hook):

```javascript
M[m].implementation = function () {
    console.log('[*] ' + m + ' called -> false');
    return false;
};
```

## Notes

- On Frida 17+, `Module.findExportByName(null, 'system')` may fail.
  Use `Process.findModuleByName('libc.so').enumerateExports()`.
- If the native lib does not load instantly, use a loop with `setTimeout`
  and `Process.findModuleByName('libX.so')`.
- `Java.scheduleOnMainThread` requires a thread with `Looper.prepare()`.
  It is better to hook methods the app calls naturally (onClick) than to
  invoke them manually.
