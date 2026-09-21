---
name: android-antifrida-file-check-bypass
description: Use when an Android app detects Frida by checking for frida-server files, scanning port 27042, or enumerating suspicious threads, and terminates or disables functionality; teaches hooking the detector or renaming frida-server to evade detection. Triggers - "anti-frida", "HookDetector", "frida-server detection", "TamperProof", "27042"
platform: [android]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---


# android-antifrida-file-check-bypass: Bypass anti-Frida file-check detection

## When
- App with a "TamperProof" toggle that closes the app if it detects frida-server.
- Trivial check `new File("/data/local/tmp/frida-server").exists()`.
- Port scan (27042) or `re.frida.server`.

## Recipe

### 1. Identify the detector (static)
```bash
jadx -d out app.apk
grep -rn "frida-server\|re.frida\|27042\|isFridaServer\|TamperProof\|HookDetector" out/
```

### 2. Hook that returns false
```javascript
Java.perform(function () {
    Java.use("com.target.detections.HookDetector")
        .isFridaServerInDevice.implementation = function () {
            console.log("[+] anti-Frida bypassed");
            return false;
        };
});
```

### 3. Alternatives if you do not know the class
```javascript
// generic File.exists hook for frida-server
var File = Java.use('java.io.File');
File.exists.implementation = function () {
    var p = this.getAbsolutePath();
    if (p.indexOf('frida') !== -1 || p.indexOf('re.frida') !== -1) {
        console.log("[+] File.exists bypass: " + p);
        return false;
    }
    return this.exists();
};
```

### 4. Rename frida-server (no hook)
```bash
adb shell "cp /data/local/tmp/frida-server /data/local/tmp/fs"
adb shell "/data/local/tmp/fs -l 0.0.0.0:27042 &"
# the filename check fails
```

## Pitfalls
- **Multiple checks**: the app may check file + port + suspicious threads. Hook them all or use a renamed `frida-server` + non-default port.
- **Native detector**: if the check is in C/C++ (`access()` / `stat()`), use `Interceptor.attach` on libc.
- **Thread scan**: some apps enumerate threads and look for `gum-js-loop` → rename via a modified `frida-server` or `frida-gadget`.
- **Check in static initializer**: if the check runs before Frida installs hooks, use spawn (`-f`) and early hooking.

## Verification
CyberTruck19: `HookDetector.isFridaServerInDevice()` → hook returns `false`, app survives the TamperProof toggle (PID stays alive, no `System.exit(0)`).
