---
name: flutter-ssl-bypass-patternscan
description: Use when intercepting HTTPS traffic from a Flutter app. Flutter uses its own BoringSSL inside libflutter.so, which ignores system proxy settings and system CAs. Generic SSL unpinning tools (objection, ssl-kill-switch) do NOT work on Flutter. This skill locates ssl_verify_peer_cert via pattern scan and patches it to always succeed. Derive the offset dynamically: never hardcode it. Triggers - "Flutter SSL", "Flutter proxy", "Flutter MITM", "BoringSSL", "libflutter.so", "ssl_verify_peer_cert", "Flutter traffic intercept", "Flutter Burp"
platform: [android, ios]
stack: [flutter]
category: enabling
tier: A
related: [flutter-dart-heap-rsa-carve]
---

# Flutter SSL Bypass via BoringSSL Pattern Scan

## When to use

- You need to intercept HTTPS traffic from a Flutter app through Burp/Caido
- System proxy is configured but no Flutter traffic appears in the proxy
- `objection` or `ssl-kill-switch2` are loaded but Flutter requests bypass them
- You see traffic in Wireshark but not in your proxy: Flutter uses its own TLS stack

## Why generic tools fail

Flutter embeds BoringSSL inside `libflutter.so`. It does NOT use:
- Android's `HttpURLConnection` or `OkHttp` (what objection hooks)
- iOS's `NSURLSession` or `Security.framework` (what ssl-kill-switch hooks)
- System CA store (your Burp CA in the system store is ignored)

The certificate verification happens in a C function (`ssl_verify_peer_cert`) compiled into `libflutter.so`. You must patch THIS function.

## Workflow

### Step 1: Find libflutter.so

```javascript
const flutter = Process.findModuleByName("libflutter.so");
console.log(`libflutter.so base: ${flutter.base}, size: ${flutter.size}`);
```

### Step 2: Pattern scan for ssl_verify_peer_cert

The function has a recognizable signature. Search for the instruction sequence near the verification return:

```javascript
'use strict';

function findSSLVerify() {
    const m = Process.findModuleByName("libflutter.so");
    if (!m) { console.log("libflutter.so not loaded yet"); return null; }

    // ARM64 pattern: the function epilogue near the "return 0" (success)
    // This pattern is stable across Flutter 3.x builds
    // Look for: handshake->peer_pubkey comparison + x0=0 return
    //
    // IMPORTANT: derive this for YOUR specific libflutter.so version.
    // Method: disassemble libflutter.so in Ghidra/IDA, find ssl_verify_peer_cert,
    // extract 8-16 bytes around the critical comparison as the scan pattern.

    // Example pattern (varies by Flutter version: DO NOT blindly copy):
    const pattern = "FF 03 01 D1 F4 4F 02 A9 FD 7B 03 A9 FD C3 00 91";

    const matches = Memory.scanSync(m.base, m.size, pattern);
    if (matches.length === 0) {
        console.log("[-] Pattern not found: extract a new one from this build");
        return null;
    }
    console.log(`[+] ssl_verify_peer_cert candidate at: ${matches[0].address}`);
    return matches[0].address;
}
```

### Step 3: Patch the function

```javascript
function patchSSLVerify(addr) {
    Interceptor.attach(addr, {
        onLeave(retval) {
            // Force return 0 = SSL_VERIFY_OK
            retval.replace(ptr(0x0));
        }
    });
    console.log("[+] ssl_verify_peer_cert patched: all certs accepted");
}

// Wait for libflutter.so to load (it loads after the Flutter engine initializes)
function waitAndPatch() {
    const interval = setInterval(() => {
        const addr = findSSLVerify();
        if (addr) {
            clearInterval(interval);
            patchSSLVerify(addr);
        }
    }, 500);
}

waitAndPatch();
```

### Step 4: Verify

After patching, trigger a network request in the app. It should appear in Burp/Caido. If it doesn't:
1. Check that the system proxy is configured (`settings put global http_proxy <ip>:<port>`)
2. Flutter ignores system proxy: you may also need `flutter-proxy-redirect-frida` to redirect at the socket level
3. Check the Frida console for the patch confirmation message

## How to derive the pattern for a new build

When the pattern doesn't match (new Flutter/Dart version):

1. **Pull libflutter.so from the device:**
   ```bash
   adb pull /data/app/~~.../lib/arm64-v8a/libflutter.so
   ```

2. **Open in Ghidra/IDA.** Search for string references to `"ssl_server"` or `"ssl_client"`: these are near the verification function.

3. **Find `ssl_verify_peer_cert`**: it's the function that calls `SSL_get_peer_certificate` and returns 0 (success) or an error code.

4. **Extract 12-16 bytes** from the function prologue as your scan pattern.

5. **Verify the pattern is unique:** `Memory.scanSync` should return exactly 1 match. If multiple matches, extend the pattern.

## Gotchas

- **Pattern changes per Flutter version.** NEVER hardcode an offset (`base + 0x89af5c`). Offsets break on every build. Pattern scan adapts automatically.
- **iOS:** `libflutter.so` becomes `Flutter.framework/Flutter` on iOS. Same BoringSSL, same technique, different binary name.
- **Delayed loading:** `libflutter.so` loads AFTER the native Activity starts. Use `setInterval` to poll until the module appears.
- **Obfuscated Flutter builds:** some builds strip symbols completely. The pattern scan still works because it targets machine code, not symbols.
- **Combined with proxy redirect:** on many Flutter apps, you need BOTH this skill (accept any cert) AND a socket-level proxy redirect (because Flutter ignores system proxy settings).
