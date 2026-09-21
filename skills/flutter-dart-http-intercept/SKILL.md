---
name: flutter-dart-http-intercept
description: Use when you need to intercept HTTP request/response bodies at the Dart application layer in a Flutter app, especially when the app applies custom encryption or encoding on top of TLS and you cannot see the real payloads in Burp even after SSL bypass. Uses blutter output to locate Dart HTTP functions and Frida to hook them by address. Triggers - "dart http", "dio interceptor", "HttpClient dart", "flutter http hook", "encrypted payload flutter", "custom encryption http", "flutter request body", "dart:io http"
platform: [android, ios]
stack: [flutter]
category: recon
tier: B
related: [mob-flutter, flutter-ssl-bypass-patternscan]
---

# Skill: Flutter Dart HTTP Intercept: hooking Dart's HTTP client with Frida

## What it solves
Flutter does NOT use OkHttp (Android) or NSURLSession (iOS) for HTTP. It uses its own
Dart implementation (`dart:io` HttpClient) over BoringSSL sockets. After an
SSL bypass (e.g.: `ssl-unpin-flutter.js`) the traffic is visible in Burp, but if the app
applies **custom encryption on top of TLS** (envelope encryption, payload signing, an
`encrypted_body` field in the JSON), Burp only shows the encrypted blob. This skill hooks
the HTTP functions **at the Dart level**: before encryption or after decryption: to
see the payloads in the target.

## When to use
- You already have the SSL bypass working but the payloads in Burp are encrypted / obfuscated.
- The app uses `package:dio` with custom interceptors that encrypt/sign the body.
- You need to see the headers, URLs, or bodies the Dart layer builds before sending.
- You want to capture responses before the app processes them (parsing, decryption,
  signature validation).

## Workflow

### 1. Prerequisite: have the blutter output

```bash
# Reconstruct the AOT snapshot
python3 blutter.py path/lib/arm64-v8a ./blutter_out
# Key files: asm/, pp.txt, blutter_frida.js
```

### 2. Locate HTTP functions in the blutter output

**For dart:io HttpClient (the most common):**
```bash
# Search for Dart runtime HTTP classes
grep -n "_HttpClient\b" blutter_out/asm/dart:io/*.dart
grep -n "HttpClientRequest" blutter_out/asm/dart:io/*.dart
grep -n "HttpClientResponse" blutter_out/asm/dart:io/*.dart
grep -n "_HttpOutgoing" blutter_out/asm/dart:io/*.dart

# Search for key methods and their offsets
grep -n "\.open\b\|\.openUrl\b\|\.getUrl\b\|\.postUrl\b" blutter_out/asm/dart:io/*.dart
grep -n "\.write\b\|\.add\b\|\.close\b" blutter_out/asm/dart:io/*.dart
```

**For package:dio (popular in Flutter apps):**
```bash
# dio classes in the snapshot
grep -rn "DioMixin\|Dio\b" blutter_out/asm/package:dio/*.dart 2>/dev/null
grep -rn "\.fetch\b\|\.request\b" blutter_out/asm/package:dio/*.dart 2>/dev/null

# The app's custom interceptors
grep -rn "InterceptorsWrapper\|Interceptor\b" blutter_out/asm/ 2>/dev/null
grep -rn "onRequest\|onResponse\|onError" blutter_out/asm/package:dio/*.dart 2>/dev/null
```

**For package:http:**
```bash
grep -rn "Client\b\|\.send\b\|\.get\b\|\.post\b" blutter_out/asm/package:http/*.dart 2>/dev/null
```

The blutter output shows each function with its **offset** in libapp.so:
```
_ _HttpClient.openUrl (dynamic, dynamic) {
       // 0x3a5f20: ...
```
The offset `0x3a5f20` is the address relative to the `libapp.so` base.

### 3. Hook Dart functions by offset with Frida

**Base pattern: attach to a Dart function by offset**
```js
const MOD = "libapp.so";

function waitModule(name) {
    return new Promise(resolve => {
        const t = setInterval(() => {
            const m = Process.findModuleByName(name);
            if (m) { clearInterval(t); resolve(m); }
        }, 100);
    });
}

// Helper: read a Dart OneByteString (AOT snapshot, compressed pointers)
function readDartStr(ptr) {
    if (ptr.isNull()) return "<null>";
    var obj = ptr.sub(1);           // strip the tag bit
    var len = obj.add(8).readU32() >> 1;  // Smi shift
    if (len <= 0 || len > 65536) return "<bad-len:" + len + ">";
    return obj.add(16).readUtf8String(len);
}

waitModule(MOD).then(mod => {
    console.log("[*] libapp.so base: " + mod.base);

    // Example: hook _HttpClient.openUrl
    // Replace 0x3a5f20 with the real offset from your blutter output
    var openUrl_offset = 0x3a5f20;

    Interceptor.attach(mod.base.add(openUrl_offset), {
        onEnter: function(args) {
            // In Dart AOT arm64: x0=this, x1=arg1, x2=arg2, ...
            // The exact registers depend on the snapshot's calling convention
            // Tip: log x0-x5 and see which ones hold Dart tagged pointers
            console.log("[openUrl] x0=" + this.context.x0);
            console.log("[openUrl] x1=" + this.context.x1);
            try {
                console.log("[openUrl] method=" + readDartStr(this.context.x1));
                console.log("[openUrl] url=" + readDartStr(this.context.x2));
            } catch(e) {
                console.log("[openUrl] parse error: " + e);
            }
        }
    });
});
```

### 4. Hook at the socket level (see raw bytes)

When you cannot identify the high-level HTTP functions, hook lower down:

```bash
# Search for socket functions in the blutter output
grep -n "_SecureSocket\|_Socket\|_RawSocket" blutter_out/asm/dart:io/*.dart
grep -n "\.write\b\|\.writeFrom\b\|\.read\b" blutter_out/asm/dart:io/*.dart
```

```js
// Hook _Socket.write or _SecureSocket.write to see outgoing bytes
// Example offset: replace with the real one
var socketWrite_offset = 0x2b3c40;

Interceptor.attach(mod.base.add(socketWrite_offset), {
    onEnter: function(args) {
        // The argument is typically a Dart _Uint8List
        // _Uint8List layout: tagged, length(Smi)@+20, data@+24
        try {
            var list = this.context.x1.sub(1); // strip the tag
            var len = list.add(20).readU32() >> 1;
            if (len > 0 && len < 65536) {
                var data = list.add(24).readByteArray(Math.min(len, 2048));
                console.log("[Socket.write] len=" + len);
                console.log(hexdump(data, {header:false, ansi:false}));
            }
        } catch(e) {}
    }
});
```

### 5. Hook dio interceptors (high level)

If the app uses `package:dio`, find the `DioMixin.fetch` method: it is the central
entry point for all requests:

```bash
grep -n "DioMixin.*fetch\|Dio.*fetch" blutter_out/asm/package:dio/*.dart
# Example output: "_ DioMixin.fetch (dynamic) { // 0x4a2100"
```

```js
// Hook DioMixin.fetch to see the RequestOptions before sending
var dioFetch_offset = 0x4a2100; // replace with the real offset

Interceptor.attach(mod.base.add(dioFetch_offset), {
    onEnter: function(args) {
        console.log("[Dio.fetch] called");
        // The RequestOptions is in x1 (first arg after this)
        // Its fields (uri, method, data, headers) are Dart objects
        // You need to walk the class's internal offsets
        // Tip: use the blutter_frida.js helpers if available
        try {
            var reqOpts = this.context.x1.sub(1);
            // Field offsets depend on the dio version
            // Check in the blutter asm which field is at which offset
            console.log("[Dio.fetch] RequestOptions@" + reqOpts);
        } catch(e) {}
    }
});
```

### 6. Alternative: hook the app's encrypt/decrypt function

It is often easier to hook the app's **custom encrypt/decrypt** function than the
generic HTTP functions:

```bash
# Search for crypto functions in the app's code (not in dart:io)
grep -rn "encrypt\|decrypt\|sign\|hmac\|cipher" blutter_out/asm/package:<app_pkg>/*.dart
grep -rn "AES\|RSA\|PointyCastle" blutter_out/asm/ 2>/dev/null
```

Hooking the encryption function (`onEnter` = plaintext, `onLeave` = ciphertext) or the
decryption one (`onEnter` = ciphertext, `onLeave` = plaintext) gives you the payloads in
the target without needing to understand the whole HTTP chain.

## What the finding confirms
- The Frida capture shows request/response bodies in plaintext revealing data that
  appeared encrypted in Burp.
- Sensitive data (tokens, PII, credentials) is identified in the application-level
  payloads that the custom encryption layer was hiding.
- It demonstrates that the custom encryption is reversible (hardcoded or extractable key)
  and therefore adds no real security over TLS.

## Limitations
- **Offsets change with every build** of the app. Each APK/IPA version requires
  running blutter again to get updated offsets.
- The Dart AOT calling convention is not standard: arguments are not always in
  x0-x7 in order. It may require trial and error to identify which register holds
  which argument.
- In apps with aggressive tree-shaking, HTTP classes may be renamed or
  inlined. Search by pattern (`open`, `fetch`, `send`) instead of exact name.
- `readDartStr` only works for `OneByteString` (ASCII/Latin-1). Strings with
  multi-byte characters use `TwoByteString` (UTF-16): adjust the reader.
- This skill complements but does not replace the SSL bypass: you first need the bypass
  so the proxy sees the TLS traffic, then this skill to see inside the custom
  encryption.
- Frida + Dart AOT can be unstable if the hook modifies the execution flow.
  Use only `Interceptor.attach` (not `replace`) to minimize crashes.
