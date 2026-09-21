---
name: encrypted-api-payload-testing
description: Use when the mobile app encrypts all API payloads with a custom crypto layer on top of TLS (RSA+AES envelope, HMAC-signed bodies, custom XOR/encode). Standard web payloads (IDOR, SQLi, business logic) fail because the server rejects malformed ciphertext. This skill teaches how to intercept at the crypto boundary with Frida or a proxy script to test server-side vulns through the encrypted channel. Triggers - "encrypted API", "custom crypto", "envelope encryption", "RSA AES payload", "can't modify request", "encrypted body", "ciphertext body"
platform: [android, ios]
stack: [any]
category: crypto
tier: B
related: [flutter-bank-rsa-idor, flutter-dart-heap-rsa-carve, mob-flutter, mob-native]
---

# Testing Server-Side Vulns Through Encrypted API Channels

## When to use

- The app encrypts all API request bodies before sending (RSA+AES envelope, HMAC-signed JSON, custom XOR/encode)
- Burp/Caido shows ciphertext blobs instead of readable JSON in request bodies
- Modifying any byte in the encrypted body causes the server to reject the request (padding error, MAC mismatch, decryption failure)
- You suspect standard server-side vulnerabilities (IDOR, SQLi, rate-limit bypass, business logic) but cannot test them because you cannot modify payloads in transit
- The app uses TLS plus an additional application-layer encryption

## Why standard testing fails

When a mobile app wraps all API traffic in a crypto envelope, the usual Burp workflow breaks:

1. You intercept the request but see `{"data":"base64blob","encKey":"base64blob"}`
2. Changing any field in the blob causes server-side decryption failure (400/500)
3. Replay works but modification does not
4. The standard OWASP web payloads (IDOR by changing user ID, SQLi in parameters) require modifying the plaintext before encryption

The idea of the attack transfers (IDOR, rate-limit, business logic are the same vulns). The payload does not transfer without wrapping it in the app's crypto.

## Step 1: Identify the crypto scheme

Determine what crypto the app uses before choosing your interception approach.

### Static analysis

```bash
# Android (jadx or blutter for Flutter)
grep -riE "encrypt|decrypt|cipher|AES|RSA|HMAC|sign|mac|seal|envelope" /tmp/re_<app>/jadx_output/ --include="*.java" -l
grep -riE "encrypt|decrypt|AES|RSA|pointycastle|cipher" /tmp/re_<app>/blutter_out/asm/ -l

# iOS
strings /tmp/re_<app>/Payload/App.app/<binary> | grep -iE "AES|RSA|CCCrypt|SecKey|OAEP|PKCS|encrypt|cipher"
```

### Traffic analysis

Capture a few requests and look for patterns:

| Pattern | Likely scheme |
|---|---|
| `{"data":"b64...","encryptedKey":"b64...","encryptedIv":"b64..."}` | RSA+AES envelope (key per request) |
| `{"payload":"b64...","signature":"hex..."}` | HMAC-signed body (integrity, not confidentiality) |
| `{"ct":"b64...","tag":"b64...","nonce":"b64..."}` | AES-GCM authenticated encryption |
| Body is raw base64 blob, no JSON structure | Custom encode or simple symmetric encryption |
| Request header contains `X-Signature` or `X-MAC` | Body signing (plaintext visible, signature validation) |

### Dynamic analysis (Frida probe)

Hook common crypto APIs to confirm and log:

```javascript
// Android: javax.crypto.Cipher
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function(input) {
        var mode = this.getOpMode();  // 1=ENCRYPT, 2=DECRYPT
        console.log("[Cipher] mode=" + mode + " algo=" + this.getAlgorithm());
        console.log("[Cipher] plaintext: " + Java.use("java.lang.String").$new(input));
        return this.doFinal(input);
    };
});
```

```javascript
// iOS: CCCrypt
Interceptor.attach(Module.findExportByName(null, "CCCrypt"), {
    onEnter: function(args) {
        this.op = args[0].toInt32();  // 0=encrypt, 1=decrypt
        this.algo = args[1].toInt32(); // 0=AES, ...
        this.dataIn = args[3];
        this.dataInLen = args[4].toInt32();
        console.log("[CCCrypt] op=" + this.op + " algo=" + this.algo + " len=" + this.dataInLen);
    }
});
```

## Step 2: Choose interception strategy

### Strategy A: Frida hook at the crypto boundary (recommended)

Hook the encryption function and the decryption function. Log plaintext on both sides. This lets you see every request/response in clear.

```javascript
// Generic pattern: hook the function that receives plaintext JSON and returns ciphertext
// Identify it from Step 1's static analysis

Java.perform(function() {
    var CryptoHelper = Java.use("com.app.crypto.CryptoHelper");
    
    // Hook encrypt to see outgoing plaintext
    CryptoHelper.encrypt.implementation = function(plaintext) {
        console.log("[ENCRYPT] plaintext: " + plaintext);
        // Optionally MODIFY the plaintext here for testing
        // plaintext = plaintext.replace('"userId":"123"', '"userId":"456"');
        var result = this.encrypt(plaintext);
        console.log("[ENCRYPT] ciphertext: " + result);
        return result;
    };
    
    // Hook decrypt to see incoming plaintext
    CryptoHelper.decrypt.implementation = function(ciphertext) {
        var result = this.decrypt(ciphertext);
        console.log("[DECRYPT] plaintext: " + result);
        return result;
    };
});
```

With this approach, modify the plaintext before it gets encrypted. The app's own crypto layer wraps your modified payload correctly.

### Strategy B: Build a proxy encryption script

When you have the key material (extracted from the binary or heap), build a Python script that wraps/unwraps payloads. Use it as a Burp extension or standalone proxy.

```python
#!/usr/bin/env python3
"""Encrypt/decrypt API payloads for manual testing.

Usage:
  # Encrypt a modified plaintext for replay
  python3 crypto_proxy.py encrypt '{"userId":"456","action":"transfer"}'
  
  # Decrypt a captured response
  python3 crypto_proxy.py decrypt '<base64_blob>'
"""
import sys, json, base64, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Key material extracted from the app (see flutter-dart-heap-rsa-carve or static analysis)
KEY = bytes.fromhex("...")  # 32 bytes for AES-256
IV  = bytes.fromhex("...")  # 16 bytes (or per-request if envelope scheme)

def encrypt_payload(plaintext_json):
    ct = AES.new(KEY, AES.MODE_CBC, IV).encrypt(pad(plaintext_json.encode(), 16))
    return base64.b64encode(ct).decode()

def decrypt_payload(b64_blob):
    ct = base64.b64decode(b64_blob)
    return unpad(AES.new(KEY, AES.MODE_CBC, IV).decrypt(ct), 16).decode()

if __name__ == "__main__":
    op, data = sys.argv[1], sys.argv[2]
    if op == "encrypt":
        print(encrypt_payload(data))
    elif op == "decrypt":
        print(decrypt_payload(data))
```

Adapt the script to the specific scheme (add RSA wrapping of AES key, HMAC computation, custom encoding).

### Strategy C: Burp extension with auto-decrypt/re-encrypt

For heavy testing, wrap the proxy script as a Burp extension that automatically decrypts requests in the proxy history and re-encrypts modified requests on send.

## Step 3: Test server-side vulns through the crypto layer

With the interception in place, test standard server-side vulnerabilities:

### IDOR
```
# Original plaintext: {"userId":"123","accountId":"ACC-001"}
# Modified plaintext:  {"userId":"123","accountId":"ACC-002"}
# Encrypt the modified version and send
```

### Business logic
```
# Original: {"amount":100,"currency":"USD","fromAccount":"mine"}
# Modified: {"amount":-100,"currency":"USD","fromAccount":"mine"}  // negative transfer
# Or:       {"amount":100,"currency":"USD","fromAccount":"theirs"} // unauthorized source
```

### SQLi
```
# Original: {"searchTerm":"john"}
# Modified: {"searchTerm":"john' OR '1'='1"}
```

### Rate-limit bypass
```
# Replay the same encrypted request rapidly (encryption is deterministic with same key/IV)
# Or forge new requests with different nonces to test per-request rate limiting
```

## Step 4: Verify the crypto is not just obfuscation

Check whether the crypto actually provides security or is just obscurity:

- **Hardcoded key?** If the key is in the binary, the encryption provides zero security (any attacker can extract it)
- **Key per session vs key per request?** Session keys can be reused across requests
- **Is the key derived from user input?** (PIN, password): if so, brute-force may be viable
- **Does the server validate the crypto or just decrypt?** Some servers accept any valid ciphertext regardless of who encrypted it

## Expected output

- Plaintext request/response logs showing all API fields
- Modified payloads that pass server-side decryption
- Server-side vulnerability findings (IDOR, SQLi, etc.) that would be invisible without crypto interception

## Limitations

- If the app uses certificate pinning AND the crypto is tied to a TLS session key, you need to bypass pinning first (see `flutter-ssl-bypass-patternscan` or `mob-enabling`)
- If the server uses per-request challenge-response (server sends nonce, client signs response), simple replay/modification may not work: you need to participate in the handshake
- If the app uses code obfuscation heavily, finding the crypto functions for hooking may require significant reverse engineering
- Envelope schemes with RSA require the public key for forging: if the key rotates, re-extract it (see `crypto-hardening-retest`)
