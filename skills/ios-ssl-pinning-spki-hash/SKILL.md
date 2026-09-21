---
name: ios-ssl-pinning-spki-hash
description: Use when an iOS app implements SSL pinning by comparing SPKI SHA-256 hashes in URLSession:didReceiveChallenge:completionHandler: and you need to MITM its HTTPS traffic. Hooks the delegate or patches verifyCertificate to accept any certificate. Triggers - "SPKI", "ssl pinning", "INVALID SIGNATURE", "base64 hash", "verifyCertificate", "SecTrustEvaluateWithError"
platform: [ios]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---

# Skill: ios-ssl-pinning-spki-hash

## What it is
iOS apps that do **SSL pinning** by comparing the certificate's SPKI
(SubjectPublicKeyInfo) SHA-256 against hard-coded base64 hashes. The pin
check lives in `URLSession:didReceiveChallenge:completionHandler:` and calls
`SecTrustEvaluateWithError` / `SecTrustCopyKey` + `SecKeyCopyExternalRepresentation`,
then hashes the public key and string-compares to the pinned base64.

## When to use it
- The app's `URLSession` delegate implements
  `URLSession:didReceiveChallenge:completionHandler:`.
- Binary contains one or more base64 strings of length 43-44 ending in `=`
  (SHA-256 base64 = 44 chars; SHA-256 base64url varies).
- You need to MITM the app's HTTPS traffic (Burp/mitmproxy) but the app
  refuses the cert with a custom error like "INVALID SIGNATURE".

## Steps

### 1) Find the pinned hashes
```bash
rabin2 -zz Vault.debug.dylib | grep -E '\b[A-Za-z0-9+/]{42,44}={0,2}\b'
# e.g.:
# AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
# BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
```
Find the xref of each hash string to locate `verifyCertificate`:
```bash
r2 -q -e bin.relocs.apply=true -c 'aaa 2>/dev/null; axt @ 0x0001c440' Vault.debug.dylib
# -> sym.Vault.ViewController.verifyCertificate... 0x1188c
```

### 2) Decode the hashes to confirm they're SPKI SHA-256
```python
import base64, hashlib
h = base64.b64decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
print(len(h), h.hex())   # 32 bytes = SHA-256
```
32 bytes ⇒ SHA-256. 20 bytes ⇒ SHA-1. The hash is compared against
`SHA256(SPKI)` of the leaf or intermediate cert.

### 3) Bypass via Frida (single hook)
Hook the `verifyCertificate` Swift function to always return `true`, OR hook
the URLSession delegate challenge handler to accept any cert:
```javascript
// A) Trust any cert (broadest)
var Resolver = new ApiResolver('objc');
Resolver.enumerateMatches('-[* URLSession:didReceiveChallenge:completionHandler:]', {
    onMatch: function (m) {
        Interceptor.attach(m.address, {
            onEnter: function (args) {
                this.challenge = new ObjC.Object(args[4]);
                this.completion = new ObjC.Block(args[5]);
            },
            onLeave: function () {
                var creds = this.challenge.proposedCredential();
                // 0 = useCredential, 1 = performDefaultHandling, 2 = cancelAuthenticationChallenge
                // Build an NSURLCredential from the server trust
                var trust = this.challenge.protectionSpace().serverTrust();
                var cred = ObjC.classes.NSURLCredential.credentialForTrust_(trust);
                this.completion.implementation(0, cred);
            }
        });
    },
    onComplete: function () {}
});
```
Or the surgical patch: find `verifyCertificate` by xref of the base64 hash
and replace its first instruction with `mov w0, #1 ; ret`:
```
0x0000aa  20 00 80 52   mov w0, #1
0x0000ae  c0 03 5f d6   ret
```
```bash
r2 -qw -c 'wx 20008052c0035fd6 @ sym.Vault.ViewController.verifyCertificate' Vault.debug.dylib
```

### 4) Then MITM
Point the device at your Burp/mitmproxy proxy (Settings → Wi-Fi → HTTP
Proxy), install the proxy's CA on device (or use Frida to bypass trust), and
the app will now accept the proxy's cert.

## Traps & edge cases

- **Two hashes = two pins**: the second is usually a backup pin on the
  intermediate cert (so leaf rotation doesn't break the app). To bypass,
  you must defeat BOTH comparisons. The cleanest single hook is the
  `URLSession:didReceiveChallenge:completionHandler:` delegate (one place).
- **`SecTrustEvaluateWithError` system call**: hooking just
  `SecTrustEvaluateWithError` to return `errSecSuccess` is NOT enough if
  the app then independently re-hashes the public key. Always hook the
  app-level `verifyCertificate` function or the delegate.
- **Hash is SHA256(SPKI), not SHA256(cert)**: when generating a proxy cert
  to satisfy a real pin, you'd need the private key of the pinned CA,
  not feasible. The Frida bypass is the practical path.
- **base64 vs base64url**: some apps use base64url (no padding, `-`/`_`).
  Normalize before comparing. The Vault app uses standard base64 with `+`
  and `/` and `=` padding.
- **Async pin evaluation**: the challenge handler runs on a background
  queue. Frida hooks still fire, but ensure your `onLeave` rewrites the
  block call with the correct `ObjC.Block` signature (auth challenge
  disposion + credential).
- **Bypassing pinning ≠ bypassing backend auth**: even with MITM, the
  server may require valid credentials/tokens. Pinning bypass only lets
  you SEE and MODIFY the traffic.