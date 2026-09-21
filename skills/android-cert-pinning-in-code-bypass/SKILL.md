---
name: android-cert-pinning-in-code-bypass
description: Use when an Android app does certificate pinning in Java code (KeyStore + TrustManagerFactory + SSLContext) instead of via networkSecurityConfig XML, causing Burp to get certificate_unknown. This skill covers two routes: static (reconstruct the secret from decompiled crypto logic without bypassing TLS) and dynamic (hook SSLContext.init / TrustManager with Frida to accept Burp CA). Triggers - "cert pinning code", "TrustManagerFactory", "SSLContext bypass", "certificate_unknown", "KeyStore pinning", "in-code pinning", "X509TrustManager hook", "Burp certificate rejected"
platform: [android]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---

# Skill: Android In-Code Certificate Pinning: Bypass & Static Secret Recovery

**When:** Android app that does *certificate pinning* **in code** (not in
`networkSecurityConfig`): loads a cert from `res/raw/*` (or `assets/`) and
builds a custom `KeyStore` + `TrustManagerFactory` + `SSLContext` in an
activity/SDK, so that `HttpsURLConnection.setSSLSocketFactory(...)` only
accepts the embedded cert. Burp gets `certificate_unknown` and the manifest
does **not** reference any `networkSecurityConfig`.

**When NOT:** **declarative** pinning via `<trust-anchors>` in
`res/xml/network_security_config.xml` → see skill
`android-cert-pinning-nsc-repack`. Pinning in libraries (OkHttp
`CertificatePinner`, `Conscrypt`, Flutter `ssl_pinning`, TrustKit) →
`objection android sslpin disable` or hook the specific API.

## Quick signs of "pinning in code"

- `AndroidManifest.xml` **without** `android:networkSecurityConfig`.
- `res/raw/*.der` / `*.pem` / `*.cer` / `*.bks` / `*.p12` (embedded cert/keystore).
- In code: `CertificateFactory.getInstance("X.509").generateCertificate(
  getResources().openRawResource(R.raw.<x>))` → `KeyStore.setCertificateEntry`
  → `TrustManagerFactory.init(ks)` → `SSLContext.init(null, tmf, null)` →
  `HttpsURLConnection.setSSLSocketFactory(ctx.getSocketFactory())`.
- Sometimes a double-check: `conn.getServerCertificates()[0].toString()
  .equals(bundledCert.toString())` → `throw` if it does not match.

## Two resolution routes

### Route A: Static: if the secret is built in Java (preferred when there is no native code)
Pinning only protects the **transport**. If the secret value (password,
token, flag) is assembled/decrypted **in the app** before being sent,
replicate that logic outside the app and you skip the pinning entirely.

1. `jadx`/`apktool d` → locate the method that builds the body/headers.
2. Textually reconstruct the calls to obfuscated getters
   (`algo.a()` that returns `arrayList.get(N)`). Resolve each `get(N)`
   by reading the corresponding getter.
3. Replicate `Cipher.getInstance("AES")` (=> AES/ECB/PKCS5Padding),
   `Base64.decode(...,0)`, `new SecretKeySpec(keyBytes,"AES")`,
   `cipher.init(Cipher.DECRYPT_MODE=2, key)`.
   In Python: `AES.new(key, AES.MODE_ECB)` + `unpad(...,16)`.
4. The decrypted result = secret/flag. Verify the prefix/closing brace
   (`HTB{...}`) and valid PKCS5 padding (byte `0xNN` repeated `NN` times).

> Tip: check **every** `charAt(k)` against the full literal string;
> the typical mistake is misreading an index (e.g. `"zlg4rj".charAt(3)='4'`, not
> `'g'`). If padding fails, re-check the indices before switching approaches.

### Route B: Dynamic: break the pinning and read the request
1. `frida-server` running on the emulator; Burp as proxy with its CA.
2. Burp → `Regenerate CA Certificate` → export DER (`cert-der.crt`).
3. Bypass the in-code `TrustManager`. Options:
   - `objection -g <pkg> explore` → `android sslpin disable`.
   - Frida script that replaces `SSLContext.init` / the `X509TrustManager`
     returned by `TrustManagerFactory.getTrustManagers()` with one whose
     `checkClientTrusted/checkServerTrusted` are no-ops.
   - "Cheap" trick: replace `res/raw/<cert>.der` with the Burp CA and
     `apktool b` + sign (works if the code only loads that raw resource and
     there is no extra cert hash).
4. Trigger the app action → Burp intercepts the body/headers in the target.

## Pitfalls
- **Double pinning:** besides the `SSLContext`, the app revalidates
  `conn.getServerCertificates()[0]` against the embedded one in the callback.
  Hook that comparison too or disable the check.
- **Embedded cert with a private key inside the APK** (trap variant): if
  you find `key.pem`/PKCS8 in `assets` or `res/raw`, you could stand up a
  MITM server signed with that key → no repack needed. Always check.
- **Anti-Frida/anti-root in `onCreate`:** combine with an anti-analysis
  bypass or use the static route (A) which does not touch the runtime.
- **Obfuscated native:** if the secret comes from `lib*.so` (XOR/AES in C),
  the Java static route is not enough → call the exported JNI functions
  with Frida (skill `android-call-jni-natives-directly`).

## Success signal
- Static: decryption with valid PKCS5 padding and a string with the `HTB{`
  prefix / expected format.
- Dynamic: Burp goes from `certificate_unknown` to intercepting the request
  in the target; the `pass=`/header = secret.
