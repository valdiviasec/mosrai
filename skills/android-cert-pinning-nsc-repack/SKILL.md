---
name: android-cert-pinning-nsc-repack
description: Use when an Android app pins certificates via networkSecurityConfig XML (trust-anchors pointing to a raw cert) and Burp gets certificate_unknown. Edit the XML to add user/system CA trust, repack with apktool, zipalign, and re-sign the APK so Burp can intercept HTTPS traffic. Triggers - "network_security_config", "trust-anchors", "NSC repack", "apktool repack", "certificate pinning XML", "Burp certificate_unknown", "APK re-sign", "zipalign"
platform: [android]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---

# Skill: Android Certificate Pinning: Bypass via Network Security Config Repack

**When:** Android app with `android:networkSecurityConfig` that pins
(`trust-anchors` → `@raw/cert` or `@raw/*`) a domain to a specific cert and
blocks MITM (`certificate_unknown` in Burp). Typical in "Anchored" challenges.

**When NOT:** if the pinning is **code-level** (OkHttp `CertificatePinner`,
custom `X509TrustManager`, Flutter `ssl_pinning`, native `libssl` rebuild).
Then editing the XML is not enough → see skill `android-pinning-frida`.

## Steps

1. `apktool d -f -o out app.apk`
2. Inspect `out/AndroidManifest.xml` →
   `android:networkSecurityConfig="@xml/network_security_config"`.
3. Read `out/res/xml/network_security_config.xml`. If there is a `<trust-anchors>`
   with `<certificates src="@raw/...">` (and no `src="user"`/`src="system"`), it is
   declarative pinning.
4. **Key edit**: add trust in the user CA (Burp):
   ```xml
   <trust-anchors>
     <certificates src="@raw/certificate"/>   <!-- original -->
     <certificates src="user"/>               <!-- ADD -->
     <certificates src="system"/>             <!-- optional, avoids breaking other TLS -->
   </trust-anchors>
   ```
   Brute alternative: change `<domain-config cleartextTrafficPermitted="false">`
   to `true` and/or set `<base-config cleartextTrafficPermitted="true">` (only if
   the server listens on HTTP).
5. `apktool b out -o patched.apk` (apktool leaves `resources.arsc` uncompressed
   → passes the Android 11+ check).
6. Align/sign:
   ```
   zipalign -p 4 patched.apk patched_aligned.apk
   apksigner sign --ks debug.keystore --ks-pass pass:android \
     --ks-key-alias androiddebugkey --out patched-signed.apk patched_aligned.apk
   ```
   (or `keytool -genkey` + `jarsigner` if you do not have `apksigner`).
7. `adb uninstall <pkg>` (the signature changed) → `adb install patched-signed.apk`.
8. Burp: `Proxy → Options → Regenerate CA Certificate` →
   `Import/export CA → Certificate (DER)` → `cert-der.crt`.
9. `adb push cert-der.crt /sdcard/Downloads` →
   `Settings → Security → Encryption & credentials → Install from SD card`.
10. Burp `Intercept on` → fire the request → read headers/body in the target.

## Pitfalls

- **Android 11 (R+)** requires `resources.arsc` *uncompressed* and aligned to
  4 bytes. If `adb install` gives `Failure [-124]`, repack with `resources.arsc`
  in `ZIP_STORED` + `zipalign -p 4` before signing (apktool `b` already does it).
- If after the repack the app **closes** due to root/tool detection, combine with
  `android-antiroot-frida-bypass` or use the Frida route from
  `android-call-jni-natives-directly`.
- The APK signature changes → you must `uninstall` before `install`.
- `<certificates src="user"/>` only works if the Burp CA is installed as a
  **user credential** on the device (the proxy alone is not enough).

## Success signal

Burp goes from `certificate_unknown` to intercepting the request in the target.
