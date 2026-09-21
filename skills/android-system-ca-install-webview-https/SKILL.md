---
name: android-system-ca-install-webview-https
description: Use when an Android WebView (targetSdk >= 28) rejects your self-signed HTTPS cert because it only trusts the system CA store; installs your CA as a system-level trusted root so the WebView loads your attacker-hosted page without SSL errors. Triggers - "net_error -202", "Trust anchor not found", "ERR_CERT_AUTHORITY_INVALID", "system CA install", "WebView HTTPS self-signed", "usesCleartextTraffic false"
platform: [android]
stack: [native]
category: enabling
tier: A
related: []
kind: enabling
---

# Skill: System CA install (Android 11) so the WebView trusts your self-signed CA

## When to use
You need an Android WebView (app with `usesCleartextTraffic="false"` and no `networkSecurityConfig` allowing user CAs) to load your HTTPS page with a self-signed cert. An app with `targetSdk >= 28` does NOT trust the user CA store by default → the WebView aborts the TLS handshake (`net_error -202, Trust anchor for certification path not found`). Hooking `WebViewClient.onReceivedSslError` with Frida does NOT always work because SSL errors from the system WebView (Chrome/X5 fallback) are handled at the native level (Cronet/Chromium) and never reach the Java callback.

Triggers: `net_error -202`, `Trust anchor for certification path not found`, `ERR_CERT_AUTHORITY_INVALID`, WebView won't load self-signed HTTPS, `usesCleartextTraffic=false`.

## Steps

### 1. Generate CA + cert for the attacker host
```bash
openssl req -x509 -newkey rsa:2048 -keyout c2_key.pem -out c2_cert.pem \
  -days 365 -nodes \
  -subj "/CN=192.168.x.x" \
  -addext "subjectAltName=IP:192.168.x.x,DNS:your.domain"
```
If the cert is only for CN without SAN, Chrome rejects it for missing Subject Alt Name.

### 2. Compute the CA name hash (Android format)
```bash
HASH=$(openssl x509 -in c2_cert.pem -noout -subject_hash_old)
cp c2_cert.pem "${HASH}.0"
```
Android expects the cert at `/system/etc/security/cacerts/<subject_hash_old>.0`.

### 3. Copy the cert to the device
```bash
adb push "${HASH}.0" /sdcard/
```

### 4. tmpfs overlay over the system CA store (Android 11, root)
`/system` is read-only. Mount tmpfs over the CA dir, copy ALL the original CAs plus ours:
```bash
adb shell "su 0 sh -c '
  # Backup the original CAs to /data/local/tmp
  mkdir -p /data/local/tmp/syscas
  cp /system/etc/security/cacerts/*.0 /data/local/tmp/syscas/
  # Mount tmpfs over the dir
  mount -t tmpfs tmpfs /system/etc/security/cacerts
  # Copy all the originals plus ours
  cp /data/local/tmp/syscas/*.0 /system/etc/security/cacerts/
  cp /sdcard/${HASH}.0 /system/etc/security/cacerts/
  chmod 644 /system/etc/security/cacerts/*.0
  chown root:root /system/etc/security/cacerts/*.0
  ls /system/etc/security/cacerts/ | wc -l   # must be N+1
'"
```
Key point: copy the originals FIRST (otherwise the empty tmpfs breaks validation for every other TLS connection).

### 5. Restart the app and verify
The WebView should pick up the new CAs at startup. Force-stop and relaunch the app:
```bash
adb shell am force-stop <package>
adb shell am start -n <package>/<launcher>
```
Now the WebView loads `https://192.168.x.x:9000/exploit.html` without a cert error.

### 6. (Alternative) Public tunnel with valid TLS
If you do not want to touch the system store, use a tunnel that terminates TLS with a public cert:
```bash
ssh -R 80:localhost:9000 <email>   # gives you https://<random>.lhr.life
```
The WebView trusts Let's Encrypt → you do not need to install anything. Better for "clean" PoCs.

## Pitfalls / edge cases
- **Do not delete the original CAs**: if you mount tmpfs and only copy your cert, the device loses ALL root CAs → all TLS breaks (Play Services, sync, etc.). Always copy the originals first.
- **User CA store is not enough**: `/data/misc/user/0/cacerts-added/` is trusted by apps with `targetSdk < 28` or with an NSC that includes `<certificates src="user"/>`. Modern apps without NSC ignore the user store. Use the system store (tmpfs) or an NSC patch.
- **Cached process**: after installing the CA, the WebView (app) process may have a cached TrustManager. Force-stop + relaunch is required; sometimes a reboot if the cache is stubborn.
- **Android 14+ / magisk**: on Android 14 the path may be `/apex/com.android.conscrypt/cacerts` and you must overlay that APEX. On Android 11 the classic `/system/etc/security/cacerts` still works.
- **`onReceivedSslError` never fires**: if you hooked that method and see no log, it is not that the hook fails: the system WebView aborts the handshake in C++ before calling the Java callback. The CA in the system store fixes the root cause.
- **SAN mandatory**: Chrome/X5 requires Subject Alt Name in the cert. Without `subjectAltName=IP:...,DNS:...`, it fails with `ERR_CERT_COMMON_NAME_INVALID` or similar even if the CN matches.
- **Restore**: when done, `umount /system/etc/security/cacerts` brings back the real CAs (the tmpfs ones are lost on reboot anyway).
