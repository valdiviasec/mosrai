---
name: android-ssl-pinning-bypass
description: 'Use when you need to bypass real Android certificate pinning (OkHttp CertificatePinner, TrustKit, X509TrustManagerExtensions, Network Security Config pin-set) with Frida or objection to MITM a pinned app. Not for TrustAll (use android-tls-mitm). Triggers - "ssl pinning bypass", "bypass cert pinning android", "okhttp certificate pinner", "trustkit bypass", "network security config pin-set"'
platform: [android]
stack: [native, react-native]
category: enabling
kind: primitive
tier: A
related: [android-tls-mitm]
---

## Ladder (enabling · Phase 0)

1. **FAST PATH (deterministic):** run the seed for the detected stack from `tools/seeds/` (see "Frida scripts per stack") -> verify that traffic flows. If it works -> done; record it in `enabling.lock`.
2. **TRIAGE (the seed did not take):** the static analysis in "When to use" identifies the implementation (CertificatePinner / TrustKit / NSC pin-set / custom).
3. **DERIVE (never-before-seen custom impl.):** invariant -> there is ONE function that validates the chain and returns/throws; locate it and hook it to accept (the patterns below are templates).
4. **ESCALATE (ambiguous):** flag to the operator with the candidate class/method + snippet.
5. **CAPTURE:** on resolution, draft the variant into the pack; the exact hook goes into `enabling.lock`.

# SKILL: android-ssl-pinning-bypass

> Skill to bypass real **certificate pinning** (not TrustAll). When the app
> DOES validate certificates but only accepts specific (pinned) ones.
>
> **Trigger**: "ssl pinning bypass", "bypass cert pinning android", "okhttp
> certificate pinner", "x509trustmanager pinning", "trustkit bypass".

## When to use

- Static analysis shows `CertificatePinner` (OkHttp), `TrustKit`,
  `X509TrustManagerExtensions.checkServerTrusted` with pins, or `Network Security
  Config` with `<pin-set>`.
- The app rejects the MITM proxy certificate with `CertificateException` or
  `PeerCertificateVerifier`.

## Do not use if

- The app uses TrustAllManager (there is no pinning to bypass). Use
  `android-tls-mitm`.

## Frida scripts per stack

### OkHttp 2/3 CertificatePinner

```javascript
// OkHttp 3
var CertificatePinner = Java.use('okhttp3.CertificatePinner');
CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(a,b){ return; };
CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(a,b){ return; };

// OkHttp 2
var CertificatePinner2 = Java.use('com.squareup.okhttp.CertificatePinner');
CertificatePinner2.check.implementation = function(a,b){ return; };
```

### TrustKit / X509TrustManagerExtensions

```javascript
var TME = Java.use('android.net.http.X509TrustManagerExtensions');
TME.checkServerTrusted.implementation = function(chain, authType, host) {
    return Java.use('java.util.Collections').emptyList();
};

var TrustKit = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
TrustKit.verify.implementation = function(a,b){ return true; };
```

### Network Security Config with pin-set

```javascript
// Hook the NetworkSecurityConfig that validates pins
var NSC = Java.use('android.security.net.config.NetworkSecurityConfig');
NSC.$init.implementation = function() {
    this.$init();
    // Disable pins
};
```

### Universal (objection)

```bash
objection -g PACKAGE_NAME explore --startup-command "android sslpinning disable"
```

## Pipeline

1. Static analysis: search for `CertificatePinner`, `pin-set`, `<pin digest=`.
2. Start frida-server on the device.
3. Stand up the MITM proxy.
4. Spawn the app with the bypass script loaded.
5. Interact and capture traffic.

## Verification

- If the app stops rejecting the proxy cert → successful bypass.
- logcat: `PeerCertificateVerifier` / `CertificatePinner.check` errors disappear.
