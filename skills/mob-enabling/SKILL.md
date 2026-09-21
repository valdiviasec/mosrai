---
name: mob-enabling
description: Use when setting up a device for security testing: root/jailbreak bypass and SSL pinning bypass. This is Phase 0, the mandatory gate before any hunting begins. No security testing proceeds until enabling is confirmed. Triggers - "enable device", "setup device", "root bypass", "jailbreak bypass", "SSL pinning", "certificate pinning", "proxy setup", "mob-enabling", "Phase 0"
platform: [android, ios]
stack: [any]
category: enabling
tier: A
related: [mob-analyze, mob-flutter, mob-native, mob-react-native, mob-capacitor, mob-retest]
---

# Device Enabling for Security Testing

This skill handles Phase 0 of any mobile security engagement: getting the device into a testable state. Both root/jailbreak bypass and SSL pinning bypass MUST succeed before any hunting begins. Follow the ladders in order: do NOT skip steps or improvise.

## Before you start

Confirm:
1. Target device is connected and accessible (adb/ideviceinfo)
2. Proxy tool is running (Burp/Caido) and configured on the device
3. App is installed on the device
4. You know the app's stack (Flutter, React Native, Capacitor, Native): if unknown, run stack detection from mob-analyze first

## Step 1: Root/Jailbreak Bypass

Follow this ladder strictly. Each step is attempted only if the previous one failed.

### Ladder

1. **Generic seeds first:** check `tools/seeds/` for root/jailbreak bypass scripts matching the platform. Load and execute the seed. If the app launches without root/JB detection firing, proceed to Step 2.

2. **Stack-specific skills:** search `SKILL_INDEX.txt` for enabling skills matching the app's stack and platform (e.g., `rootbeer-root-detection-bypass`, `ios-jailbreak-bypass-frida`, `anti-root-bypass-static`). Load the matching skill and follow its instructions.

3. **Derive custom bypass:** if seeds and indexed skills both fail, the app uses custom detection. Triage the decompiled code:
   - Android: search for `RootBeer`, `SafetyNet`, `Play Integrity`, `su`, `/system/app/Superuser`, `com.topjohnwu.magisk`, `test-keys` in jadx output
   - iOS: search for `jailbroken`, `cydia://`, `/Applications/Cydia.app`, `/private/var/lib/apt`, `canOpenURL`, `fork()` in class-dump/Hopper output
   - Identify the detection method and write a targeted Frida hook to bypass it
   - Document the custom bypass logic in `enabling.lock`

4. **Escalate to human:** if custom derivation fails after 3 distinct attempts, STOP. Report what was tried, what failed, and why. Do NOT guess or silently skip.

### Rules for root/JB bypass
- **Deterministic first:** always try seeds before derivation. Seeds are tested; derivation is not.
- **Fail-hard:** if bypass is not confirmed, do NOT proceed. A false negative here wastes the entire engagement.
- **Magisk/Zygisk:** on Android with Magisk, check if DenyList or Zygisk modules (Shamiko, etc.) can hide root before resorting to Frida.

## Step 2: SSL/TLS Pinning Bypass

Follow this ladder strictly. The correct approach depends on the app's stack.

### Ladder

1. **Generic seeds first:** check `tools/seeds/` for SSL bypass scripts. Execute and verify (see Step 3).

2. **Stack-specific skills:** search `SKILL_INDEX.txt` for SSL/TLS bypass skills matching the stack. Load and follow.

3. **Derive custom bypass:** triage the decompiled code for the pinning implementation and write a targeted hook.

4. **Escalate to human:** if bypass fails after 3 attempts, STOP and report.

### Stack-specific guidance

**Native Android:**
- OkHttp3 `CertificatePinner`: hook `CertificatePinner.check()` to return without throwing
- `HttpsURLConnection` with custom `HostnameVerifier`: hook the verifier to return true
- Custom `X509TrustManager`: hook `checkServerTrusted()` to return without throwing
- Network Security Config: if `res/xml/network_security_config.xml` exists, check for `<pin-set>` directives
- Also check for `TrustManagerFactory` and `SSLContext` custom initialization

**Native iOS:**
- `NSURLSession` delegate with `URLSession:didReceiveChallenge:completionHandler:`: hook to call completionHandler with `.useCredential`
- `SecTrustEvaluate` / `SecTrustEvaluateWithError`: hook to return `errSecSuccess`
- `SSLSetSessionOption` with `kSSLSessionOptionBreakOnServerAuth`: hook to disable
- TrustKit: if present, hook `TSKPinningValidator` methods
- ATS exceptions in Info.plist: check `NSAppTransportSecurity` settings

**Flutter:**
- Generic SSL hooks DO NOT work on Flutter. Flutter uses its own BoringSSL library compiled into the Flutter engine, bypassing platform HTTP stacks entirely.
- MUST use the `flutter-ssl-bypass-patternscan` skill, which scans `libflutter.so` / `Flutter.framework` for the `ssl_crypto_x509_session_verify_cert_chain` function pattern and hooks it directly.
- If pattern-scan fails (engine version mismatch), extract the Flutter engine version and search for known offsets.

**React Native:**
- RN typically uses the platform's HTTP stack (OkHttp on Android, NSURLSession on iOS), so generic SSL bypass usually works.
- Exception: apps using `react-native-ssl-pinning` or `react-native-pinch`: these implement custom pinning. Check `node_modules` or the JS bundle for these imports.
- Try generic hooks first. If they fail, check for custom pinning libraries.

**Capacitor/Cordova:**
- WebView-based apps use the platform WebView (WKWebView on iOS, Android WebView on Android).
- System-level proxy settings or VPN-based proxy (e.g., Proxyman) capture WebView traffic.
- SSL pinning in Capacitor is rare but possible via plugins like `cordova-plugin-advanced-http` or `capacitor-ssl-pinning`. Check plugin list.
- If the app uses a native HTTP plugin that bypasses the WebView, treat it like a native app for SSL bypass.

## Step 3: Verification

This is the gate check. Do NOT skip it.

1. Launch the app on the device
2. Trigger a network request (login screen, API call, splash screen fetch)
3. Check the proxy (Burp/Caido) for the request
4. **Pass condition:** the request appears in the proxy with full request/response visible
5. **Fail condition:** no traffic, or only non-app traffic (Google, Firebase noise)

If verification fails:
- Check proxy configuration (correct IP, port, CA cert installed)
- Check if app uses certificate transparency or additional validation
- Retry with a different bypass approach from the ladder
- After 3 failed verification attempts: **STOP and escalate to human**

## Step 4: Lock

Once both bypasses are verified:

1. Write `enabling.lock` in the engagement directory with:
   - Device model and OS version
   - App package name and version
   - Root/JB bypass method used (seed name or custom script path)
   - SSL bypass method used (seed name or custom script path)
   - Frida version used
   - Proxy tool and configuration
   - Date and tester
2. The lock file must be **replay-deterministic**: running the scripts in the lock file on the same device/app version must reproduce the enabled state.
3. Update `engagement.state`: set `enabling.status: active`

## Rules (always active)

- **Deterministic first:** seeds before derivation. Always.
- **Fail-hard:** do not silently skip a failed bypass. If it does not work, stop and report.
- **Document everything:** every attempt, success or failure, goes into `enabling.lock` or the engagement log.
- **No guessing:** if you are unsure whether a bypass worked, verify it. If verification is ambiguous, escalate.
- **Stack matters:** the correct SSL bypass depends entirely on the stack. Flutter MUST use BoringSSL pattern-scan. Do not waste time trying generic hooks on Flutter.
- **Reproducibility:** another tester must be able to replay your enabling from the lock file alone, without reading the engagement notes.
