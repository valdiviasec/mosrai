---
name: mob-native
description: Use when the target app is native Android (Java/Kotlin) or iOS (Swift/ObjC). Covers platform-specific decompilation, manifest/entitlements analysis, storage auditing, auth bypass, Frida hooking, and IPC attack surfaces. Triggers - "native app", "java app", "kotlin app", "swift app", "objective-c app", "jadx", "class-dump", "native android", "native ios", "mob-native"
platform: [android, ios]
stack: [native]
category: recon
tier: A
related: [mob-analyze, mob-enabling, mob-retest]
---

# Native App Security Assessment

This skill orchestrates recon and hunting for native Android (Java/Kotlin) and iOS (Swift/ObjC) apps. Native apps have the widest attack surface and the most mature tooling. The platform determines the tools and techniques.

## Step 1: Decompilation

### Android (Java/Kotlin)

**Primary: jadx**
```
jadx -d /tmp/re_<appname>/ app.apk
```
- Produces readable Java source from DEX bytecode
- Handles most ProGuard obfuscation (renamed classes/methods, but logic is intact)
- Output includes `AndroidManifest.xml`, resources, and decompiled source

**Supplementary: apktool**
```
apktool d app.apk -o /tmp/re_<appname>/apktool_out/
```
- Produces smali (Dalvik assembly): useful when jadx decompilation fails or is ambiguous
- Preserves exact resource structure, required for repackaging
- Use for smali patching when Frida is not an option

**Obfuscated code:** if ProGuard/R8 mapping file is available (rare in pentest), use it to de-obfuscate. Otherwise:
- jadx handles renamed identifiers; logic is readable
- For string encryption: search for decryption routines, hook them with Frida
- For class-level obfuscation (DexGuard, Arxan): search SKILL_INDEX.txt for specific bypass skills

**Multi-DEX:** jadx handles multi-DEX automatically. For manual inspection: `dex2jar` on each `classes*.dex`, then `jd-gui` or `cfr`.

### iOS (Swift/ObjC)

**ObjC apps:**
- `class-dump` extracts Objective-C headers (class names, method signatures, properties, protocols)
- This gives the app's full API surface without decompiling the binary
- For implementation details: Hopper Disassembler or Ghidra

**Swift apps:**
- `class-dump` has limited Swift support (Swift classes bridged to ObjC show up, pure Swift may not)
- Hopper: decompiles ARM64 to pseudo-code, handles Swift name demangling
- Ghidra: free alternative, requires Swift demangler plugin for best results
- `swift-demangle` on extracted symbol table: `nm -g App | swift-demangle`

**Both:**
- Extract `Info.plist` for app configuration, URL schemes, ATS settings
- Check `embedded.mobileprovision` for entitlements (Keychain groups, app groups, push notifications)
- `codesign -d --entitlements :- App.app` for full entitlements list

## Step 2: Manifest and Configuration Analysis

### Android: AndroidManifest.xml

Critical items to extract and document:

1. **Exported components:** activities, services, broadcast receivers, content providers with `exported="true"` or intent-filters (implicit export)
   - Each exported component is a potential entry point for other apps
   - Activities: check for auth bypass via direct intent launch
   - Services: check for bound services exposing sensitive operations
   - Content providers: check for SQL injection, path traversal
   - Broadcast receivers: check for intent injection

2. **Permissions:**
   - Dangerous permissions: `CAMERA`, `RECORD_AUDIO`, `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, `READ_EXTERNAL_STORAGE`
   - Custom permissions: check protection level (`normal` vs `signature` vs `dangerous`)
   - Missing permissions: operations that should require a permission but don't

3. **Intent-filters:**
   - Deep links: `<data android:scheme="..." android:host="..."/>`
   - Custom schemes: potential for link hijacking
   - Implicit intents: potential for intent interception

4. **Flags:**
   - `android:allowBackup="true"`: data extractable via `adb backup`
   - `android:debuggable="true"`: full debugging access (rare in production, critical if present)
   - `android:usesCleartextTraffic="true"`: HTTP allowed
   - `android:networkSecurityConfig`: pointer to NSC XML

### iOS: Info.plist and Entitlements

1. **URL schemes:** `CFBundleURLTypes`: custom URL schemes the app handles
2. **Universal Links:** `com.apple.developer.associated-domains` entitlement
3. **ATS:** `NSAppTransportSecurity`: check for `NSAllowsArbitraryLoads`, per-domain exceptions
4. **Background modes:** `UIBackgroundModes`: what the app does in background
5. **Keychain sharing:** `keychain-access-groups` entitlement: which apps share Keychain data
6. **App groups:** `com.apple.security.application-groups`: shared container access

## Step 3: Common Attack Surfaces

### Local Storage

**Android:**
- `SharedPreferences`: XML files in `/data/data/<pkg>/shared_prefs/`. Check for tokens, credentials, PII in plaintext.
- `SQLite` / `Realm`: databases in `/data/data/<pkg>/databases/`. Check for unencrypted sensitive data, SQL injection in ContentProviders.
- Internal storage files: `/data/data/<pkg>/files/`. Check for cached credentials, session data.
- External storage: world-readable on older Android versions. Check for sensitive data written to SD card.
- `EncryptedSharedPreferences` / `EncryptedFile`: verify the master key is properly managed via Android Keystore.

**iOS:**
- `NSUserDefaults`: plist in app sandbox. Check for tokens, credentials, PII.
- `Keychain`: use `keychain-dumper` (jailbroken) or Frida to enumerate entries. Check accessibility flags (`kSecAttrAccessibleWhenUnlocked` vs `kSecAttrAccessibleAlways`).
- `CoreData` / `SQLite`: databases in app sandbox. Same checks as Android.
- `FileProtection`: check file protection class on sensitive files (`NSFileProtectionComplete` is the strongest).

### Keystore / Keychain

**Android Keystore:**
- Keys should be hardware-backed (TEE/StrongBox)
- Check for `setUserAuthenticationRequired`: does key use require biometric/PIN?
- Check for `setKeyValidityForOriginationEnd`: key rotation
- Hook `KeyStore.getInstance` and `Cipher.init` with Frida to observe key usage

**iOS Keychain:**
- Check `kSecAttrAccessible` values: `kSecAttrAccessibleAlways` is insecure
- Check for `kSecAttrAccessControl` with biometric binding
- Verify `kSecAttrSynchronizable`: if true, data syncs to iCloud Keychain

### WebView Bridges

**Android:**
- `addJavascriptInterface` exposes Java methods to JavaScript: check for sensitive operations
- `WebViewClient.shouldOverrideUrlLoading`: check for URL validation
- `setAllowFileAccessFromFileURLs` / `setAllowUniversalAccessFromFileURLs`: if true, XSS can read local files
- `WebChromeClient.onJsPrompt/onJsAlert`: potential bridge via prompt/alert

**iOS:**
- `WKScriptMessageHandler`: `userContentController:didReceiveScriptMessage:` exposes native methods to JS
- `WKNavigationDelegate`: check URL validation in `decidePolicyForNavigationAction`
- `evaluateJavaScript`: native code injecting JS into the WebView
- `javaScriptEnabled`: should be false unless required

## Step 4: Auth Patterns

### Biometric Bypass

**Android:**
- `BiometricPrompt` with `CryptoObject`: cryptographic binding (stronger)
- `BiometricPrompt` without `CryptoObject`: event-based (bypassable)
- Hook `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded` to bypass
- Check if biometric success merely sets a boolean flag (trivially bypassable)

**iOS:**
- `LAContext.evaluatePolicy`: event-based (bypassable by hooking completion handler)
- `LAContext.evaluateAccessControl` with `SecAccessControl`: Keychain-bound (stronger)
- Hook `evaluatePolicy:localizedReason:reply:` to call reply block with success=YES
- Check if the app validates the biometric result server-side (rare, but ideal)

### Token Storage

- Where are auth tokens stored? (SharedPrefs/Keychain/SQLite/memory)
- Are tokens encrypted at rest?
- Token expiry: does the app check expiry client-side or server-side?
- Refresh tokens: same storage scrutiny as access tokens
- Session fixation: can a token from one session be reused in another?

### Session Management

- How does logout work? (token invalidated server-side, or just cleared locally?)
- Concurrent sessions: can the same account have multiple active sessions?
- Session timeout: does the app enforce idle timeout?

## Step 5: Frida Hooking

### Android

```javascript
Java.perform(function() {
    // Hook a specific method
    var TargetClass = Java.use('com.example.app.ClassName');
    TargetClass.methodName.implementation = function(arg1, arg2) {
        console.log('methodName called:', arg1, arg2);
        var result = this.methodName(arg1, arg2);
        console.log('methodName returned:', result);
        return result;
    };
});
```

- `Java.perform` for all Java/Kotlin hooking
- `Java.choose` to find live instances of a class
- `Java.enumerateLoadedClasses` to discover class names (useful for obfuscated apps)
- For native methods: `Interceptor.attach` on JNI function pointers

### iOS

```javascript
// ObjC method hooking
var ClassName = ObjC.classes.ClassName;
Interceptor.attach(ClassName['- methodName:'].implementation, {
    onEnter: function(args) {
        console.log('methodName called:', ObjC.Object(args[2]));
    },
    onLeave: function(retval) {
        console.log('methodName returned:', ObjC.Object(retval));
    }
});
```

- `ObjC.classes` for Objective-C class enumeration
- `ObjC.protocols` for protocol enumeration
- For Swift: use demangled names, hook via `Module.findExportByName`
- Swift method names include the module prefix: `$s<module><class><method>...`

## Step 6: IPC Attack Surfaces

### Android

1. **Intents:** craft intents to exported components. Test with `adb shell am start/broadcast/startservice`
2. **Broadcast receivers:** register for broadcasts the app sends. Check for sensitive data in broadcast extras.
3. **Bound services:** bind to exported services. Check AIDL interfaces for sensitive operations.
4. **Content providers:** query exported providers. Test for SQL injection, path traversal, permission bypass.
5. **Deep links:** test custom URL schemes and App Links for auth bypass, data exfiltration.
6. **PendingIntents:** search for `PendingIntent` with implicit intents: hijackable by malicious apps.

### iOS

1. **URL schemes:** test custom URL scheme handlers for input validation. Open via `xcrun simctl openurl` or Safari.
2. **Universal Links:** check AASA (Apple App Site Association) file for associated domains.
3. **App extensions:** check share extensions, today widgets, notification content for data leakage.
4. **Pasteboard:** check if the app copies sensitive data to the general pasteboard (`UIPasteboard.general`).
5. **Handoff / Continuity:** check for sensitive data in NSUserActivity.

## Rules (always active)

- **jadx for Android, class-dump/Hopper for iOS:** deterministic tool selection based on platform.
- **Output to /tmp:** all decompilation output goes to `/tmp/re_<appname>/`.
- **Exported = entry point:** every exported component must be tested. No exceptions.
- **Storage is guilty until proven innocent:** assume all local storage is insecure until verified otherwise.
- **Biometric is UI, not security:** unless biometric result is cryptographically bound (CryptoObject/SecAccessControl), it is bypassable. Document the bypass.
- **Document IPC surface:** every intent-filter, URL scheme, and content provider goes into the engagement surface map.
