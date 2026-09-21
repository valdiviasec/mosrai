---
name: mob-flutter
description: Use when the target app is built with Flutter/Dart. Covers detection, decompilation with blutter, Dart snapshot analysis, Flutter-specific SSL bypass, and hunting surfaces unique to Flutter apps. Triggers - "flutter app", "dart app", "libflutter.so", "Flutter.framework", "App.framework", "blutter", "flutter analysis", "mob-flutter"
platform: [android, ios]
stack: [flutter]
category: recon
tier: A
related: [mob-analyze, mob-enabling, flutter-ssl-bypass-patternscan, flutter-aot-blutter-frida-hook, flutter-dart-heap-rsa-carve, flutter-bank-rsa-idor]
---

# Flutter App Security Assessment

This skill orchestrates recon and hunting for Flutter/Dart apps. Flutter apps compile Dart to AOT native code, which makes them fundamentally different from other stacks. The tooling, bypass techniques, and attack surfaces are all Flutter-specific.

## Step 1: Detection

Confirm the app is Flutter before proceeding. False positives waste time on the wrong toolchain.

**Android:**
- Unzip the APK and search for `lib/<arch>/libflutter.so` and `lib/<arch>/libapp.so`
- `libflutter.so` = Flutter engine (BoringSSL, Dart VM, Skia)
- `libapp.so` = compiled Dart application code (the AOT snapshot)
- Both must be present for a Flutter app. `libflutter.so` alone could be a false positive (hybrid app with Flutter module)

**iOS:**
- Extract the IPA and search for `Frameworks/Flutter.framework/` and `Frameworks/App.framework/`
- `App.framework/App` is the AOT-compiled Dart code
- Check for `flutter_assets/` directory inside the app bundle

**Hybrid detection:** some apps embed Flutter as a module within a native app. In that case, both Flutter-specific and native analysis apply. Document the hybrid nature in `engagement.state`.

## Step 2: Decompilation

### Dart code: blutter (mandatory)

Use `blutter` to decompile the Dart AOT snapshot. NEVER use jadx for Dart code: jadx cannot parse Dart AOT snapshots and will produce garbage or nothing.

```
blutter libapp.so /tmp/re_<appname>/blutter_out
```

**Output structure:**
- `asm/`: disassembled Dart functions with type annotations
- `pp.txt`: object pool entries (strings, constants, class references)
- `objs.txt`: Dart objects found in the snapshot
- `blutter_frida.js`: auto-generated Frida hooks for discovered functions

**Key files to examine:**
- Function names in `asm/` reveal class structure, method names, and library organization
- `pp.txt` contains string literals, URLs, API keys, and constants embedded in the Dart code
- Look for classes with names like `ApiClient`, `AuthService`, `CryptoHelper`, `StorageManager`

### Native wrapper: jadx (supplementary)

jadx is still useful for analyzing the native Android wrapper:
- `AndroidManifest.xml`: exported components, permissions, intent-filters
- Java/Kotlin bridge code: platform channels implemented on the native side
- `res/xml/network_security_config.xml`: but remember, Flutter ignores this for its own HTTP traffic

For iOS, use `class-dump` or Hopper/Ghidra on the native wrapper alongside blutter output.

## Step 3: Dart Snapshot Analysis

The blutter output requires manual analysis. Dart AOT compilation means:

- **No simple string search for URLs:** URLs are not stored as contiguous strings in the binary. They appear in `pp.txt` as object pool entries or as fragments across multiple pool entries. Search `pp.txt` and `objs.txt`, not the raw binary.
- **Class names are preserved:** Dart AOT retains class and method names (unless obfuscated with `--obfuscate`). Use these to map the app's architecture.
- **Type information is rich:** Dart's type system means blutter output includes parameter types, return types, and field types. This is more information than typical native decompilation provides.

### What to look for

1. **API surface:** grep blutter output for `http`, `https`, `dio`, `HttpClient`, `fetch`, `api`, `endpoint`, `url`, `uri`
2. **Auth flows:** search for `login`, `auth`, `token`, `session`, `jwt`, `oauth`, `credential`, `password`
3. **Crypto usage:** search for `encrypt`, `decrypt`, `aes`, `rsa`, `hmac`, `hash`, `sha`, `md5`, `cipher`, `key`, `iv`, `nonce`, `pointycastle`
4. **Storage:** search for `SharedPreferences`, `Hive`, `Isar`, `sqflite`, `secure_storage`, `flutter_secure_storage`
5. **Sensitive data:** search for `secret`, `private`, `api_key`, `apiKey`, `token`, `bearer`

### Obfuscation check

If class/method names are mangled (single letters, random strings), the app was built with `--obfuscate`:
- Blutter still extracts type information and object pool data
- Focus on `pp.txt` for string literals and constants
- Use dynamic analysis (Frida) to supplement static findings
- Search SKILL_INDEX.txt for obfuscation-specific skills

## Step 4: SSL Bypass

**Critical:** Flutter uses its own BoringSSL library compiled into `libflutter.so` / `Flutter.framework`. The platform HTTP stack (OkHttp, NSURLSession) is NOT used for Flutter's HTTP client (`dart:io` HttpClient, `dio`, `http` package).

- Generic SSL bypass hooks (OkHttp, NSURLSession) DO NOT intercept Flutter HTTP traffic
- MUST use the `flutter-ssl-bypass-patternscan` skill
- The pattern-scan approach locates `ssl_crypto_x509_session_verify_cert_chain` in the Flutter engine by byte pattern matching and hooks it directly
- If the pattern scan fails due to an unusual Flutter engine version, extract the engine version from `libflutter.so` headers and search for known offsets

**Exception:** if the Flutter app uses a platform channel to delegate HTTP requests to the native side (e.g., via `method_channel` calling OkHttp), those requests go through the native stack and generic bypass works for that traffic. Check for both paths.

## Step 5: Flutter-Specific Attack Surfaces

### Platform Channels (MethodChannel / EventChannel / BasicMessageChannel)

Platform channels are the bridge between Dart and native code. They are a key attack surface:
- Search blutter output for `MethodChannel`, `EventChannel`, `BasicMessageChannel`
- Channel names are strings: find them in `pp.txt`
- Data crossing the channel is serialized (StandardMethodCodec or custom). Intercept with Frida on the native side: hook `FlutterMethodChannel` (iOS) or `io.flutter.plugin.common.MethodChannel` (Android)
- Check if sensitive data (tokens, keys, PII) crosses the bridge
- Check if the native side validates data received from Dart

### Custom Serialization

Flutter apps often use custom serialization (not JSON):
- `protobuf` / `grpc`: search for `.proto` definitions or `GeneratedMessage` subclasses
- Custom binary formats: look for `ByteData`, `Uint8List` manipulation in blutter output
- `freezed` / `json_serializable`: code-generated JSON serialization, look for `fromJson`/`toJson`

### dart:ffi Calls

Some Flutter apps call native C/C++ libraries directly via `dart:ffi`:
- Search blutter output for `ffi`, `DynamicLibrary`, `NativeFunction`, `Pointer`
- These calls bypass the Dart type system: potential for memory corruption
- Identify which native library is being called and analyze it separately

### Local Storage

- `SharedPreferences` via Flutter plugin: stored in platform-specific location (Android SharedPrefs XML, iOS NSUserDefaults plist). Unencrypted by default.
- `flutter_secure_storage`: uses Android Keystore / iOS Keychain. Check for fallback to insecure storage on older devices.
- `Hive`: lightweight NoSQL database. Files stored in app directory. Check if encryption is enabled (Hive supports AES-256).
- `Isar`: newer database. Check encryption configuration.
- `sqflite`: SQLite wrapper. Same analysis as native SQLite: check for plaintext sensitive data.

### Firebase / Cloud Services

Many Flutter apps use Firebase plugins:
- Search for `firebase`, `firestore`, `cloud_functions`, `firebase_auth`
- Check `google-services.json` (Android) or `GoogleService-Info.plist` (iOS) for project configuration
- Test Firestore/RTDB rules if the app uses direct database access

## Step 6: Dynamic Analysis with Frida

### Hooking Dart functions

blutter generates `blutter_frida.js` with hooks for discovered functions. Use this as a starting point:
- Hook authentication functions to observe credentials
- Hook crypto functions to capture keys, IVs, plaintext
- Hook API client methods to see request/response data before encryption

### Intercepting at the native boundary

For platform channel interception:
- Android: `Java.perform` to hook `MethodChannel.invokeMethod` and `MethodChannel.Result`
- iOS: hook `FlutterMethodChannel handleMethodCall:result:`

### Memory inspection

- Dart objects live in the Dart heap, not the native heap. Standard memory dump tools may miss them.
- Use blutter's object pool analysis and Frida's Dart-specific hooks to inspect live objects.
- For RSA/crypto keys in memory: see `flutter-dart-heap-rsa-carve` skill.

## Limitations

- **No source maps:** Dart AOT compilation does not include source maps. The blutter output is reconstructed, not decompiled source.
- **String fragmentation:** URLs and other strings may be split across multiple object pool entries. Automated tools may miss them.
- **Obfuscation:** `--obfuscate` flag removes class/method names. Dynamic analysis becomes essential.
- **Engine version coupling:** SSL bypass patterns are tied to the Flutter engine version. New engine versions may require updated patterns.
- **Web-only packages:** some Dart packages are web-only and do not appear in AOT mobile builds. Do not search for `dart:html` in mobile blutter output.

## Rules (always active)

- **blutter, not jadx:** jadx is for the native wrapper only. Dart code analysis goes through blutter. No exceptions.
- **Output to /tmp:** decompilation output goes to `/tmp/re_<appname>/`, never inside the project directory.
- **SSL is BoringSSL:** do not waste time on generic SSL hooks for Flutter HTTP traffic. Use `flutter-ssl-bypass-patternscan`.
- **Deterministic routing:** detection confirms Flutter, blutter decompiles, pattern-scan bypasses SSL. This sequence is not negotiable.
- **Document hybrid:** if the app mixes Flutter with native code, document both and analyze both sides.
