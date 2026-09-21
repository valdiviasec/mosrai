---
name: mob-react-native
description: Use when the target app is built with React Native. Covers detection, JS bundle extraction, Hermes bytecode decompilation, bridge inspection, AsyncStorage auditing, and RN-specific attack surfaces. Triggers - "react native", "react-native", "hermes", "jsbundle", "index.android.bundle", "main.jsbundle", "metro", "expo", "mob-react-native"
platform: [android, ios]
stack: [react-native]
category: recon
tier: A
related: [mob-analyze, mob-enabling, mob-retest]
---

# React Native App Security Assessment

This skill orchestrates recon and hunting for React Native apps. RN apps run JavaScript (or Hermes bytecode) inside a JS engine, bridged to native UI and APIs. The JS bundle is the primary target: it often contains the full application logic, API endpoints, and sometimes hardcoded secrets.

## Step 1: Detection

Confirm the app is React Native before proceeding.

**Android:**
- Unzip the APK and search for:
  - `assets/index.android.bundle`: plain JavaScript bundle (older RN or Metro without Hermes)
  - `assets/index.android.bundle` with Hermes magic bytes (`c6 1f bc 03` at offset 0): Hermes bytecode (.hbc)
  - `lib/<arch>/libhermes.so`: Hermes JS engine
  - `lib/<arch>/libjsc.so`: JavaScriptCore engine (pre-Hermes or opted out of Hermes)
  - `lib/<arch>/libreactnativejni.so`: React Native native bridge
- `com.facebook.react` package in jadx output confirms RN

**iOS:**
- Extract the IPA and search for:
  - `main.jsbundle` in the app bundle: JavaScript bundle
  - `Frameworks/hermes.framework`: Hermes engine
  - `Frameworks/jsc.framework`: JavaScriptCore (if not using system JSC)
- Search binary symbols for `RCTBridge`, `RCTRootView`

**Expo detection:**
- `app.json` or `app.config.js` with `"expo"` key in assets
- `expo-` prefixed packages in the JS bundle
- `Expo.framework` in iOS frameworks
- Expo apps may use OTA updates via Expo Updates: check for update URLs in the bundle

## Step 2: JS Bundle Extraction and Decompilation

### Plain JavaScript bundle

If the bundle is plain JavaScript (no Hermes bytecode):
- Extract directly from APK (`assets/index.android.bundle`) or IPA (`main.jsbundle`)
- The file is a single minified JavaScript file containing the entire app logic
- Use a JS beautifier (`js-beautify`, Prettier) for readability
- Search directly for strings, URLs, API keys, credentials

### Hermes bytecode (.hbc)

If the bundle is Hermes bytecode (check magic bytes `c6 1f bc 03`):

**Primary: hermes-dec**
```
hermes-dec index.android.bundle /tmp/re_<appname>/hermes_out/
```
- Decompiles Hermes bytecode back to readable JavaScript
- Output quality varies: some functions decompile cleanly, others produce partial output
- String literals are usually well-preserved

**Supplementary: hbctool**
- `hbctool disasm` for lower-level Hermes assembly when hermes-dec fails
- Useful for inspecting specific functions that hermes-dec could not decompile

**Fallback: string extraction**
- Even if decompilation partially fails, strings in the .hbc file are extractable
- `strings` on the bundle captures URLs, API keys, error messages
- `hermes-dec --strings-only` if available

### Output location

All extraction output goes to `/tmp/re_<appname>/`:
- `/tmp/re_<appname>/bundle/`: raw extracted bundle
- `/tmp/re_<appname>/hermes_out/`: hermes-dec output
- `/tmp/re_<appname>/bundle_beautified.js`: beautified plain JS bundle

## Step 3: JS Bundle Analysis

The JS bundle is the primary attack surface. Search systematically.

### API Endpoints and URLs
- `fetch(`, `axios.`, `XMLHttpRequest`, `.get(`, `.post(`, `.put(`, `.delete(`
- Base URLs: `baseURL`, `BASE_URL`, `apiUrl`, `API_URL`, `serverUrl`
- Full URLs: `https://`, `http://`, `wss://`, `ws://`
- GraphQL: `query`, `mutation`, `__typename`, `/graphql`

### Hardcoded Secrets
- API keys: `apiKey`, `api_key`, `API_KEY`, `x-api-key`
- Auth tokens: `token`, `bearer`, `authorization`, `secret`
- Firebase config: `apiKey`, `authDomain`, `projectId`, `storageBucket`, `messagingSenderId`
- AWS: `accessKeyId`, `secretAccessKey`, `aws_access_key_id`
- Third-party keys: Stripe, Twilio, SendGrid, Sentry DSN, Mixpanel
- Encryption keys: `encryptionKey`, `secretKey`, `privateKey`, `AES`, `IV`

### Authentication Logic
- Login flows: `login`, `signIn`, `authenticate`, `credential`
- Token handling: `setToken`, `getToken`, `refreshToken`, `accessToken`
- Role checks: `isAdmin`, `role`, `permission`, `authorize`
- Client-side validation: any security check in the JS bundle can be bypassed

### AsyncStorage Keys
- `AsyncStorage.setItem`, `AsyncStorage.getItem`, `AsyncStorage.multiGet`
- Document all keys used: these are stored unencrypted on disk
- Common sensitive keys: `@auth_token`, `@user_data`, `@session`, `@credentials`

## Step 4: Bridge Inspection

The React Native bridge is the boundary between JavaScript and native code. Data crossing it is a key attack surface.

### Native Modules

Search the JS bundle for:
- `NativeModules.ModuleName`: standard bridge modules
- `TurboModuleRegistry.get` / `TurboModuleRegistry.getEnforcing`: new architecture
- `requireNativeComponent`: native UI components

For each native module found:
1. Identify what it does (crypto, storage, biometric, file access)
2. Check if sensitive data crosses the bridge (tokens, keys, PII)
3. Check if the native module validates inputs from the JS side
4. On Android: find the corresponding `ReactContextBaseJavaModule` in jadx
5. On iOS: find the corresponding `RCT_EXPORT_MODULE` implementation

### JSI (JavaScript Interface)

Newer RN apps may use JSI for direct native calls:
- JSI bypasses the bridge entirely: native functions callable from JS without serialization
- Harder to intercept than bridge calls
- Look for `jsi::Runtime`, `jsi::Function` in native code

### Serialization

Bridge data is serialized as JSON by default. Check for:
- Custom serialization that might leak data types or structure
- Binary data sent as base64 strings (inefficient, inspectable)
- Protobuf or other binary serialization via custom native modules

## Step 5: React Native-Specific Attack Surfaces

### AsyncStorage

AsyncStorage is the most common storage in RN apps. It is **unencrypted by default**:
- Android: stored in SQLite database at `/data/data/<pkg>/databases/RKStorage`
- iOS: stored in a SQLite database in the app sandbox
- Extract and inspect for tokens, credentials, PII, session data
- Check if the app uses `react-native-encrypted-storage` or `react-native-keychain` as alternatives

### CodePush / OTA Updates

Many RN apps use Microsoft CodePush or Expo Updates for over-the-air JS bundle updates:
- Search for `codePush`, `CodePush`, `appCenterSecret` in the bundle
- Search for `expo-updates`, `Updates.checkForUpdateAsync`
- Check if update integrity is verified (signing, hash validation)
- If updates are not signed: potential for MITM to inject malicious JS bundle
- Check the update URL: is it HTTPS? Is the server's certificate pinned?

### Expo-Specific

If the app uses Expo:
- `expo-secure-store`: uses Keychain (iOS) / Keystore (Android). Verify it is used for sensitive data.
- `expo-file-system`: check for sensitive file operations
- `expo-auth-session`: OAuth handling. Check for state parameter, PKCE, redirect URI validation.
- Expo Go compatibility: if the app runs in Expo Go, the entire app code is downloadable from the Expo server

### Deep Linking

RN deep link handling:
- `Linking.getInitialURL` / `Linking.addEventListener('url', ...)`
- Navigation libraries: `react-navigation` deep link configuration in the JS bundle
- Check for auth bypass via deep links (navigating directly to authenticated screens)
- Check for data exfiltration via deep link parameters

### Third-Party Packages

Search `node_modules` references in the bundle for vulnerable packages:
- `react-native-webview`: check for `injectedJavaScript`, `onMessage` handlers
- `react-native-device-info`: check what device data is collected
- `react-native-sensitive-info`: check usage patterns
- `react-native-biometrics`: check for event-based (bypassable) vs crypto-based

## Step 6: SSL Bypass

React Native typically uses the platform's HTTP stack:
- **Android:** OkHttp (default for RN on Android). Generic OkHttp SSL bypass usually works.
- **iOS:** NSURLSession (default for RN on iOS). Generic NSURLSession bypass usually works.

**Try generic hooks first.** They work in the majority of RN apps.

**Exceptions that require custom handling:**
- `react-native-ssl-pinning`: implements custom pinning via a native module. Hook the module's verification method.
- `react-native-pinch`: similar custom pinning. Hook the verification.
- Custom `TrustManager` (Android) or `URLSessionDelegate` (iOS) implemented in the native bridge code: hook the specific implementation.
- `TrustKit` integration: check native code for TrustKit configuration.

If generic bypass fails, inspect the native bridge code for custom HTTP/TLS handling before escalating.

## Step 7: Dynamic Analysis

### Frida on the JS Bridge

Hook the bridge to observe all JS-to-native communication:
- Android: hook `com.facebook.react.bridge.CatalystInstanceImpl.jniCallJSFunction`
- iOS: hook `RCTCxxBridge` methods

### Hermes Debugging

If Hermes is enabled and the app is debuggable:
- Chrome DevTools can attach via `chrome://inspect`
- Full JS debugging: breakpoints, console, network inspection
- Even release builds may have Hermes debugging enabled (check `isDebuggingSupported`)

### Runtime JS Injection

If the bridge is accessible:
- Inject JavaScript via Frida to call native modules directly
- Modify app state by calling `setState` on React components
- Bypass client-side validation by intercepting and modifying JS function returns

## Limitations

- **Hermes bytecode quality:** hermes-dec may produce partial or unreadable output for complex functions. Supplement with string extraction and dynamic analysis.
- **Obfuscation:** some apps use `react-native-obfuscating-transformer` or `metro-minify-obfuscator`. This makes static analysis harder but strings are often still extractable.
- **New Architecture (Fabric/TurboModules):** newer RN apps use Fabric renderer and TurboModules. The bridge is replaced by JSI, making interception harder. Hook at the native layer instead.
- **Split bundles:** some apps split the JS bundle into multiple chunks. Ensure all chunks are extracted and analyzed.

## Rules (always active)

- **hermes-dec for Hermes, direct read for plain JS:** deterministic tool selection based on bundle format. Check magic bytes.
- **Output to /tmp:** all extraction output goes to `/tmp/re_<appname>/`.
- **JS bundle = source code:** treat the JS bundle as the full app source. Analyze it with the same rigor as decompiled native code.
- **AsyncStorage = plaintext:** assume all AsyncStorage data is readable by anyone with device access. Flag sensitive data stored there.
- **Generic SSL first:** try platform-specific generic bypass before investigating custom pinning.
- **Check OTA updates:** if CodePush/Expo Updates is present, verify update integrity. Unsigned OTA is a finding.
