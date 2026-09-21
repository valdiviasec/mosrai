---
name: mob-capacitor
description: Use when the target app is built with Capacitor or Cordova (hybrid web app). Covers detection, web asset extraction, plugin auditing, WebView configuration analysis, and hunting surfaces unique to hybrid apps. Triggers - "capacitor app", "cordova app", "ionic app", "hybrid app", "capacitor.config", "config.xml", "webview app", "mob-capacitor"
platform: [android, ios]
stack: [capacitor]
category: recon
tier: A
related: [mob-analyze, mob-enabling, mob-retest, capacitor-deeplink-ato-no-binding, webview-js-interface-intent-forging, webview-xss-rce-bridge]
---

# Capacitor/Cordova App Security Assessment

This skill orchestrates recon and hunting for Capacitor and Cordova (hybrid) apps. These apps are essentially web apps (HTML/JS/CSS) packaged inside a native WebView container with native plugin bridges. The web assets are the primary target: they often contain the full application logic in readable JavaScript.

## Step 1: Detection

Confirm the app is Capacitor or Cordova before proceeding. Distinguish between the two: they have different directory structures and plugin systems.

**Capacitor:**
- Android APK: `assets/public/` contains the web assets, `capacitor.config.json` or `capacitor.config.ts` present
- iOS IPA: `Payload/App.app/public/` contains web assets
- Look for `capacitor.js`, `@capacitor/core` imports in JS files
- `com.getcapacitor` package in Android jadx output
- `CAPBridge` or `CAPPlugin` in iOS headers

**Cordova:**
- Android APK: `assets/www/` contains the web assets, `config.xml` at root of assets
- iOS IPA: `Payload/App.app/www/` directory
- `cordova.js`, `cordova_plugins.js` present in web assets
- `config.xml` contains plugin declarations and access whitelists
- `org.apache.cordova` package in Android jadx output

**Ionic:**
- Ionic is a UI framework, not a runtime: it runs on top of Capacitor (newer) or Cordova (older)
- Detection is Capacitor/Cordova detection plus `@ionic` imports in JS bundles
- The runtime determines the skill approach, not the UI framework

## Step 2: Web Asset Extraction

The web assets are the app's source code. Extract them completely.

### Extraction

**Android:**
```
unzip app.apk -d /tmp/re_<appname>/apk_extract/
# Capacitor: cp -r /tmp/re_<appname>/apk_extract/assets/public/ /tmp/re_<appname>/web_assets/
# Cordova: cp -r /tmp/re_<appname>/apk_extract/assets/www/ /tmp/re_<appname>/web_assets/
```

**iOS:**
```
unzip app.ipa -d /tmp/re_<appname>/ipa_extract/
# Capacitor: cp -r /tmp/re_<appname>/ipa_extract/Payload/App.app/public/ /tmp/re_<appname>/web_assets/
# Cordova: cp -r /tmp/re_<appname>/ipa_extract/Payload/App.app/www/ /tmp/re_<appname>/web_assets/
```

### Structure

Typical web asset structure:
```
web_assets/
  index.html         : entry point
  main.js / main.*.js: bundled application JavaScript
  vendor.js          : third-party libraries
  polyfills.js       : browser polyfills
  styles.css         : application styles
  assets/            : images, fonts, other static assets
  capacitor.js       : Capacitor bridge (or cordova.js)
```

The `main.js` (or similar bundled JS file) contains the full application logic. It is typically minified but not obfuscated (most hybrid apps do not use JS obfuscation). Beautify it for analysis.

## Step 3: Direct Source Analysis

The web assets are essentially the full app source. This is the most information-rich attack surface in any mobile framework.

### API Endpoints and Backend
- Search all JS files for: `fetch(`, `axios`, `HttpClient`, `XMLHttpRequest`, `.get(`, `.post(`
- Base URLs: `environment.apiUrl`, `baseUrl`, `API_BASE`, `serverUrl`
- API keys: `apiKey`, `x-api-key`, `Authorization`, `Bearer`
- GraphQL: `query`, `mutation`, `/graphql`
- WebSocket: `wss://`, `ws://`, `new WebSocket`

### Authentication
- Token storage: `localStorage.setItem`, `sessionStorage.setItem`, `Preferences.set`, `Storage.set`
- Auth flows: `login`, `signIn`, `OAuth`, `PKCE`, `authToken`, `refreshToken`
- Role/permission checks in client-side code: all bypassable
- JWT handling: search for `jwt`, `jsonwebtoken`, `jwt-decode`, `atob` on JWT parts

### Cryptographic Material
- Encryption keys: `CryptoJS`, `crypto-js`, `sjcl`, `forge`, `tweetnacl`
- Hardcoded secrets: `secretKey`, `encryptionKey`, `hmacKey`, `iv`, `salt`
- Password derivation: `PBKDF2`, `scrypt`, `argon2`

### Environment Files
- `environment.ts`, `environment.prod.ts` (Angular): often contain API URLs, keys, feature flags
- `.env` values inlined at build time: search for `process.env`, `import.meta.env`
- Build artifacts may contain development/staging URLs alongside production

### Source Maps
- Check for `.map` files alongside JS bundles (e.g., `main.js.map`)
- Source maps expose the original TypeScript/JavaScript source code with full variable names, comments, and file structure
- If present, this is the highest-quality source available: analyze the original sources, not the minified bundle
- Source maps in production are a finding (information disclosure)

## Step 4: Plugin Audit

Plugins bridge web code to native capabilities. Each plugin is a potential privilege escalation from web to native.

### Enumerate Plugins

**Capacitor:**
- Read `capacitor.config.json` for plugin configuration
- Search JS for `import { ... } from '@capacitor/...'` and `Capacitor.Plugins.X`
- Check `package.json` if available (sometimes included in web assets)
- List Capacitor plugins registered in native code: Android `MainActivity.java`, iOS `AppDelegate`

**Cordova:**
- Read `cordova_plugins.js`: lists all installed plugins with their IDs and entry points
- Read `config.xml` for plugin configuration and access whitelists
- `<access origin="*"/>` in config.xml = no domain restriction (finding)

### High-Risk Plugins

Flag and investigate these plugins specifically:

| Plugin | Risk | Check |
|--------|------|-------|
| `@capacitor/filesystem` / `cordova-plugin-file` | File system access | What paths can it access? Is it reading/writing sensitive locations? |
| `@capacitor/camera` / `cordova-plugin-camera` | Camera access | Where are captured images stored? Are they sent to the server? |
| `cordova-plugin-inappbrowser` | Arbitrary URL loading | Can it load attacker-controlled URLs? Does it share cookies? |
| `@capacitor/browser` | External browser | Can it be triggered by deep links with arbitrary URLs? |
| `cordova-plugin-advanced-http` | Custom HTTP | Bypasses WebView network stack: SSL pinning implications |
| `@capacitor/preferences` / `cordova-plugin-nativestorage` | Storage | Is sensitive data stored? Is it encrypted? |
| `@capacitor/push-notifications` | Push tokens | Is the push token sent to a secure endpoint? |
| `cordova-plugin-file-transfer` | File upload/download | Destination validation? Authentication on transfers? |

### Plugin Configuration

Check each plugin's configuration for excessive permissions or insecure settings:
- File plugins with broad path access (`ExternalDataDirectory`, `ApplicationDirectory`)
- Camera plugins storing images without encryption
- HTTP plugins with disabled SSL verification
- Any plugin with `*` wildcard permissions

## Step 5: WebView Configuration

The WebView is the runtime environment. Its configuration determines the app's security posture.

### Android WebView

Check the native code (jadx output) for WebView settings:

- `setAllowFileAccessFromFileURLs(true)`: **critical**: JS can read local files via `file://` XHR
- `setAllowUniversalAccessFromFileURLs(true)`: **critical**: JS can read any local file
- `setAllowFileAccess(true)`: JS can access `file://` URLs (less critical than above, but still risky)
- `setJavaScriptEnabled(true)`: expected for hybrid apps, but note it
- `setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)`: allows HTTP resources in HTTPS pages
- `addJavascriptInterface`: native methods exposed to JS beyond the Capacitor/Cordova bridge
- `setWebContentsDebuggingEnabled(true)`: remote debugging enabled (finding in production)

### iOS WKWebView

Check the native code (class-dump/Hopper output):

- `WKWebViewConfiguration` settings
- `allowsInlineMediaPlayback`, `mediaTypesRequiringUserActionForPlayback`
- Custom `WKScriptMessageHandler` beyond Capacitor/Cordova bridge
- `WKNavigationDelegate` URL validation logic
- `NSAppTransportSecurity` settings in Info.plist

### Content Security Policy

Check `index.html` for CSP meta tag or response headers:
- Missing CSP = no restriction on loaded resources (finding)
- `unsafe-inline`, `unsafe-eval` in CSP = weakened protection
- `*` or overly broad domain whitelists = ineffective CSP
- Capacitor apps need `capacitor://localhost` (iOS) or `http://localhost` (Android) in CSP: but nothing beyond that

## Step 6: Storage Analysis

Hybrid apps store data in web storage, which is inherently accessible.

### Web Storage
- `localStorage`: persistent, unencrypted, accessible via WebView debugging or file extraction
  - Android: stored in WebView databases directory
  - iOS: stored in WKWebView data directory
- `sessionStorage`: per-session, same accessibility concerns
- Check for: auth tokens, user data, API keys, feature flags, cached responses

### IndexedDB / WebSQL
- Used for larger structured data
- Same accessibility as localStorage
- Extract database files from app sandbox and inspect

### Capacitor/Cordova Storage Plugins
- `@capacitor/preferences` (formerly `@capacitor/storage`): key-value store using native SharedPreferences/NSUserDefaults
- `cordova-plugin-nativestorage`: same pattern
- `@ionic/storage`: abstraction layer over SQLite/IndexedDB
- All of these are unencrypted by default unless explicitly wrapped

### Cookie Storage
- Cookies in the WebView context: inspect via WebView debugging
- Check for session cookies without `Secure`, `HttpOnly`, or `SameSite` flags
- `android.webkit.CookieManager` settings on Android

## Step 7: SSL Bypass

Capacitor/Cordova apps use the platform WebView for network requests. This simplifies SSL bypass:

**Standard approach:**
- System-level proxy settings capture WebView traffic (Android requires CA cert installed as user cert + proxy configured)
- VPN-based proxy tools (Proxyman, HTTP Toolkit) capture all device traffic including WebView
- No app-level bypass usually needed: WebView respects system proxy

**SSL pinning in hybrid apps is rare but possible:**
- `cordova-plugin-advanced-http`: implements its own HTTP stack with pinning. Hook the plugin's native code.
- `capacitor-ssl-pinning`: community plugin for SSL pinning. Hook `SSLPinning.verify`.
- Custom native HTTP modules: if the app makes HTTP requests via a custom native plugin (bypassing the WebView), treat those requests like native app traffic for SSL bypass.
- WKWebView `serverTrust` delegate: iOS apps can implement custom server trust evaluation

**Verification:** trigger a request in the app and confirm it appears in the proxy. WebView traffic shows as regular HTTP(S) traffic.

## Step 8: Hunting Surfaces Specific to Hybrid Apps

### Deep Link Handling

- Capacitor: check `capacitor.config.json` for `appUrlOpen` listeners, `App.addListener('appUrlOpen', ...)`
- Cordova: check `config.xml` for `<universal-links>` and custom URL schemes
- Test if deep links can navigate to authenticated screens without auth checks
- Test if deep link parameters are reflected in the WebView without sanitization (XSS)
- Check for open redirect via deep link to `InAppBrowser`

### postMessage Bridge

- Search for `window.postMessage`, `addEventListener('message', ...)` in web assets
- Check if messages between the WebView and native layer are validated:
  - Is the origin checked? (`event.origin`)
  - Is the message type validated?
  - Can an injected iframe send messages to the native bridge?
- Capacitor bridge: `window.Capacitor.postMessage`: check if it can be called from injected content

### Sensitive Data in Web Assets

- Source maps (`.map` files): full original source code (information disclosure)
- Comments in minified code: developer notes, internal URLs, credentials
- Unused code (tree-shaking failures): dead code with staging/dev endpoints
- HTML comments with sensitive information

### XSS in WebView Context

XSS in a hybrid app is more severe than in a regular web app because:
- XSS can call native plugins (file access, camera, push notifications)
- XSS can access all web storage (localStorage, IndexedDB)
- XSS can access the Capacitor/Cordova bridge directly
- Test all user input that is rendered in the WebView without sanitization
- Check for `innerHTML`, `document.write`, `eval()` usage with user data

## Rules (always active)

- **Web assets = source code:** the JS bundle is the full application source. Analyze it thoroughly.
- **Output to /tmp:** all extraction output goes to `/tmp/re_<appname>/`.
- **Plugin audit is mandatory:** every installed plugin must be enumerated and assessed. High-risk plugins require deep inspection.
- **WebView config is critical:** `allowFileAccessFromFileURLs` or `allowUniversalAccessFromFileURLs` set to true is always a finding.
- **XSS = native access:** XSS in a hybrid app is not just a web vuln: it grants native capability access via the bridge. Severity is elevated accordingly.
- **Source maps in production = finding:** if `.map` files are present in the published app, report as information disclosure.
- **CSP matters:** missing or weak CSP in a hybrid app is more impactful than in a regular website. Document and report.
