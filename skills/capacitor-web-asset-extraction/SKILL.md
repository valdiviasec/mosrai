---
name: capacitor-web-asset-extraction
description: Use when you need to extract and analyze web assets (HTML/JS/CSS) from a Capacitor or Cordova hybrid app. This is the first recon step for any hybrid app: the web assets ARE the app source code. Covers extraction paths for both Android and iOS, source map detection, secrets grep, and framework fingerprinting.
platform: [android, ios]
stack: [capacitor]
category: recon
tier: B
related: [mob-capacitor, capacitor-deeplink-ato-no-binding]
---

# Web Asset Extraction for Capacitor/Cordova Apps

## When to use

- You have an APK or IPA identified as a Capacitor or Cordova app (see `mob-capacitor` detection step).
- You need the full client-side source code before hunting for secrets, endpoints, or logic bugs.
- This is the mandatory first step before `capacitor-plugin-audit` or any JS-level analysis.

## Step 1: Extract web assets from the package

### Android (APK)

**Capacitor** stores web assets at `assets/public/` inside the APK. **Cordova** uses `assets/www/`.

```
unzip -o app.apk -d /tmp/re_<appname>/
# Capacitor
ls /tmp/re_<appname>/assets/public/
# Cordova
ls /tmp/re_<appname>/assets/www/
```

The entry point is `index.html`. JavaScript is typically bundled as `main.*.js` or split into `main.js`, `vendor.js`, `polyfills.js`, and `runtime.js`.

### iOS (IPA)

**Capacitor** stores web assets at `Payload/App.app/public/` inside the IPA. **Cordova** uses `Payload/App.app/www/`.

```
unzip -o app.ipa -d /tmp/re_<appname>/
# Capacitor
ls /tmp/re_<appname>/Payload/App.app/public/
# Cordova
ls /tmp/re_<appname>/Payload/App.app/www/
```

### Normalize the working directory

Regardless of platform or framework, copy the web assets to a common location for all subsequent analysis:

```
# Adjust source path based on platform and framework detected above
cp -r /tmp/re_<appname>/assets/public/ /tmp/re_<appname>/web_assets/
```

## Step 2: Check for source maps

Source maps (`.map` files) expose the original unminified source code, component structure, variable names, and developer comments. Their presence in a production app is an information disclosure finding.

```
find /tmp/re_<appname>/web_assets/ -name "*.map"
```

If source maps are present:
- They contain the original TypeScript/JavaScript in full, often with file paths from the developer's machine.
- Analyze the original sources from the map instead of the minified bundle: they are far more readable.
- Report as **Information Disclosure**: source maps ship the full pre-build source to every user who downloads the app.

## Step 3: Search for hardcoded secrets and endpoints

Run these searches against the extracted web assets directory:

```
# API keys, tokens, credentials
rg -n 'api_key\|apiKey\|secret\|password\|token\|Bearer\|Authorization' /tmp/re_<appname>/web_assets/

# URLs and endpoints
rg -n 'https?://[a-zA-Z0-9.-]+' /tmp/re_<appname>/web_assets/ | grep -v node_modules

# Client-side storage usage (targets for storage extraction skill)
rg -n 'localStorage\|sessionStorage\|IndexedDB' /tmp/re_<appname>/web_assets/

# Environment variables inlined at build time
rg -n 'process\.env\|import\.meta\.env' /tmp/re_<appname>/web_assets/

# Cryptographic material
rg -n 'CryptoJS\|crypto-js\|secretKey\|encryptionKey\|hmacKey\|PBKDF2' /tmp/re_<appname>/web_assets/
```

## Step 4: Detect the JavaScript framework

Knowing the framework narrows where to look for routing, auth guards, and state management.

| Framework | Indicators |
|-----------|-----------|
| Angular | `angular.json`, `ngsw.json`, `runtime.*.js`, `polyfills.*.js`, `ng-` prefixed attributes in HTML |
| React | `react-dom` imports, `_jsx` calls, `useState`/`useEffect` hooks, `createRoot` |
| Vue | `vue-router`, `createApp`, `.vue` references, `v-if`/`v-for` directives in templates |
| Svelte | `svelte` imports, `$$invalidate`, compiled component patterns |
| No framework (vanilla) | Plain DOM manipulation, jQuery, no SPA router |

Quick detection command:

```
rg -l 'angular\|ngsw' /tmp/re_<appname>/web_assets/ && echo "==> Angular"
rg -l 'react-dom\|_jsx\|useState' /tmp/re_<appname>/web_assets/ && echo "==> React"
rg -l 'vue-router\|createApp\|v-if' /tmp/re_<appname>/web_assets/ && echo "==> Vue"
```

## Step 5: Beautify minified bundles

If no source maps are available, beautify the main bundle for manual analysis:

```
# Using js-beautify (pip install jsbeautifier)
js-beautify /tmp/re_<appname>/web_assets/main.*.js > /tmp/re_<appname>/web_assets/main.beautified.js

# Or using prettier (npx)
npx prettier --write /tmp/re_<appname>/web_assets/main.*.js
```

## What confirms the finding

- **Source maps in production:** `.map` files found alongside JS bundles. Severity: Medium (Information Disclosure). The maps expose the full original source, file structure, and developer comments.
- **Hardcoded secrets:** API keys, tokens, or credentials found in JS files. Severity depends on the secret type and what it grants access to.
- **Staging/dev endpoints:** URLs pointing to non-production environments. Severity: Low-Medium (Information Disclosure), potentially higher if the staging environment lacks authentication.

## Limitations

- If the app uses a JS obfuscator (rare in hybrid apps, but possible), the extracted code will be harder to analyze. Look for patterns like `_0x` variable prefixes, string arrays with rotation functions, or control flow flattening. Tools like `de4js` or `synchrony` can help deobfuscate.
- Web assets in the APK/IPA are a snapshot from build time. Runtime-loaded code (e.g., CodePush updates in React Native hybrid setups) will not be present: check for OTA update mechanisms separately.
- iOS IPA extraction requires either a jailbroken device, a decrypted IPA from a tool like `frida-ios-dump`, or an IPA obtained from a non-App-Store distribution (enterprise, TestFlight). App Store IPAs are encrypted.
