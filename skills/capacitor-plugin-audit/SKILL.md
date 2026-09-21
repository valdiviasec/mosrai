---
name: capacitor-plugin-audit
description: Use when you need to enumerate and audit installed Capacitor or Cordova plugins for security-relevant permissions, capabilities, and misconfigurations. Covers plugin enumeration, a high-risk plugin checklist, permission cross-referencing with AndroidManifest.xml, and input validation checks on native plugin interfaces.
platform: [android, ios]
stack: [capacitor]
category: recon
tier: B
related: [mob-capacitor, capacitor-web-asset-extraction]
---

# Capacitor/Cordova Plugin Security Audit

## When to use

- You have extracted web assets from a Capacitor or Cordova app (see `capacitor-web-asset-extraction`).
- You need to enumerate what native capabilities are exposed to the JavaScript layer.
- You are looking for privilege escalation paths from web code to native device features (filesystem, camera, location, etc.).

## Step 1: Enumerate installed plugins

### Capacitor

Read the Capacitor configuration file for plugin settings:

```
cat /tmp/re_<appname>/assets/capacitor.config.json
```

Search for plugin registrations and imports across the extracted codebase:

```
rg -n 'registerPlugin\|@capacitor/\|capacitor-community' /tmp/re_<appname>/
```

In the web assets, search for Capacitor plugin usage:

```
rg -n 'import.*from.*@capacitor\|Capacitor\.Plugins\.' /tmp/re_<appname>/web_assets/
```

On the native side (if jadx output is available), check plugin registration:

```
rg -n 'add\(.*\.class\)\|registerPlugin' /tmp/re_<appname>/jadx_output/
```

### Cordova

Cordova has a dedicated plugin manifest that lists ALL installed plugins with their JS-to-native mappings:

```
cat /tmp/re_<appname>/assets/www/cordova_plugins.js
```

Also check `config.xml` for plugin configuration and access whitelists:

```
cat /tmp/re_<appname>/assets/www/config.xml
```

Flag `<access origin="*"/>` in config.xml: this means no domain restriction on network requests (finding).

## Step 2: Check the high-risk plugin checklist

For each installed plugin, cross-reference against this table. Any match requires deeper inspection in Step 3.

| Plugin | Risk | What to check |
|--------|------|---------------|
| `@capacitor/filesystem` | File read/write outside sandbox | Can JS code read arbitrary paths? Check `Directory` enum usage for `ExternalStorage`, `Documents`, or root paths |
| `@capacitor/camera` | Photo access, metadata leak | Does the app strip EXIF before upload? Are captured images stored unencrypted? |
| `@capacitor/geolocation` | Location tracking | Is the permission justified by app function? Is location data sent to third-party analytics? |
| `@capacitor/browser` | Opens URLs in system browser | Can JS control the URL parameter? Open redirect risk if URL comes from untrusted input |
| `@capacitor/share` | Data sharing to other apps | Can attacker-controlled content be passed to the share intent? |
| `@capacitor/push-notifications` | Push token access | Is the push token sent to a third-party analytics endpoint instead of (or in addition to) the app backend? |
| `cordova-plugin-file` | Arbitrary file access | Are read/write paths controlled by JS input without validation? Path traversal risk |
| `cordova-plugin-inappbrowser` | Embedded browser | Can load arbitrary URLs. Can an attacker inject a URL? Does it share cookies with the main WebView? |
| `cordova-plugin-sqlite-2` | Local database access | Is the SQLite database unencrypted? Does it store sensitive data (tokens, PII)? |
| `cordova-plugin-advanced-http` | Custom HTTP stack | Bypasses WebView network stack: SSL pinning implications. Does it disable certificate validation? |
| `@capacitor/preferences` | Key-value storage | Stores to SharedPreferences (Android) / NSUserDefaults (iOS): both unencrypted. Is sensitive data stored here? |
| `cordova-plugin-file-transfer` | File upload/download | Is the destination URL validated? Is authentication enforced on transfers? |

## Step 3: Inspect native plugin code for input validation

For each high-risk plugin identified in Step 2, check whether the JS-to-native interface validates its inputs:

```
rg -n 'call.*method\|getCall\|getString\|getObject' /tmp/re_<appname>/
```

Specific vulnerability patterns to look for:

**Path traversal in filesystem operations:**
```
rg -n 'getPath\|resolve\|join.*path\|Directory\.' /tmp/re_<appname>/web_assets/
```
If the path parameter comes from user input or a deep link without sanitization (no stripping of `../`), this is a path traversal finding.

**Unvalidated URLs in browser/webview operations:**
```
rg -n '\.open\|Browser\.open\|InAppBrowser\|window\.open' /tmp/re_<appname>/web_assets/
```
If the URL parameter can be controlled by an attacker (e.g., via deep link parameter, postMessage, or URL fragment), this is an open redirect or potential phishing finding.

**SQL injection in SQLite operations:**
```
rg -n 'executeSql\|execSQL\|rawQuery\|run.*SELECT\|run.*INSERT' /tmp/re_<appname>/web_assets/
```
If SQL queries are built by string concatenation with user input, this is a SQL injection finding.

## Step 4: Cross-reference permissions with AndroidManifest.xml

Check what permissions the app declares:

```
rg -n 'uses-permission' /tmp/re_<appname>/AndroidManifest.xml
```

Cross-reference each permission with the installed plugins:

- If a permission exists but no installed plugin uses that capability, it may be a leftover from a removed plugin: this is an information disclosure finding (reveals removed features and development history).
- If a plugin requires a permission not declared in the manifest, the plugin cannot function: this may indicate dead code or a misconfiguration.
- Flag overly broad permissions: `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `ACCESS_FINE_LOCATION` when only coarse location is needed, `CAMERA` without a camera plugin.

## Step 5: Check plugin configuration for insecure settings

Review `capacitor.config.json` or `config.xml` for plugin-specific configuration:

```
# Capacitor: check the plugins section
cat /tmp/re_<appname>/assets/capacitor.config.json | python3 -m json.tool

# Cordova: check feature and preference elements
rg -n '<feature\|<preference\|<allow' /tmp/re_<appname>/assets/www/config.xml
```

Flag these insecure configurations:

- `allowNavigation` set to `*` or overly broad patterns: allows the WebView to navigate to any URL.
- `allowIntent` with broad patterns: allows the app to open arbitrary intents.
- Server URL pointing to `http://` instead of `https://`: cleartext traffic.
- Any plugin with disabled certificate validation or SSL verification.

## What confirms the finding

- **High-risk plugin without input validation:** A plugin like `@capacitor/filesystem` used with path parameters from untrusted sources (deep links, postMessage, URL fragments) without sanitization. Severity: Medium-High depending on what can be read/written.
- **Orphan permissions:** Permissions in AndroidManifest.xml with no corresponding plugin or code using them. Severity: Low (Information Disclosure).
- **Overly broad access whitelist:** `<access origin="*"/>` or `allowNavigation: ["*"]`. Severity: Medium: allows the app to load content from any domain.
- **Unencrypted sensitive storage:** High-risk storage plugin (`@capacitor/preferences`, `cordova-plugin-sqlite-2`) storing auth tokens or PII without encryption. Severity: Medium-High.

## Limitations

- Plugin enumeration from JS imports may miss plugins that are registered natively but not imported in the main bundle (e.g., plugins used only by a background service).
- Cordova's `cordova_plugins.js` is the most reliable source for Cordova apps: it is auto-generated and comprehensive. Capacitor has no exact equivalent; cross-referencing JS imports with native code is necessary.
- Input validation issues at the native layer require decompiled native code (jadx for Android, class-dump/Hopper for iOS). If the native code is obfuscated, the audit may be incomplete.
- Some plugins have their own update mechanisms (e.g., Cordova plugin updates via hooks). The version in the APK/IPA is a snapshot; the runtime version may differ.
