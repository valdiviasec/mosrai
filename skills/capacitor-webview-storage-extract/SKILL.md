---
name: capacitor-webview-storage-extract
description: Use when you need to extract localStorage, sessionStorage, IndexedDB, and WebSQL data from a Capacitor or Cordova app's WebView on a rooted or jailbroken device. Covers file-based extraction paths for Android and iOS, LevelDB and SQLite parsing, runtime extraction via WebView debugging, and sensitive data identification.
platform: [android, ios]
stack: [capacitor]
category: storage
tier: B
related: [mob-capacitor, capacitor-web-asset-extraction]
---

# WebView Storage Extraction for Capacitor/Cordova Apps

## When to use

- You have a rooted Android device or jailbroken iOS device with the target Capacitor/Cordova app installed and used (so storage has been populated).
- You need to extract authentication tokens, cached API responses, PII, or other sensitive data stored in the WebView's client-side storage.
- You have already extracted and analyzed the web assets (see `capacitor-web-asset-extraction`) and identified `localStorage`, `sessionStorage`, or `IndexedDB` usage in the JavaScript code.

## Step 1: Extract localStorage and sessionStorage (Android)

The WebView stores localStorage in a LevelDB database on disk.

**File location:**
```
/data/data/<pkg>/app_webview/Default/Local Storage/leveldb/
```

**Extract via adb (requires root or run-as):**
```
adb pull /data/data/<pkg>/app_webview/Default/Local\ Storage/ /tmp/re_<appname>/webstorage/
```

**Quick method using strings (no LevelDB parser needed):**
```
adb shell "run-as <pkg> cat app_webview/Default/Local\ Storage/leveldb/*.log" | strings | grep -i 'token\|key\|auth\|pass\|secret'
```

**Structured parsing with plyvel (Python LevelDB library):**
```
pip install plyvel
python3 -c "
import plyvel
db = plyvel.DB('/tmp/re_<appname>/webstorage/leveldb')
for key, value in db:
    print(key, value)
db.close()
"
```

If `plyvel` installation fails (requires libleveldb), fall back to the `strings` method or use `leveldb-dump` from npm:
```
npx leveldb-dump /tmp/re_<appname>/webstorage/leveldb/
```

## Step 2: Extract IndexedDB (Android)

IndexedDB is also stored as LevelDB, with each origin in its own directory.

**File location:**
```
/data/data/<pkg>/app_webview/Default/IndexedDB/
```

**Extract and parse:**
```
adb pull /data/data/<pkg>/app_webview/Default/IndexedDB/ /tmp/re_<appname>/indexeddb/
ls /tmp/re_<appname>/indexeddb/
```

Each subdirectory corresponds to an origin. Parse the LevelDB inside each the same way as localStorage (Step 1).

## Step 3: Extract WebSQL (Android)

WebSQL databases are standard SQLite files.

**File location:**
```
/data/data/<pkg>/app_webview/Default/databases/
```

**Extract and query:**
```
adb pull /data/data/<pkg>/app_webview/Default/databases/ /tmp/re_<appname>/webdb/
ls /tmp/re_<appname>/webdb/

# List tables and dump all data
for db in /tmp/re_<appname>/webdb/*.db; do
  echo "=== $db ==="
  sqlite3 "$db" ".tables"
  sqlite3 "$db" ".dump"
done
```

## Step 4: Extract localStorage (iOS)

On iOS, WebKit stores localStorage as SQLite databases.

**File location:**
```
<app-container>/Library/WebKit/WebsiteData/LocalStorage/
```

Locate the app container first:
```
# On jailbroken device, find the app container
find /var/mobile/Containers/Data/Application/ -name "LocalStorage" 2>/dev/null
```

The `.localstorage` files are SQLite databases. Copy them off the device and query:
```
sqlite3 /tmp/re_<appname>/ios_localstorage/*.localstorage "SELECT * FROM ItemTable;"
```

## Step 5: Extract IndexedDB (iOS)

**File location:**
```
<app-container>/Library/WebKit/WebsiteData/IndexedDB/
```

IndexedDB on iOS is also SQLite-backed. Extract and query:
```
find /var/mobile/Containers/Data/Application/ -path "*/IndexedDB/*" -name "*.sqlite*" 2>/dev/null
```

Copy the SQLite files off the device and inspect with `sqlite3`.

## Step 6: Runtime extraction via WebView debugging

If remote debugging is enabled on the WebView, you can extract storage at runtime without file-level access.

**Check if WebView debugging is enabled (from static analysis):**
```
rg -n 'setWebContentsDebuggingEnabled' /tmp/re_<appname>/
```

If `setWebContentsDebuggingEnabled(true)` is set, this is a finding on its own: **WebView debugging enabled in production**.

**Connect and extract:**

1. Connect the device via USB.
2. Open `chrome://inspect` in Chrome on the host machine.
3. The app's WebView should appear under "Remote Target".
4. Open DevTools and run in the Console:

```javascript
// Dump all localStorage
JSON.stringify(localStorage)

// Dump all sessionStorage
JSON.stringify(sessionStorage)

// List IndexedDB databases
indexedDB.databases().then(dbs => console.log(JSON.stringify(dbs)))

// Dump a specific IndexedDB (replace dbName and storeName)
let req = indexedDB.open("dbName");
req.onsuccess = e => {
  let db = e.target.result;
  let tx = db.transaction("storeName", "readonly");
  let store = tx.objectStore("storeName");
  store.getAll().onsuccess = ev => console.log(JSON.stringify(ev.target.result));
};
```

**iOS Safari equivalent:** Enable Web Inspector on the iOS device (Settings > Safari > Advanced > Web Inspector). Connect via USB and use Safari's Develop menu on macOS to inspect the WebView.

## Step 7: Identify sensitive data

Search all extracted storage data for sensitive content:

**Authentication material:**
- JWT tokens (look for `eyJ` prefix: base64-encoded JSON header)
- Session IDs or session tokens
- OAuth access tokens, refresh tokens
- API keys or bearer tokens

**Personally Identifiable Information (PII):**
- User names, email addresses, phone numbers
- Physical addresses, government IDs
- Financial data (account numbers, transaction history)

**Application secrets:**
- API keys for third-party services
- Encryption keys or initialization vectors
- Feature flags that control security behavior (e.g., `isAdmin`, `bypassAuth`, `debugMode`)

**Cached API responses:**
- Responses containing other users' data (access control issue)
- Responses with sensitive business data
- Responses that should have been ephemeral but are persisted

Quick grep across all extracted data:
```
rg -i 'eyJ\|token\|bearer\|auth\|password\|secret\|api.key\|session' /tmp/re_<appname>/webstorage/ /tmp/re_<appname>/indexeddb/ /tmp/re_<appname>/webdb/ 2>/dev/null
```

## What confirms the finding

- **Auth tokens in localStorage/IndexedDB:** JWT, session tokens, or refresh tokens stored in unencrypted WebView storage. Severity: Medium-High. On a rooted/jailbroken device or via WebView debugging, these tokens can be extracted and reused.
- **PII in client-side storage:** User personal data cached in localStorage or IndexedDB without encryption. Severity: Medium. Violates data minimization principles; data persists after logout in many implementations.
- **WebView debugging enabled in production:** `setWebContentsDebuggingEnabled(true)` found in decompiled code. Severity: Medium. Allows any app on the device (or USB-connected host) to inspect and manipulate the WebView, including extracting all storage.
- **Feature flags controlling security:** Client-side flags like `isAdmin` or `debugMode` in localStorage that can be modified to bypass security checks. Severity depends on what the flag controls.

## Limitations

- **Root/jailbreak required for file extraction:** Steps 1-5 require elevated privileges on the device. Without root/jailbreak, only the runtime method (Step 6) works, and only if WebView debugging is enabled.
- **LevelDB parsing:** LevelDB files can be partially corrupted or compacted. The `strings` method catches most readable content but may miss binary-encoded values. Use a proper LevelDB parser when precision matters.
- **sessionStorage is volatile:** `sessionStorage` is cleared when the WebView is destroyed (app kill). It can only be captured via runtime extraction while the app is running, not from file extraction after the fact.
- **iOS encrypted backups:** If extracting via an iOS backup instead of a jailbroken device, the backup must be unencrypted or decrypted first. iTunes/Finder encrypted backups protect the WebKit data directories.
- **Capacitor Preferences vs. WebView storage:** Data stored via `@capacitor/preferences` (formerly `@capacitor/storage`) goes to Android SharedPreferences or iOS NSUserDefaults, not to WebView storage. Those are different files and require different extraction paths (standard mobile forensics, not this skill).
