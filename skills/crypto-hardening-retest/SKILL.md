---
name: crypto-hardening-retest
description: Use when retesting an app after the client reports crypto remediation (changed padding scheme, rotated keys, added obfuscation, upgraded cipher suite). Covers detecting what changed, re-extracting key material, adapting exploit tools, and issuing accurate verdicts. The approach generalizes across RSA, AES, and hybrid envelope schemes. Triggers - "crypto retest", "key rotated", "padding changed", "OAEP migration", "PKCS1 to OAEP", "keys obfuscated", "strings no longer visible", "crypto hardening"
platform: [android, ios]
stack: [any]
category: crypto
tier: B
related: [flutter-dart-heap-rsa-carve, flutter-bank-rsa-idor, encrypted-api-payload-testing, mob-retest]
---

# Detecting and Adapting to Crypto Hardening Between Retests

## When to use

- You previously found a crypto-related vulnerability (hardcoded key, weak padding, key in strings, etc.)
- The client claims remediation: changed the RSA padding, rotated keys, added obfuscation, upgraded from AES-ECB to AES-GCM
- Your previous exploit scripts or Frida hooks no longer work on the new build
- The key material that was previously visible via `strings` is no longer there
- The server now rejects payloads forged with the old key/scheme

## The pattern

Clients typically harden crypto in one or more of these ways. Each requires a specific detection and adaptation approach:

| Hardening | Detection | Adaptation |
|---|---|---|
| RSA padding change (PKCS1v1.5 to OAEP) | Old forged payloads get server error; strings show `OAEP` or `SHA-256` | Update forge script: change padding parameter |
| Key rotation | Old key still decrypts old traffic but not new; heap scan finds different modulus | Re-extract key from heap or binary |
| Key obfuscation (no longer in `strings`) | `strings libapp.so \| grep "BEGIN"` returns nothing | Scan heap at runtime for DER/PEM markers |
| Cipher upgrade (ECB to CBC/GCM) | Ciphertext length changes; new fields appear (IV, tag, nonce) | Update crypto proxy to use new mode |
| Key derivation change (static to PBKDF2) | Key no longer appears in binary; KDF params in code | Hook KDF output or reverse the derivation |
| Certificate pinning added/strengthened | SSL bypass no longer works | Re-derive bypass offset (see flutter-ssl-bypass-patternscan) |

## Step 1: Diff the builds

Before testing, compare the old and new builds to understand what changed.

### Binary diff

```bash
# Compare strings between versions
strings /tmp/re_<app>/old/libapp.so | sort > /tmp/old_strings.txt
strings /tmp/re_<app>/new/libapp.so | sort > /tmp/new_strings.txt
diff /tmp/old_strings.txt /tmp/new_strings.txt | grep -iE "rsa|aes|oaep|pkcs|encrypt|cipher|key|sha" | head -40

# Compare file sizes (significant change often means code/key changes)
ls -la /tmp/re_<app>/old/libapp.so /tmp/re_<app>/new/libapp.so
```

### Decompilation diff (Flutter)

```bash
# Decompile both versions
blutter /tmp/re_<app>/old/libapp.so /tmp/re_<app>/old_blutter/
blutter /tmp/re_<app>/new/libapp.so /tmp/re_<app>/new_blutter/

# Diff crypto-related functions
diff <(grep -i "encrypt\|decrypt\|rsa\|aes\|cipher" /tmp/re_<app>/old_blutter/asm/*.txt) \
     <(grep -i "encrypt\|decrypt\|rsa\|aes\|cipher" /tmp/re_<app>/new_blutter/asm/*.txt)
```

### Manifest/config diff

```bash
# Compare AndroidManifest.xml, network_security_config.xml
diff /tmp/re_<app>/old/AndroidManifest.xml /tmp/re_<app>/new/AndroidManifest.xml
```

## Step 2: Detect the specific hardening

### Padding scheme change

Run your old forge script against the new build. The error message reveals what changed:

| Server error | Likely change |
|---|---|
| "Decryption failed" / padding error | Padding scheme changed (PKCS1v1.5 to OAEP, or OAEP hash changed) |
| "Invalid key" / "Key not found" | Key was rotated |
| "Signature invalid" / "MAC mismatch" | Signing/MAC scheme changed |
| Request succeeds but returns wrong data | Different encryption context (new session key derivation) |

### Key visibility check

```bash
# Was the key previously in strings? Check new build
strings /tmp/re_<app>/new/libapp.so | grep -iE "BEGIN.*KEY\|MII\|AQAB"

# If nothing: key is now obfuscated or split across code
# If present but different: key was rotated (new modulus/exponent)
```

### Heap scan for rotated/obfuscated keys

When keys are no longer statically visible, scan the Dart VM heap (or Java heap) at runtime:

```javascript
// Frida: scan for RSA key markers in memory
var ranges = Process.enumerateRanges('r--');
ranges.forEach(function(range) {
    // DER SPKI prefix for RSA-2048: 30 82 01 22 30 0d 06 09
    var pattern = "30 82 01 22 30 0d 06 09";
    Memory.scan(range.base, range.size, pattern, {
        onMatch: function(address, size) {
            console.log("[RSA-DER] Found at " + address);
            console.log(hexdump(address, {length: 294}));
        },
        onComplete: function() {}
    });
});
```

For symmetric keys, hook the crypto API (see `encrypted-api-payload-testing` Step 1).

## Step 3: Adapt exploit tools

### Padding change adaptation

```python
# Old: PKCS1v1.5
# from Crypto.Cipher import PKCS1_v1_5
# cipher = PKCS1_v1_5.new(pub_key)

# New: OAEP with SHA-256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
cipher = PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)
```

Common padding migrations and their pycryptodome equivalents:

| Old scheme | New scheme | Change in code |
|---|---|---|
| PKCS1_v1_5 | OAEP/SHA-1 | `PKCS1_OAEP.new(key, hashAlgo=SHA1)` |
| OAEP/SHA-1 | OAEP/SHA-256 | Change `hashAlgo=SHA1` to `hashAlgo=SHA256` |
| AES-CBC | AES-GCM | Change mode, add nonce/tag handling |
| AES-ECB | AES-CBC | Add IV parameter |

### Key rotation adaptation

1. Extract the new key (Step 2 heap scan or static analysis)
2. Update your forge script with the new key material
3. Verify by encrypting a known plaintext and checking server accepts it

### Obfuscation adaptation

If strings obfuscation was added:
- Keys split across multiple constants: hook the function that assembles them
- XOR-encoded keys: find the XOR constant and decode
- Dynamic key loading from server: hook the network response that delivers the key

## Step 4: Issue the retest verdict

After adapting, re-run the original exploit with the new crypto parameters:

| Outcome | Verdict |
|---|---|
| Exploit succeeds with adapted tools (same vuln, new crypto) | PARTIALLY REMEDIATED: crypto hardened but underlying vuln persists |
| Exploit fails, new crypto correctly prevents the attack | REMEDIATED |
| New crypto introduces a different vulnerability | NEW FINDING (document separately) |
| Key material still extractable (from heap, binary, or traffic) | NOT REMEDIATED: key management unchanged despite padding upgrade |

The verdict "PARTIALLY REMEDIATED" is common: upgrading the padding scheme is good practice but does not fix the underlying problem if the key is still extractable from the app.

## Expected output

- Build diff showing specific crypto changes
- New key material (if extractable)
- Updated forge/proxy script adapted to the new scheme
- Evidence-backed verdict per finding with before/after comparison

## Limitations

- Server-side key rotation without client update: if the server rotates keys independently and the app fetches them at runtime via a secure channel, key extraction requires hooking the fetch
- Hardware-backed keys (Android Keystore, iOS Secure Enclave): keys never leave the secure element: heap scanning will not find them
- If the client also changed the entire API protocol (not just crypto), this becomes a new assessment rather than a retest
