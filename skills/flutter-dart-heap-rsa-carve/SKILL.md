---
name: flutter-dart-heap-rsa-carve
description: Use when a Flutter/Dart app embeds RSA keys for login crypto, certificate pinning, or license validation and the keys are invisible statically (no strings output, obfuscated). Scans the Dart VM heap at runtime with Frida for RSA key material (modulus, primes, PEM/DER markers) and reconstructs full RSA-2048 public+private key pairs from raw BigInt representations. Works even after key rotation by scanning for DER SPKI prefix patterns. Triggers - "RSA key extraction", "Dart heap", "Flutter crypto", "key not in strings", "obfuscated key", "BigInt", "memory scan RSA", "key rotation", "SPKI"
platform: [android, ios]
stack: [flutter]
category: crypto
tier: B
related: [flutter-ssl-bypass-patternscan]
---

# RSA Key Carving from Dart VM Heap

## When to use

- Flutter app uses RSA encryption (login, signature verification, license check)
- `strings libapp.so` and static analysis return no key material
- The key is obfuscated, split across constants, or loaded dynamically
- You need the key to forge encrypted payloads or decrypt responses
- The client rotated keys and you need to find the NEW key without prior knowledge

## How it works

Dart stores BigInts (used for RSA modulus, primes, exponents) in the VM heap as tagged objects. When the app performs any RSA operation, the key materializes in memory. Frida can scan readable-writable memory ranges for known patterns:

1. **Known modulus bytes**: if you have a previous key, scan for its modulus prefix
2. **DER SPKI prefix**: the standard `30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01` pattern appears when the app constructs an RSA public key object
3. **PEM markers**: `-----BEGIN PUBLIC KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`
4. **BigInt tag patterns**: Dart VM internal representations of large integers

## Workflow

### Step 1: Trigger key use

Launch the app and trigger an operation that uses the RSA key (login, encryption, signature). This forces the key into the heap.

### Step 2: Scan heap with Frida

```javascript
'use strict';

Java.perform(() => {
    // Scan all readable-writable ranges for DER SPKI prefix
    const SPKI_PREFIX = "30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01";
    const pattern = SPKI_PREFIX.split(" ").join(" ");

    Process.enumerateRanges("rw-").forEach(range => {
        Memory.scanSync(range.base, range.size, pattern).forEach(match => {
            console.log("[RSA] SPKI prefix found at:", match.address);
            // Read 294 bytes (typical RSA-2048 SPKI DER length)
            const der = match.address.readByteArray(294);
            console.log("[RSA] DER dump:", hexdump(der));
            // Write to file for offline reconstruction
            const f = new File("/data/local/tmp/rsa_pub_" + match.address + ".der", "wb");
            f.write(der);
            f.close();
        });
    });
});
```

### Step 3: Reconstruct the key

From the DER dump, reconstruct the PEM:

```python
#!/usr/bin/env python3
"""Reconstruct RSA public key from DER dump."""
import base64, sys
from Crypto.PublicKey import RSA

der = open(sys.argv[1], "rb").read()
key = RSA.import_key(der)
print(f"Modulus (n): {key.n}")
print(f"Exponent (e): {key.e}")
print(f"Bit length: {key.size_in_bits()}")
print(key.export_key("PEM").decode())
```

### Step 4: Find private key material (if in memory)

If the app has both public and private keys in memory (common in self-signed/debug builds or apps that decrypt locally):

```javascript
// Scan for RSA PRIVATE KEY PEM marker
const PEM_PRIV = "2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56"; 
// "-----BEGIN RSA PRIV"

Process.enumerateRanges("rw-").forEach(range => {
    Memory.scanSync(range.base, range.size, PEM_PRIV).forEach(match => {
        // Read until "-----END"
        const raw = match.address.readUtf8String(4096);
        const end = raw.indexOf("-----END");
        if (end > 0) {
            console.log("[RSA PRIVKEY]", raw.substring(0, end + 30));
        }
    });
});
```

### Step 5: Full reconstruction from components

If you find modulus (n) and one prime (p) but not the full private key, reconstruct:

```python
from Crypto.PublicKey import RSA
from sympy import mod_inverse

# From heap scan
n = 0x...  # modulus
e = 65537
p = 0x...  # one prime factor (found in heap)
q = n // p
assert p * q == n, "p is not a factor of n"

phi = (p - 1) * (q - 1)
d = mod_inverse(e, phi)

key = RSA.construct((n, e, d, p, q))
print(key.export_key("PEM").decode())
```

### Step 6: Handle key rotation

When the client rotates keys between retests:

1. **Don't search for old modulus bytes**: the new key is unknown
2. **Search for DER SPKI prefix pattern**: this is constant across all RSA keys
3. **Compare moduli**: if you find multiple keys, compare `n` values to identify which is new
4. **Check padding scheme changes**: rotation often comes with PKCS1v1.5 → OAEP upgrade

## Gotchas

- **Timing:** scan AFTER the key is used, not at app startup (the packer may not have loaded crypto code yet)
- **Multiple keys:** the app may have multiple RSA keys (server cert, signing key, encryption key). Identify each by its usage context.
- **Dart BigInt format:** in Dart VM, BigInts are stored as little-endian arrays of digits. The raw heap bytes may need byte-reversal before constructing the key.
- **Memory layout changes:** Dart VM updates can change how BigInts are laid out. The DER prefix scan is more robust than raw BigInt byte scanning.
- **iOS:** on iOS, the key may be in the Keychain rather than the heap. Scan the Keychain items first before heap scanning.
