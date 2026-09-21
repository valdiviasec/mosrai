---
name: aes-ecb-decrypt-from-native-key
description: Use when an Android APK validates input by encrypting it with AES-ECB using a key derived from a JNI native function return value: hook the native to get the key, then decrypt the stored ciphertext offline. Triggers - "AES native key", "JNI key SHA-256", "SecretKeySpec native", "stringFromJNI"
platform: [android]
stack: [native]
category: crypto
tier: B
related: []
---

# Skill: AES-ECB decrypt from APK + native key

## When to use
- Android APK that validates an input by comparing it against an AES-encrypted asset/constant.
- The AES key is derived from a value returned by a JNI native function (`initFromJNI`, `getKey`, etc.).
- The cipher is initialized in ENCRYPT mode (`Cipher.init(ENCRYPT_MODE, ...)`) and the ciphertext is stored base64 in assets/resources.
- Works for any app where: `stored == Base64(AES_encrypt(user_input))` and the key comes from native.

## Steps
1. **Decompile with jadx** and locate the class that performs the validation (search for `Cipher`, `AES`, `SecretKeySpec`, `Base64`, `equals`).
2. **Understand the cryptographic scheme**:
   - `key = SHA-256(nativeBytes)` (or another KDF)
   - `cipher = Cipher.getInstance("AES")` → Java default = **AES/ECB/PKCS5Padding** (no IV = ECB)
   - `stored = Base64.encodeToString(cipher.doFinal(input.getBytes()), NO_WRAP)`
3. **Extract the native value at runtime** (see skill `frida-jni-return-value`). Do NOT try to reverse the .so obfuscation by hand unless it is trivial.
4. **Decrypt offline** with Python:
   ```python
   import hashlib, base64
   from Crypto.Cipher import AES
   key = hashlib.sha256(jni_bytes).digest()
   ct = base64.b64decode(asset_b64)
   pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
   pad = pt[-1]  # PKCS5/PKCS7 unpad
   password = pt[:-pad].decode()
   ```
5. **Verify** by injecting the password into the app (successful login) or by hooking `equals`/the validation function.

## Pitfalls / edge cases
- **Java "AES" without IV = ECB**, not CBC. Many people assume CBC and fail to decrypt.
- `Base64.NO_WRAP` (flag `2`) strips newlines; the asset may have a trailing `\n` when read: run `.strip()`.
- If `initFromJNI` returns `byte[]` (not `String`), use Frida to read it byte by byte (see skill frida-jni-return-value).
- The padding can be PKCS5 or PKCS7 (in AES they are equivalent: pad = 16 - len%16).
- If the KDF is not SHA-256, check: PBKDF2, raw bytes, MD5, XOR, etc.
- If the ciphertext is not a multiple of 16, it is probably not AES-ECB or there is an IV prefix (CBC).

## References
- Any app where `stored == Base64(AES_encrypt(input))` and the key is produced by native code.
- OWASP Mobile: "Insecure Cryptography" (MSTG-CRYPTO-4).
