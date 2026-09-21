---
name: flutter-aot-blutter-frida-hook
description: Use when testing a Flutter release app (Dart AOT) where jadx only shows the FlutterActivity shell and all logic is compiled into libapp.so. Reconstruct Dart code with blutter to recover function offsets, literals, and the crypto scheme, then hook target functions with Frida to dump keys, IVs, plaintext, and flags at runtime. Covers compressed-pointer decoding and OneByteString reading in the AOT snapshot. Triggers - "flutter", "libapp.so", "blutter", "dart AOT", "pointycastle", "flutter frida hook", "dart snapshot", "flutter reverse"
platform: [android]
stack: [flutter]
category: recon
tier: B
related: []
---

# Skill: Flutter AOT: blutter + Frida hooks to extract secrets at runtime

## What it solves
**Flutter release (Dart AOT)** apps: all Dart code compiles to a native snapshot in
`libapp.so`. jadx only sees the shell (`MainActivity extends FlutterActivity`). With blutter
you reconstruct the code (pseudo-asm + literals) and with Frida you hook the functions
by offset. It lets you extract encrypted keys/IV/strings, decrypt `integrity_check`-like
fields, and capture secrets at runtime. Typical case: a release Flutter app that
validates an `integrity_check` field (AES-**SIC**-PKCS7).

## Workflow

### 1. Detect the version
```
strings lib/arm64-v8a/libflutter.so | grep -E '^3\.[0-9]+\.[0-9]+'
# e.g.: "3.4.0 (stable) (Mon May 6 2024) on android_arm64"
```

### 2. Reconstruct with blutter
```
# blutter (github.com/worawit/blutter): the 1st time it compiles that version's Dart runtime
python3 blutter.py path/lib/arm64-v8a ./blutter_out
```
Output: `asm/<pkg>/...dart` (pseudo-asm + literals), `pp.txt` (indexed object pool),
`blutter_frida.js` (Frida helpers: `getDartString`, `getTaggedObjectValue`, class
offsets), `objs.txt`.

- Search `pp.txt` for all `String:` entries (long base64, URLs, tokens, `flag{`).
- The `s.replaceAll(frag, "")` obfuscation is visible verbatim in the asm (the
  fragment/base64 literals appear in the file itself).
- Note the address (offset) of each interesting function, e.g.:
  `decryptIntegrityCheck -> 0x1cfdc4`, `verifyDecryptedIntegrityCheck -> 0x1cfd70`,
  `Base64Codec::decode -> 0x345370`, `Encrypter::decrypt64 -> 0x1cfea4`.

### 3. Identify the crypto scheme (do NOT assume the mode!)
Look at the `AES()` constructor in the asm: the `Obj!AESMode@...` resolves against the
`Map<AESMode, String>` from the object pool (pp.txt). Typical map from package:encrypt:
`CBC, CFB-64, CTR, ECB, OFB-64/GCTR, OFB-64, SIC, GCM`.
- **pointycastle's SIC** = stream: `keystream = AES-ECB(key, ctr)` with `ctr=IV`
  incremented **big-endian** per 16B block, then XOR; with PKCS7 over the plaintext.
- App error `Invalid or corrupted pad block` = wrong mode (or bad key/IV).

### 4. Hook at runtime (Frida)
```js
const MOD = "libapp.so";
function waitModule(n){return new Promise(r=>{const t=setInterval(()=>{const m=Process.findModuleByName(n);if(m){clearInterval(t);r(m)}},100);});}
waitModule(MOD).then(mod=>{
  Interceptor.attach(mod.base.add(0x1cfdc4), function(){          // onEnter
    // arg in x2 (arm64 AOT snapshot, compressed-pointers)
    console.log(readDartStr(this.context.x2));
  });
});
```

**Reading a OneByteString from the AOT snapshot (compressed-pointers):**
```
obj   = taggedPtr.sub(1)        // strip the tag bit (+1)
len   = obj.add(8).readU32() >> 1   // length is a Smi (<<1)
data  = obj.add(16)                 // 1 byte/char, no terminator
```
- Dart pointers in registers are already expanded (heap base in `x28<<32`),
  but *fields* are compressed (32-bit) → `decompress(v) = heapAddr.add(v)`.
- Capture the heap in any onEnter with `this.context.x28.shl(32)`.

**Key/IV dump**: hook `Base64Codec::decode` and filter Uint8Lists of 16/32/44/24 bytes
(`_Uint8List` layout: len Smi @20, data @24, tagged = base+1). See
`frida_capture_key.js` in this directory.

**Capture the decrypted plaintext**: hook the *verifier* function that receives the
result (its arg x2): more reliable than `onLeave` (the retval can be a wrapper).

### 5. Verify offline
Reconstruct the server's encryption (same key/IV/mode) and confirm the roundtrip with
python/cryptography (mirror the same key/IV/mode the app uses).

## Gotchas
- `frida-ls-devices` dies without a TTY → `python3 -c "import frida; ..."` or a helper.
- The hook must be installed **after** `libapp.so` loads (use `spawn` + `waitModule`).
- Frida (QuickJS) has no `btoa` → implement base64 by hand.
- The plaintext sometimes does not appear on screen: the verifier only checks a
  prefix and the UI shows a decoy. The hook is the evidence.
- blutter: if `/private/tmp` has a broken repo, clone fresh (`git clone --depth 1`).
