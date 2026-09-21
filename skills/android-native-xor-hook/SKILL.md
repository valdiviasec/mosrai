---
name: android-native-xor-hook
description: Use when a native library constructs a secret by XOR-ing data and key arrays at a specific instruction: hook the XOR (eor/xor) instruction with Frida Interceptor to capture each byte of the result at runtime. Triggers - "XOR hook native", "eor instruction", "Interceptor XOR", "native secret XOR"
platform: [android]
stack: [native]
category: crypto
tier: B
related: []
---


# android-native-xor-hook: Native secrets via XOR instruction hook

## When
- Secret in `lib*.so` built with `data[i] ^ key[i]` in a loop.
- `strings` shows `data[]` (plaintext decoy) but the real secret is the XOR result.
- You need the secret at runtime without reconstructing the logic offline.

## Recipe

### 1. Locate the XOR offset
```bash
# disassemble the arm64 .so
objdump -d lib/arm64-v8a/libnative-lib.so | grep eor
# arm64:  7cc: 4a0b014a   eor w10, w10, w11
# x86:    6cf: 31 c8      xor eax, ecx        (offset 0x6cf)
```
`data[i]` is in `w10` (arm64) or `eax` (x86); `key[i]` in `w11`/`ecx`.

### 2. Dump strings in ro.data
```javascript
// after getting the base via Process.findModuleByName (see step 3)
// offset of the data[] string (e.g. 0x085d arm64 / 0x074d x86)
hd(base.add(0x085d), 64);
// parse until a non-printable byte
```

### 3. Hook the XOR instruction
> **Frida 17 API**: `Module.findBaseAddress()` does NOT exist. Use `Process.findModuleByName(name).base`.
> Native libs can load late (lazy-load when a button is pressed) → retry until it exists.

```javascript
var arch = Process.arch;
var eorOff = (arch === 'arm64') ? 0x7cc : (arch === 'ia32') ? 0x6cf : 0x7cc;
var dyn = '', idx = 0;

function hookEor() {
    var mod = Process.findModuleByName("libnative-lib.so");   // correct Frida 17 API
    if (!mod) { return setTimeout(hookEor, 500); }             // retry if lazy-load
    var base = mod.base;

    Interceptor.attach(base.add(eorOff), function () {
        if (idx >= 32) { idx = 0; dyn = ''; }   // reset on each invocation
        var x, y;
        if (arch === 'arm64') { x = this.context.x10 & 0xff; y = this.context.x11 & 0xff; }
        else { x = this.context.eax & 0xff; y = this.context.ecx & 0xff; }
        dyn += String.fromCharCode((x ^ y) & 0xff);
        if (++idx === 32) console.log("[secret] " + dyn + " (len=" + dyn.length + ")");
    });
    console.log("[+] eor hooked @ 0x" + eorOff.toString(16));
}
hookEor();
```

### 4. Trigger the native function
- The app must call the JNI method containing the loop (e.g. press a button).
- If it is lazy-loaded, hook `System.loadLibrary` to wait for the module.

## Offline alternative (no Frida)
```python
data = bytes.fromhex("4e61746976655f633064...")  # from strings/ro.data
key  = bytes.fromhex("2c00170212556f111429467b...")
secret = bytes(d ^ k for d, k in zip(data, key))
print(secret.decode())  # backd00r$Mu$tAlw4ysBeF0rb1dd3n$$
```

## Pitfalls
- **Frida 17 API**: `Module.findBaseAddress()` and `Module.enumerateExports()` do NOT exist as statics. Use `Process.findModuleByName(name)` and `mod.enumerateExports()`. Old scripts (Frida 12/14) used them: migrate.
- **Lazy-load**: the `.so` may not be loaded at spawn → retry with `setTimeout` until `Process.findModuleByName` returns non-null.
- **Multiple invocations**: the hook accumulates across calls → keep a counter and reset when reaching `n` (length of `data`).
- **PIE/ASLR**: use `Process.findModuleByName` + relative offset, never an absolute address.
- **arm64 vs x86**: offsets and registers change: detect with `Process.arch`.
- **`strlen` at runtime**: the loop may use `strlen(data)` as the limit; if `data` has an internal null byte, the loop stops short. Verify with a hexdump.

## Verification
CyberTruck19 CH3 (arm64): `eor @ 0x7cc`, `x10^x11` → `backd00r$Mu$tAlw4ysBeF0rb1dd3n$$` (32 chars).
