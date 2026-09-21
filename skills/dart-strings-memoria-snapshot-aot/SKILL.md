---
name: dart-strings-memoria-snapshot-aot
description: Use when hooking a Flutter release app (Dart AOT snapshot with compressed-pointers) and you need to read Dart strings, byte arrays, or function arguments from memory via Frida. Documents exact memory layouts for OneByteString (+16 data, +8 Smi length), TwoByteString, _Uint8List, and compressed-pointer decompression using the heap base register (x28). Triggers - "Dart string memory", "Flutter Frida hook", "AOT snapshot", "compressed pointers", "OneByteString layout", "readDartString", "Dart VM heap"
platform: [android]
stack: [flutter]
category: recon
tier: B
related: []
---

# Skill: Dart strings in memory: AOT snapshot (compressed-pointers)

## What it solves
Reading Dart strings/byte arrays directly from memory with Frida in Flutter release
apps (AOT snapshot with `compressed-pointers`). The foundation for all argument/return
capture hooks. Typical case: a release Flutter app (Dart AOT, compressed pointers).

## Verified layouts (Dart VM 3.4.0, arm64, product, compressed-pointers)

### OneByteString (ASCII, cid 93)
```
tagged_ptr = obj_base + 1          # old-space tag bit
offset +0  : tags (4B)             # cid in bits 12+
offset +8  : length as Smi (4B)    # real = value >> 1
offset +16 : data (1 byte/char, NO NUL terminator)
```
```js
function readDartString(taggedPtr){
  const obj = taggedPtr.sub(1);
  const len = obj.add(8).readU32() >> 1;      // Smi
  if (len < 0 || len > 8192) return null;
  return obj.add(16).readUtf8String(len);
}
```

### TwoByteString (UTF-16, cid 94)
Same but `readUtf16String(len)` at +16.

### _Uint8List (cid 115)
```
tagged_ptr = base + 1
+20 : length Smi (>>1)
+24 : data (1 byte/element)
```

### Compressed pointers (object fields)
- **Registers** (`x0..x7`, stack args) already carry the pointer expanded to the heap.
- **Object fields** store 32-bit compressed values → `heapAddr + u32`.
- `heapAddr = x28 << 32` (capture it in any onEnter).

```js
function decompress(v){
  const u = (typeof v === "number") ? v : v.toInt32();
  return heapAddr.add(u);
}
```

### Dart function arguments (arm64 ABI)
- args 0-7 in `x0..x7`; arg i in `context['x'+i]`.
- `this` (receiver) goes in `x1`; real args start at `x2`.
- NOTE: the function can **reorder** parameters in the prologue
  (`mov x4,x2; mov x2,x5; ...`): read blutter's asm for the correct slot.

## Typical mistakes when reading strings
| Symptom | Cause |
|---|---|
| `<weird len 2147483648>` | reading length at +4 instead of +8 (Smi) |
| text with garbage bytes | pointer = base+tag without `sub(1)` |
| `access violation` | the value was a compressed field (missing `decompress`) |
| empty string but data exists | data offset = +16, not +12 |
| huge len | forgetting the Smi `>>1` |

## Quick verification
Hook the target function and dump `hexdump(ptr.sub(1), 64)`: the first 8 bytes are
tags+len; the ascii text starts at +16. Confirmed on Fly Away:
```
+0  [tags 4B]
+8  80 00 00 00   <- len 64 (Smi 0x80 >> 1)
+16 37 62 59 72   <- '7bYr' (base64 ciphertext)
```

## Frida 17
`Memory.readByteArray(ptr, len)` was removed → use `ptr.readByteArray(len)`.
