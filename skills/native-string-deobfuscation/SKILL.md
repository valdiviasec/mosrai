---
name: native-string-deobfuscation
description: "Use when an Android/iOS native library (.so) builds obfuscated strings at runtime by moving individual bytes or using XOR/ADD operations, requiring static or dynamic deobfuscation."
platform: [ios, android]
stack: [native]
category: recon
tier: B
related: []
---

# Skill: Native String Deobfuscation via Stack-Built Dword Arrays

## When to use
Android/iOS native library (.so) that builds obfuscated strings at runtime by moving
encoded 32-bit immediates to consecutive stack slots, then calling a decoder helper.
Common in hardened apps and packers that hide JNI class/method names, file paths,
and DEX payloads.

## Detection signals
- `JNI_OnLoad` or `JNI_OnLoad` early in the .so contains dozens of
  `mov dword [var_Xh], 0xIMM` instructions followed by `call <helper>`
- `strings` output shows JNI class descriptors (`Lcom/...`), file paths, or
  method signatures as **fragments** or not at all (they are encoded)
- A small helper function is called many times, each time with a different
  count argument and a fresh set of stack dwords

## Method

### 1. Identify the decoder helper
Look for a function called repeatedly from `JNI_OnLoad` that:
- Takes a count (number of dwords) and a pointer to a stack array
- `malloc(count * 2 + 1)` for the output buffer
- Loops over the dwords producing 2 output bytes each
- Returns a null-terminated string

### 2. Reverse the decode formula
Common patterns (derive from the actual bit manipulation in the helper):

**Pattern A: adjacent-byte XOR:**
```
For each 32-bit dword v (little-endian: b0 | b1<<8 | b2<<16 | b3<<24):
  out[2*i]   = b1 ^ b0          # byte1 XOR byte0
  out[2*i+1] = b3 ^ b2          # byte3 XOR byte2
```

**Pattern B: simple XOR with constant:**
```
  out[i] = v_byte[i] ^ CONSTANT
```

**Pattern C: byte rotation / subtraction:**
```
  out[i] = (v_byte[i] - K) & 0xff
```

### 3. Extract the dword arrays from disassembly
- Dump `JNI_OnLoad` disassembly: `r2 -q -c 'aaa; s sym.JNI_OnLoad; pD <size>' lib.so`
- Each group = sequence of `mov dword [var], IMM` + `mov dword [esp], COUNT` + `call helper`
- The array order is **lowest stack address first** (r2 var names: `size < nitems < stream < var_10h < ... < var_54h`)
- Group count = the `mov dword [esp], N` value right before the call

### 4. Script the extraction
```python
import re
def var_off(name):
    m = re.match(r'var_([0-9a-f]+)h', name)
    if m: return int(m.group(1), 16)
    return {'size':4,'nitems':8,'stream':0xc}.get(name, 0x1000)

# Parse asm: collect mov dword [var], IMM; on 'call helper', sort by offset, decode
```

## Pitfalls
- **Stack ordering**: r2 names stack vars by offset from frame base. The array is read
  from lowest address upward: sort var names numerically before decoding.
- **Count vs ndwords**: the count argument should equal the number of dwords; if
  they don't match, the array start offset may differ by one slot (check the
  `lea eax, [arg]` in the helper to confirm where the array begins).
- **Null terminators**: the decoder appends `\0`; some decoded strings have
  embedded `\0` (e.g. UTF-16 or multi-field buffers).

## Tools
- `radare2`: disassembly, function analysis
- `jadx`: DEX decompilation (after extracting embedded DEX)
- Python: scripting the decode + flag recovery
