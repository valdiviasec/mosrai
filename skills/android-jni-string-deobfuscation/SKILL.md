---
name: android-jni-string-deobfuscation
description: Use when a native Android library builds strings on the stack using 0xFFFFFFFF + offset patterns (byte-by-byte ADD obfuscation): extract the offsets from disassembly to recover hidden keys or flags statically. Triggers - "0xffffffff pattern", "stack string construction", "JNI string obfuscation", "native string extraction"
platform: [android]
stack: [native]
category: crypto
tier: B
related: []
---

# Skill: android-jni-string-deobfuscation

Recover obfuscated strings (`0xffffffff + offset` pattern or equivalents) in Android native libraries: used by apps that hide messages, keys, or constants in the binary.

**Triggers:** "obfuscated strings", "obfuscated string", "extract string from .so", "0xffffffff pattern", "libnative-lib", JNI reverse.

## When to use

- The `.so` shows no readable strings with `strings` (byte-by-byte runtime obfuscation).
- The JNI function builds constants on the stack: pattern `movl $0xffffffff, reg` + `addl $imm8` + `movb %cl, %al` + store to `off(%esp)`.
- You want to extract the flag/message/key without running the binary.

## Pipeline

### 1. Find the pattern

```bash
objdump -d lib/x86/libnative-lib.so > /tmp/natlib.asm
grep -n "Java_.*stringFromJNI\|Java_.*" /tmp/natlib.asm
```

Locate the start of the JNI function (the `Java_<pkg>_<class>_<method>` symbol). The obfuscation pattern:
```
movl   $0xffffffff, 0x58(%esp)     ; base = -1 (0xffffffff)
movl   0x58(%esp), %ecx
addl   $0x42, %ecx                 ; offset -> 0xff + 0x42 = 'A'
movb   %cl, %al
movb   %al, 0x70(%esp)             ; store byte on the stack
...
movb   $0x0, 0x87(%esp)            ; NUL terminator
```

### 2. Extract the offset sequence (script)

```python
import re
data = open('/tmp/jnifunc.asm').read()
# cut the function from the symbol to the next one
func = data.split('<Java_..._stringFromJNI>')[1].split('\n\n')[0]
# offsets in program order (use the correct register, eax or ecx)
offs = re.findall(r'addl\s+\$(0x[0-9a-fA-F]+),\s+%(?:eax|ecx)', func)
base = 0xffffffff
print(''.join(chr((base + int(o,16)) & 0xff) for o in offs))
```

> Note: the first instruction is usually the PIC prologue's `addl $0x1a78, %eax` (GOT base): discard it (it is an address offset, not a character). The real string starts at the first `addl` that operates on the value loaded from the slot containing `0xffffffff`.

### 3. Cross-check (GOT / binary strings)

The string obfuscation pattern usually coexists with plain strings in `.rodata`. Pointers are computed PIC-style:

```
GOT_base = address_after_the_call + imm32
string_off = GOT_base - delta   (appears as leal -0x15d5(%eax) or similar)
```

```python
data = open('libnative-lib.so','rb').read()
got = 0x564 + 0x1a78              # address after `calll` (0x564) + addl imm (0x1a78)
for delta in (0x15d5, 0x15c7):    # deltas seen in leal
    off = got - delta
    print(data[off:off+40])       # -> b'Not activated', b'LICENSEKEYOK'
```

## Verdict

- Byte-by-byte obfuscation is **not** cryptography: it is trivially reversible with objdump + a 5-line script.
- If the app's "secret key" (verification/license/encryption) can be extracted this way, the security control is broken by design. Report as *client-side crypto* / *hardcoded key* (skill `android-flutter-aot-key-extraction`, `hybrid-client-crypto`).
