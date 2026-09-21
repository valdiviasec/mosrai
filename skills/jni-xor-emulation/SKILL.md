---
name: jni-xor-emulation
description: Use when a JNI function builds a string at runtime by XORing two rodata tables and you want to solve it statically by emulating the x86_64 prologue without a device or Frida. Triggers - "JNI XOR emulation", "rodata XOR tables", "static emulation .so", "punpcklqdq XOR"
platform: [android]
stack: [native]
category: crypto
tier: B
related: []
---

# Skill: JNI-XOR-Emulation: solve the JNI function statically by emulating the prologue

## When to use
- The JNI function does not contain the string in the target: it builds it byte by byte by XORing two rodata tables.
- There is no frida-server available (or you want a reproducible solver without a device).
- The JNI function is small and the compiler (clang/NDK) left it with symbols (`nm -D lib*.so`).

## Steps
1. Extract the correct `.so` per ABI: `unzip -o app.apk -d apk && file apk/lib/*/lib*.so` (Genymotion = x86_64).
2. Locate the function: `nm -D lib/x86_64/libnative-lib.so | grep Java_`.
3. Disassemble: `objdump -d --start-address=0x... --stop-address=0x... lib.so` and look at the pattern:
   - `leaq 0x...(%rip), %rax` + `punpcklqdq %xmm0,%xmm1` + `movdqa %xmm1, off(%rsp)` = the compiler materializes rodata pointers on the stack (8 bytes per char, pointers to each char).
   - Then a loop: `for (i=0; i<N; i++) out[i] = key[i] ^ cipher[i];` reading the tables with stride 8.
4. Script the parse: extract the rodata pointer tables from the objdump output and XOR them in order (Python or a disassembler script).

## Pitfalls / edge cases
- **The first key byte is NOT in the stack table**: it stays alive in `%rcx` (the last `leaq → %rcx` of the prologue). Modeling it wrong gives a corrupted result (classic off-by-one).
- **`objdump` resolves jumps as `#` comments**: cut the `insn` at `#`.
- **Stack stores are not only from `%rcx`**: there is also `movq %rax, off(%rsp)`. Track `rax` and `rcx` separately (the `leaq` of `0x2b6b0` ends up in `%rax`).
- **`movdqa %xmmN, %xmmM`** (reg-reg copy) appears in the prologue; you must handle it.
- **File offset == VMA** in these Android `.so` files (no weird PT_LOAD offsets): for low VMAs, `xxd -s <VMA>` reads the rodata bytes directly.
- The rodata chars are **2-byte UTF-16LE** (`61 00` = 'a'): when emulating, read 2 bytes and take the low byte.

## Validation
- The solver must print the recovered string; sanity-check that it looks like a plausible key/password.
- Cross-check dynamically with `frida-jni-string-dump` (must match).
