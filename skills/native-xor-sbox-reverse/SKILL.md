---
name: native-xor-sbox-reverse
description: Use when JNI check functions in a .so apply affine XOR transformations or S-box permutation table lookups to validate (constant, secret) pairs, requiring radare2 disassembly to extract constants and invert the bijection. Triggers - "S-box XOR native", "affine XOR mN", "permutation table .so", "native bijection reverse"
platform: [android]
stack: [native]
category: crypto
tier: B
related: []
---

# Skill: Reverse `((c^K1)^(s^K2))` and S-box XOR natives from an Android .so

## When to use
JNI check functions in `lib/*/lib*.so` that turn a `(constant, secret)` pair
into a byte to compare against a target. Two recurring shapes:

### Shape A: affine XOR (most `mN`)
```c
int mN(int c, int s) {
    return ((c + K1) ^ (s - K2)) & 0xff;        // K1,K2 per function
}
```
A bijection in `c` for fixed `s` → a byte checked with `& 0xff == T` has a
**unique** solution.

### Shape B: S-box XOR (e.g. last bytes)
```c
int mN(int c, int s) {
    return sboxA[(c + Ka) & 0xff] ^ sboxB[(s - Kb) & 0xff];
}
```
`sboxA/B` are `int[256]` permutation tables in `.data`. Still a bijection in
`c` (for fixed `s`) when `sboxA` is a permutation.

## Reading them with radare2 (x86_64 easiest)
```bash
r2 -q -c 'aaa; pdf @ sym.Java_pkg_Solver_m0' lib/x86_64/libnative-lib.so \
  | sed 's/\x1b\[[0-9;]*m//g'
```
Signs:
- Shape A: `lea esi,[rdx+K1]` … `lea edx,[rcx-K2]` … `and eax,0xffffff00` …
  `sub` … `xor eax,esi` … `ret`. The `and 0xffffff00` + `sub` is the compiler's
  signed `% 256` idiom; the result is the low byte of `(c+K1)^(s-K2)`.
- Shape B: ends with `mov rdx,[reloc.sA]; mov rsi,[reloc.sB]; mov eax,[rsi+rax*4];
  xor eax,[rdx+rcx*4]; ret`. The two arrays come from GOT relocations.

## Extracting the S-boxes
- `is~s` lists data symbols with `paddr`/`vaddr`/size (1024 = `int[256]`).
- Read straight from the file at `paddr` (LE int32):
  ```python
  import struct
  blob = open("lib/x86_64/libnative-lib.so","rb").read()
  sbox = [struct.unpack_from("<i", blob, 0x2010 + i*4)[0] for i in range(256)]
  ```
  (r2's `px @ vaddr` can mis-map; trust the file offset / Python read.)
- Confirm each is a permutation: `set(sbox) == set(range(256))`.

## Runtime-mutated S-box (fold it in)
A `void mN(x)` called just before a Shape-B check may fill a `.bss` S-box:
`for i: s4[i] = s5[i] ^ x` (SSE: `movdqa; pxor xmm0; movdqa`). The XOR is
32-bit but the check `& 0xff` keeps only `x & 0xff`, so fold it into the
formula: `mN(c,s,x) = (s5[(c+Ka)&0xff] ^ sboxB[(s-Kb)&0xff] ^ (x&0xff)) & 0xff`.
Here `x` is usually a function of earlier input bytes (e.g. a sum): compute
it from the already-solved bytes.

## Solving per byte
For byte position `k` with table `T[k]` (maps flag-byte value → constant):
```
candidates = [v in 0..255 if ( mK(T[k][v], secret_k) & mask_k ) == target_k ]
```
- `mask_k == 0xff` ⇒ 1 candidate (unique).
- `mask_k < 0xff` ⇒ the cleared bits are free ⇒ a handful of candidates; let
  the final checksum disambiguate.
- A byte with **no native call** (only e.g. `(b & FLAG) == FLAG`) has many
  candidates and is pinned purely by the checksum.
