---
name: android-native-so-re
description: Use when an APK loads a native library (System.loadLibrary) and you need to extract hardcoded strings, JNI function signatures, or return values from the .so using radare2 static analysis. Triggers - "libnative-lib.so", "radare2 .so", "JNI reverse", "native library analysis"
platform: [android]
stack: [native]
category: recon
tier: B
related: []
---

# Skill: android-native-so-re: Analysis of libnative-lib.so with radare2

> **When to use:** an APK loads a native library (`System.loadLibrary("native-lib")`) and you need to extract strings, JNI functions, or obfuscated functions that return hardcoded values.

## Setup

```bash
# Extract the .so from the APK (no need to install it)
unzip -o app.apk "lib/*" -d extracted/
# Try architectures: x86_64 > arm64 > x86 > armeabi-v7a
# x86_64 is easier to analyze in radare2 on macOS/Linux
ls extracted/lib/
```

## Basic analysis

### 1. List exported JNI functions
```bash
nm -D libnative-lib.so | grep Java
# Typical output:
# Java_com_package_Activity_methodJNI
```

The convention is: `Java_<package_with_underscores>_<Activity>_<method>`.

### 2. Hardcoded strings
```bash
strings libnative-lib.so | grep -iE "part|flag|secret|key|token|password"
```

### 3. Binary sections
```bash
r2 -q -e scr.color=0 -c "iS" libnative-lib.so
# Look for: .text, .rodata, .init_array, .fini_array
```

### 4. Exported functions (all symbols)
```bash
r2 -q -e scr.color=0 -c "aaa; afl" libnative-lib.so | grep "sym\."
```

## Pattern: obfuscated functions returning 1 char

In stripped native libraries, it is common to find C++ functions with obfuscated names (`_Z1bv` = `b()`, `_Z2crv` = `cr()`) that each return a single character:

```asm
sym.b__ ();
    0x000073e0      b07d           mov al, 0x7d    ; '}'
    0x000073e2      c3             ret
```

### Extract all chars in one shot

```bash
# List obfuscated functions (exclude C++ runtime and JNI)
r2 -q -e scr.color=0 -c "aaa; afl" libnative-lib.so \
  | grep "sym\." \
  | grep -vE "imp\.|Java|cxa|std|exception|alloc|cast|typeid|class_type|forced|foreign|guard|new|nothrow|terminate|unexpected|verbose|demangle|gcclib|si_class|operator"
```

### Disassemble each function

```bash
r2 -q -e scr.color=0 -c "aaa; s <addr>; pd 2" libnative-lib.so
# Look for: mov al, 0xNN
```

### Python script to automate

```python
import subprocess, re

SO = "libnative-lib.so"
ASCII_MAP = {}  # map any out-of-ASCII values the compiler emits, if needed

out = subprocess.run(["r2","-q","-e","scr.color=0","-c","aaa; afl", SO],
                     capture_output=True, text=True)
funcs = []
for line in out.stdout.splitlines():
    m = re.match(r'(0x[0-9a-f]+)\s+\d+\s+\d+\s+sym\.(\w+)', line)
    if m and not any(x in m.group(2) for x in ["Java","cxa","std","imp","operator"]):
        funcs.append((int(m.group(1),16), m.group(2)))
funcs.sort()

chars = []
for addr, fname in funcs:
    dis = subprocess.run(["r2","-q","-e","scr.color=0","-c",
                          f"aaa; s {addr}; pd 2", SO],
                         capture_output=True, text=True)
    m = re.search(r'mov al,\s*0x([0-9a-f]+)', dis.stdout)
    if m:
        val = int(m.group(1), 16)
        chars.append(ASCII_MAP.get(val, chr(val)))
print("".join(chars))
```

## Determine the call order

**Problem:** obfuscated functions often have no direct xrefs (they are called via tables, constructors, or pointers).

**Solutions, in order of preference:**

1. **Sort by ascending memory address**: works in most stripped libraries.
2. **Search xrefs:** `r2 -c "aaa; s <addr>; axt"`
3. **Look in `.init_array`**: pointers to functions that run when the lib loads.
4. **Dynamic hook with Frida**: intercept each function and log the call order.
5. **Common sense**: if the chars are `_and_cool}`, the order that forms that phrase is the correct one.

## Dynamic hook with Frida (when static is not enough)

```javascript
// frida -U -f <package> -l hook_native.js --no-pause
var lib = Module.findBaseAddress("libnative-lib.so");
var funcs = {
    "b": 0x73e0, "l": 0x73a0, "m": 0x7390, "q": 0x7380,
    "t": 0x73b0, "z": 0x7360, "cr": 0x7350, "ir": 0x73d0,
    "pr": 0x7370, "sr": 0x73c0
};
Object.keys(funcs).forEach(function(name) {
    Interceptor.attach(lib.add(funcs[name], {
        onLeave: function(retval) {
            console.log(name + "() -> " + String.fromCharCode(retval.toInt32()));
        }
    });
});
```

## ASCII reference table

| Hex | Char | Hex | Char | Hex | Char |
|-----|------|-----|------|-----|------|
| 0x20 | ` ` | 0x41 | `A` | 0x61 | `a` |
| 0x2d | `-` | 0x42 | `B` | 0x62 | `b` |
| 0x2e | `.` | 0x43 | `C` | 0x63 | `c` |
| 0x2f | `/` | 0x44 | `D` | 0x64 | `d` |
| 0x30-0x39 | `0-9` | 0x45 | `E` | 0x65 | `e` |
| 0x3b | `;` | 0x46 | `F` | 0x66 | `f` |
| 0x3d | `=` | ... | ... | ... | ... |
| 0x5f | `_` | 0x5a | `Z` | 0x7a | `z` |
| 0x7b | `{` | | | 0x7d | `}` |

## Antipatterns

- **Do NOT** assume `oneLastThing()` (declared `native void`) has logic: it can be an empty `ret` (dummy).
- **Do NOT** analyze armeabi-v7a if you have x86_64 available: x86_64 is more readable in radare2.
- **Do NOT** forget that `strings` is your first tool: it reveals strings without any RE.
- **Do NOT** trust obfuscated function names (`_Z1bv` = `b()`) for the order: use addresses.

## Alternatives to radare2

| Tool | Pros | Cons |
|------------|------|---------|
| `r2` (radare2) | Fast, CLI, scriptable | Learning curve |
| Ghidra | Decompiles to C, GUI | Heavy, requires Java |
| `objdump -d` | Ubiquitous, simple | No decompilation |
| Frida (dynamic) | Sees the real call order | Requires a device |
