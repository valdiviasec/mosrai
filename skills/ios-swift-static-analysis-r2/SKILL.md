---
name: ios-swift-static-analysis-r2
description: Use when analyzing a Swift iOS Mach-O arm64 binary with radare2 to locate string references, map boolean logic, or reconstruct keyword arrays in __DATA. Provides r2 command patterns for Swift-specific static analysis. Triggers - "Swift radare2", "Mach-O analysis", "Swift static analysis", "r2 Swift", "_TtC mangled"
platform: [ios]
stack: [native]
category: recon
tier: B
related: []
---

# Skill: Static analysis of Swift/iOS binaries with radare2 (no Ghidra)

## When to use
- A Mach-O arm64 binary from a Swift app (strings with `_TtC11...` = mangled names).
- You need to locate which function uses a string, map boolean flag logic, or reconstruct keyword arrays in `__DATA`.

## Steps
```bash
# Strings with addresses (radare2)
r2 -q -c 'izz~<pattern>' binary          # list strings with vaddr
r2 -q -c 'izz~MHC' binary               # search for flag/pattern

# Who references a string
r2 -q -c 'aaa; axt 0x10002fe00' binary  # xrefs to the string

# Disassemble the function that uses it
r2 -q -c 'aaa; s sym.func.1000107d0; pdf' binary

# Memory dump at an address (keyword arrays, seed data)
r2 -q -c 'px 256 @ 0x100044820' binary

# Binary sections
r2 -q -c 'iS' binary
```

## Interpreting Swift patterns
- `strb w8, [x22, 0x65a]` → sets a boolean flag on an object (e.g. `_systemPromptBypassed`). Look for who reads it (`ldrb w8, [x22, 0x65a]` + `cmp w8, 1`).
- `mov x8, 0x6573; movk x8, 0x7261, lsl 16` → builds short inline strings ("sear", "web", "user"...). The `movk` with lsl 16/32/48 assemble the word in little-endian.
- Arrays of strings in `__DATA.__data` (e.g. `0x1000448a0`): each entry is `[len][ptr]`; the strings live in `__TEXT.__cstring`. `px` shows you the layout.
- `lowercased__String` + chained comparisons (`Foundation...SyRd__lF` = `hasPrefix`/`contains`) → keyword matching logic.
- `sqlite3_prepare_v2` + `sqlite3_step` + `sqlite3_column_text` → real local SQL execution.
- `swift_getKeyPath` + `Combine.Published...` → writes to @Published properties (UI state changes).

## Pitfalls / edge cases
- **`axt` requires `aaa` first** and may not resolve xrefs for strings in `__DATA` (relocs). If there are no xrefs, search for the pointer's byte pattern: `python3 -c "struct.pack('<Q', 0x10002fe00)"` and look for it in the file.
- **Long UTF-8 strings** (prompts) live in `__TEXT.__cstring`; `strings -a` shows them in full. Prompts with emojis/multibyte UTF-8 can get split: use `izz` to see exact ranges.
- **Swift does not export methods to ObjC**: `ObjC.classes['_TtC...'].$ownMethods` gives empty lists. To hook, use Frida with `Module.findExportByName` or intercept `sqlite3_*`/`NSURLSession`.
- **r2's ANSI color dirties the output**: `sed 's/\x1b\[[0-9;]*m//g'`.
- **macOS `strings` does not support `-e l`** (UTF-16); use `xxd` + grep for hex patterns.
- **Dummy flags**: if you cannot find `MHC{` in the binary, the flag is generated at runtime (DB seed) or lives on the lab's remote device. Document the exploit; do not waste hours looking for a string that does not exist.
