---
name: ios-buffer-overflow-objectivec
description: Use when an iOS Objective-C app has fixed-size buffers adjacent to protected data, with debug functionality visible via nm symbols (a flag/secret getter and a debug handler). Overflows a buffer to reach the flag code path. Triggers - "iOS buffer overflow", "Objective-C overflow", "fixed buffer", "debug mode iOS", "adjacent memory"
platform: [ios]
stack: [native]
category: vectors-misc
tier: B
related: []
---

# iOS Buffer Overflow in Objective-C (string > fixed buffer → flag)

## When to use
- iOS app in Objective-C (not Swift) with `nm` showing `_flag`, `scanURL:`, `handleDebugRequest:` functions.
- `strings <binary>` shows an embedded expected value or secret.
- The app exposes a debug path ("buffer overflow", "fixed-size buffer", "adjacent memory", "debug functionality").
- There is a debug mode (`enableDebugModeWithURL:`, `debugModeEnabled`).

## Steps

1. **Static recon**: `nm <binary> | grep -iE "flag|scan|debug|buffer"` → locate `_flag` and `scanURL:`.
2. **Recon `_flag`**: `r2 -c 'aaa; s sym._flag; pd 40' <binary>` → identify the overflow branch.
3. **Identify the fixed buffer**: look for `strlen(s) > N` in `_flag`: the buffer is N bytes (typically 32).
4. **Identify the expected string**: `strings <binary> | grep -iE "[A-Za-z0-9_]+\{[^}]{4,}\}"` → the embedded value.
5. **Rebuild the exploit**:
   - Enable debug mode (`enableDebugModeWithURL:`)
   - Send a URL > N bytes that overflows the buffer
   - The value at the correct offset must match the flag string
6. **Verify**: if the comparison in `_flag` matches, the flag is revealed.

## Pitfalls / Edge cases
- **Swift vs Objective-C**: in Objective-C, `nm` shows symbols; in stripped Swift, use `ObjC.enumerateLoadedClasses`.
- **Stack canary**: `__stack_chk_fail` detects the smashing if the overflow does not match the flag.
- **Debug mode**: debug mode may be required for the overflow to be processed (without debug, the normal scan does not overflow).
- **The flag is in `.cstring`**: `strings` finds it; `r2` shows the reference in the disassembly.
- A full chain requires demonstrating the overflow, not just reading an embedded value.

## Verification
- `_flag` returns the flag string when the comparison matches.
- `__stack_chk_fail` is called if it does not match (stack smashing).
- Confirm end to end: the comparison in the target function matches and the value is returned.
