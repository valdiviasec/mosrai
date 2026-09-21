---
name: ios-jailbreak-bypass-frida
description: Use when an iOS Swift app runs jailbreak detection at launch (isJailbroken checking Cydia paths, /bin/bash, canOpenCydia) and blocks functionality on jailbroken devices. Bypasses via Frida Interceptor.attach on the detection function, forcing retval to 0, or via static binary patching (mov w0,#0x0). Triggers - "isJailbroken", "jailbreak detection iOS", "Cydia.app check", "canOpenCydia", "jailbreak bypass frida", "retval replace 0"
platform: [ios]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---

# Skill: iOS jailbreak bypass with Frida (Swift, ret 0)

**When to use**: An iOS app that runs jailbreak detection at startup (`viewDidLoad`) and aborts or blocks functionality on a jailbroken device. Typical signals: an `isJailbroken()`-style method in a view controller, strings such as `"Jail broken device!"`, paths like `/private/var/lib/apt/` or `/Applications/Cydia.app`, or a `canOpenCydia` helper.

**Steps**:
1. Locate the detection function. Prefer a runtime lookup over a pinned offset:
   ```bash
   nm -nm <binary> | grep -i jail          # symbol name (may be Swift-mangled)
   ```
   If the symbol is stripped, find its address by scanning the disassembly (r2/Ghidra) for the Swift-mangled substring (`isJailbroken`) or its callers, and resolve it at runtime instead of hardcoding an offset.
2. Frida spawn (`frida -D <UDID> -f <bundle_id> -l bypass.js`) and force the return value to false:
   ```js
   var mod = null;
   Process.enumerateModules().forEach(function (m) {
       if (m.path.indexOf("<binary-substring>") !== -1) mod = m;
   });
   // Resolve the symbol; fall back to the offset computed from `nm` output.
   var impl = mod.findExportByName ? mod.findExportByName("<mangled_symbol>") : null;
   if (impl) {
       Interceptor.attach(impl, {
           onLeave: function (retval) { retval.replace(ptr(0)); }  // force false
       });
   }
   ```
   When the method is Objective-C-visible, use `ApiResolver('objc')` or `ObjC.classes` to bind to the selector instead of an address.
3. Static alternative (patching): in Ghidra/r2, change the return to false (`mov w0,#0x1` → `mov w0,#0x0`, bytes `20 00 80 52` → `00 00 80 52`) in each return site of the detection function; re-sign with `ldid -S` and reinstall.

**Pitfalls**:
- `Module.findBaseAddress("<name>")` can return null when the module name has spaces or is the main executable → iterate `Process.enumerateModules()` and match on `path`.
- Hook `onLeave` (not `onEnter`) to force the return value.
- A rootless device may still detect by paths; the Frida bypass is enough to continue.
- Multiple detection call sites may exist; patch or hook all of them, not just the first.
