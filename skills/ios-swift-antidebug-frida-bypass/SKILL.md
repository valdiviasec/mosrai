---
name: ios-swift-antidebug-frida-bypass
description: Use when an iOS Swift app terminates or blocks functionality upon detecting Frida, jailbreak, or a debugger (ptrace/PT_DENY_ATTACH, amIReverseEngineered). Replaces anti-debug and jailbreak-check functions via Frida Interceptor.replace to keep the app alive. Triggers - "ptrace", "PT_DENY_ATTACH", "Noncompliant device", "amIReverseEngineered", "FridaGadget", "anti-debug"
platform: [ios]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---

# Skill: iOS Swift anti-debug / jailbreak bypass (Frida)

## When to use
An iOS app (Swift, Mach-O arm64) that closes, shows "Noncompliant device detected!" or blocks the flag when it detects Frida/jailbreak/debugger. Symptoms: strings with `ptrace`, `_disable_gdb`, `amIReverseEngineered`, `FridaGadget`, `frida-server`, `libcycript`, `Suspicious file found`.

## Steps

### 1. Static (local, no device)
```bash
unzip app.ipa -d out/
cd "out/Payload/App.app"
strings -a "App" | grep -iE "ptrace|jail|frida|hook|flag|detect"
nm -gU "App" | grep -iE "disable|Reverse|Checker|getFlag|whereIs"
otool -tv "App" | sed -n '/_disable_gdb:/,/^_/p'   # ptrace(PT_DENY_ATTACH) via dlsym
```
- `_disable_gdb` = `dlsym(RTLD_DEFAULT,"ptrace"); ptrace(0x1f /*PT_DENY_ATTACH*/,0,0)`: called from `viewDidLoad`.
- `amIReverseEngineered` = wrapper of `performChecks` (FailedCheck enum: suspicious files, DYLD, ports, PSelect flag): returns `passed ^ 1`.
- The flag routine = decryption logic (base64 + XOR + AES-CBC with CryptoSwift). Reconstructing it in Python from the symbols/strings is the fastest path.

### 2. Install on jailbroken (TrollStore/rootless)
`ideviceinstaller install` fails with `ApplicationVerificationFailed` (invalid signature). On rootless:
```bash
iproxy 2222 22 -u <UDID> &          # SSH tunnel over USB
sshpass -p 'root' ssh -p 2222 root@127.0.0.1
scp -P 2222 -r "Payload/App.app" root@127.0.0.1:/var/jb/Applications/
ssh ... '/var/jb/usr/bin/ldid -S "/var/jb/Applications/App.app/App"; chown -R root:wheel ...; uicache -a'
```

### 3. Dynamic bypass (Frida, spawn + pause)
```js
// ptrace: replace the whole function
Interceptor.replace(m.base.add(0x8000), new NativeCallback(() => {}, 'void', []));
// jailbreak check: force false
Interceptor.replace(m.base.add(0xd1e8), new NativeCallback(() => 0, 'bool', []));
```
Always `device.spawn()` (not attach): the `viewDidLoad` ptrace kills the process if it is already running.

### 4. Extract the flag (Swift String in registers)
`getFlag` returns a `Swift.String` (16 bytes in x0/x1):
- x0 = flags/count (count = `x0 & 0xffff`)
- x1 = pointer to `_StringStorage` (isa +0x0, refcount +0x8, capacity +0x10, count +0x18, **data at +0x20**)
```js
Interceptor.attach(getFlag, { onLeave() {
  const count = this.context.x0.toUInt32() & 0xffff;
  const flag = this.context.x1.add(0x20).readUtf8String(count);
}});
```
Strings ≤15 bytes are inline (bytes in x1 itself): there is no storage.

## Pitfalls / edge cases
- **ObjC bridge unavailable**: Swift-only apps do not expose `ObjC.classes` in Frida → do not use `ObjC.classes._TtC...`; use NativeFunction + registers.
- **ptrace kills the process**: if the hook is not installed before `viewDidLoad`, the process dies. Use spawn + hook in `setTimeout(100)`.
- **`Interceptor.replace` instead of `attach`**: `attach` does not prevent ptrace from running; `replace` neutralizes it.
- **Signature**: `codesign -s -` (adhoc) is also rejected by installd; on rootless use `/var/jb/usr/bin/ldid -S` + copy to `/var/jb/Applications` + `uicache -a`.
- **Rootless SSH**: the password is usually `root` (not `alpine`).
- **Flag strings**: the plaintext is NOT in strings; it is encrypted (AES-CBC). Look for base64 + obfuscated byte arrays (XOR) in the disassembly.
