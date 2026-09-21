---
name: emulator-dns-redirect-bind-mount
description: Use when you need to redirect an Android emulator's DNS to a local mock server via bind-mounting a custom hosts file, without breaking native library loading. Triggers - "bind mount hosts", "emulator DNS redirect", "mock server", "custom hosts file"
platform: [android]
stack: [native]
category: enabling
kind: enabling
tier: A
related: []
---

# Skill: emulator-dns-redirect-bind-mount

**Category:** mobile / dynamic analysis / network mock

Redirect a hostname from a rooted Android emulator to a local mock server
without breaking native library loading.

## When to use
- You need to point an app at a local mock server (offline backend, internal
  API, etc.) but the app uses a hardcoded hostname.
- The emulator is rooted (Genymotion, or AVD with `su`).
- `/system` is read-only and you can't edit `/system/etc/hosts` directly.

## The problem with naive approaches
1. **`mount -o rw,remount /system`**: often fails on modern Android (system
   is `ext4 ro` and not in `/proc/mounts` as `/system`).
2. **`mount -t tmpfs tmpfs /etc`**: breaks native libs because `/etc` is a
   symlink to `/system/etc`, and overlaying tmpfs hides
   `public.libraries.txt`, causing app crashes.
3. **iptables `OUTPUT REDIRECT --to-port`**: doesn't help if DNS resolution
   fails before the TCP connection.

## The clean solution: bind-mount a custom hosts file
```bash
DEVICE="127.0.0.1:6555"

# 1. Write a custom hosts file to a writable location
adb -s "$DEVICE" shell "su -c 'printf \"127.0.0.1 localhost\\n::1 ip6-localhost\\n127.0.0.1 target.example.com\\n\" > /data/local/tmp/custom_hosts'"

# 2. Bind-mount it over the read-only hosts file
adb -s "$DEVICE" shell "su -c 'mount --bind /data/local/tmp/custom_hosts /system/etc/hosts'"

# 3. Verify
adb -s "$DEVICE" shell "su -c 'cat /system/etc/hosts'"
adb -s "$DEVICE" shell "ping -c 1 target.example.com"  # should resolve to 127.0.0.1
```

## Forwarding the port to the host
If the mock server runs on the host (not on the emulator), use `adb reverse`:
```bash
# Emulator's 127.0.0.1:7777 -> host's 127.0.0.1:7777
adb -s "$DEVICE" reverse tcp:7777 tcp:7777
```
Genymotion also has `10.0.3.2` as the host gateway; you can point the hosts
entry at `10.0.3.2` instead of `127.0.0.1` and skip `adb reverse`.

## Cleanup
```bash
adb -s "$DEVICE" shell "su -c 'umount /system/etc/hosts'"
adb -s "$DEVICE" reverse --remove-all
```

## Why bind-mount is safe
`mount --bind` overlays a single file without affecting the rest of `/system`
or `/etc`. Native library loading (`public.libraries.txt`) continues to work
because only `hosts` is replaced.