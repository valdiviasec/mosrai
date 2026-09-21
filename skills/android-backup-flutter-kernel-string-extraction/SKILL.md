---
name: android-backup-flutter-kernel-string-extraction
description: Use when an Android backup (.ab) contains a Flutter app and you need to extract strings from the kernel_blob.bin JIT snapshot inside it. Triggers - ".ab", "android backup", "flutter", "kernel_blob", "kernel_blob.bin"
platform: [android]
stack: [flutter]
category: storage
tier: B
related: []
---

# Skill: Android Backup (.ab) → Flutter JIT (kernel_blob.bin) string extraction

## When to use
You are given an `.ab` (*Android Backup*) or a `backup.ab` inside a zip. `file` reports `Android Backup, version N, Compressed/Uncompressed, Encrypted/Not-Encrypted`. The goal is to reach the app data (typically a Flutter app) and read strings/flag.

## Context: the .ab format
An `.ab` is **4 lines of ASCII text** followed by the payload:
```
ANDROID BACKUP
<version>          # 1-5 (5 = modern)
<compression>      # 1 = compressed (zlib), 0 = uncompressed
<encryption>       # "none" or "AES-256"
<payload...>       # if compressed: zlib of a tar ; if encrypted: AES first
```
The header takes **24 bytes** in the typical case (`ANDROID BACKUP\n5\n1\nnone\n`). If it is not encrypted (`none`), there is no password to crack.

## Steps

### 1. Recognize
```bash
file backup.ab              # Android Backup, version 5, Compressed, Not-Encrypted
xxd backup.ab | head -3     # see the text header and where the payload starts
```
If the byte right after the 4th line is `78 da` (or `78 9c`/`78 01`) → payload is **zlib**, not encrypted.

### 2. Strip the header and decompress
Count the exact bytes of the header (4 lines + their `\n`). The typical case = 24 bytes.
```bash
dd if=backup.ab of=backup.tar.zlib bs=1 skip=24     # skip = header bytes
python3 -c "import zlib; open('backup.tar','wb').write(zlib.decompress(open('backup.tar.zlib','rb').read()))"
```
- If `compression=0` (uncompressed): no zlib needed; the tar sits right after the header → `dd skip=24 of=backup.tar`.
- If `encryption != none`: you must first decrypt AES-256 with the passphrase (out of scope for this skill).

### 3. List and extract the tar
```bash
tar -tvf backup.tar
tar -xf backup.tar
```
Installed apps live in `apps/<package>/`. The interesting parts:
- `apps/<package>/r/app_flutter/flutter_assets/` → **Flutter** app
- `apps/<package>/a/<package>.apk` → sometimes the base APK (rare in a data-only backup)

### 4. Detect Flutter debug/JIT vs release
| File in `flutter_assets/` | Build mode | Difficulty |
|---|---|---|
| `kernel_blob.bin` (+ `isolate_snapshot_data`, `vm_snapshot_data`) | **debug/JIT** | Easy: strings in the target |
| `libapp.so` + `libflutter.so` (in `lib/arm64-v8a/`) | **release/AOT** | Hard: Blutter/darter |

**If `kernel_blob.bin` exists, it is debug/JIT**: the Dart kernel keeps the source strings in the target. That is the goldmine.

### 5. Extract the flag / the source
```bash
strings -a kernel_blob.bin | grep -iE "flag|secret|password|token|api[_-]?key"
```
To reconstruct the Dart source around a match (printable-ASCII window):
```python
import re
data = open("kernel_blob.bin","rb").read()
m = re.search(rb"[A-Za-z0-9_]+\{[^}]{4,}\}", data)  # or the known secret pattern
start = max(0, m.start()-500)
win = data[start:m.end()+100]
src = "".join(chr(b) if 32 <= b < 127 else "\n" for b in win)
import re as r; print(r.sub(r"\n{2,}", "\n\n", src).strip())
```
The original source path is usually embedded: `strings kernel_blob.bin | grep "file:///"`.

## Pitfalls / edge cases
- **It is not a zip**: `unzip backup.ab` fails with `End-of-central-directory signature`. It is its own format.
- **Direct `tar` fails**: the text header breaks `tar` (`Unrecognized archive format`). You must skip the bytes first.
- **Header offset**: count the exact bytes (`"ANDROID BACKUP\n5\n1\nnone\n"` = 24). A wrong `skip` leaves garbage before the `78 da` and zlib blows up. Verify with `xxd` that the first payload byte is `78`.
- **`openssl zlib` does not exist** in many builds (e.g. Homebrew) → use `python3 -c "import zlib; ..."`.
- **Release AOT** (no `kernel_blob.bin`): `strings` over `libapp.so` is almost useless; you need **Blutter** (`blutter -i libapp.so -o out`) to decompile the Dart snapshot into readable pseudocode. Route to [[flutter-apps]].
- **Encrypted backup**: if the header says `AES-256`, the backup passphrase is needed (out of scope here; there is `ab_decrypt`/`abe` with `-passphrase`).
- **Data-only vs full backup**: a "full" backup includes the base APK; a "data" one only brings `r/` (the app data root), where the Flutter assets live.

## One-command pipeline (reference)
Adapt paths to the target: unzip → strip 24 bytes → zlib → tar → grep `kernel_blob.bin`. Minimal version:

```python
import zipfile, zlib, tarfile, io, re
ab = zipfile.ZipFile("backup.zip").read("backup.ab")
tar = zlib.decompress(ab[24:])                       # skip 24-byte header
with tarfile.open(fileobj=io.BytesIO(tar)) as t:
    kb = t.extractfile([m for m in t.getmembers() if m.name.endswith("kernel_blob.bin")][0]).read()
print(re.search(rb"[A-Za-z0-9_]+\{[^}]{4,}\}", kb).group(0).decode())
```

## Related branches
- Flutter AOT (release, `libapp.so`): [[flutter-apps]] / **Blutter** tool.
- Flutter APK (not a backup): `apktool d` → `lib/arm64-v8a/libapp.so`, same Blutter flow.
- Encrypted backups: `abe` tool (Android Backup Extractor, Java) with passphrase.
