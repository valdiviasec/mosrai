---
name: rootbeer-root-detection-bypass
description: 'Use when you need to bypass RootBeer root detection (com.scottyab.rootbeer) with Frida by hooking its 11 individual checks plus the isRooted() method. Triggers - "rootbeer", "scottyab", "isRooted", "root detection"'
platform: [android]
stack: [native]
category: enabling
tier: A
kind: primitive
related: []
---


# Bypassing RootBeer Root Detection with Frida

## What it solves

RootBeer is the most widely used root detection library on Android (`com.scottyab.rootbeer.RootBeer`).
Its sample app runs 11 individual checks + an aggregate `isRooted()`. On a rooted
device (Genymotion with `su`, `test-keys`, `ro.debuggable=1`), the app reports `ROOTED*`.

This skill contains the tested Frida script that bypasses **all** RootBeer checks at
runtime: without patching the APK, without changing the signature: keeping the original APK intact.

Result: the app shows `NOT ROOTED` on a device that IS rooted.

## The problem (what RootBeer detects)

RootBeer runs 11 checks, each with a different primitive:

| Check | Method | Primitive | Clean value |
|---|---|---|---|
| Root Management Apps | `detectRootManagementApps()` | `PackageManager.getPackageInfo` | false |
| Potentially Dangerous Apps | `detectPotentiallyDangerousApps()` | `PackageManager.getPackageInfo` | false |
| Root Cloaking Apps | `detectRootCloakingApps()` | `PackageManager.getPackageInfo` + native lib access | false |
| TestKeys | `detectTestKeys()` | `Build.TAGS.contains("test-keys")` | false |
| BusyBoxBinary | `checkForBusyBoxBinary()` | `File.exists()` on paths | false |
| SU Binary | `checkForSuBinary()` → `checkForBinary("su")` | `File.exists()` on 15+ paths | false |
| 2nd SU Binary | `checkSuExists()` | `Runtime.exec("which su")` | false |
| RW Paths | `checkForRWPaths()` | `Runtime.exec("mount")` parse | false |
| Dangerous Props | `checkForDangerousProps()` | `Runtime.exec("getprop")` parse | false |
| Root via native | `checkForRootNative()` | JNI `fopen()` in C++ | false |
| Magisk | `checkForMagiskBinary()` → `checkForBinary("magisk")` | `File.exists()` | false |

Aggregate: `isRooted()` = OR of all the above (except busybox and cloaking).

## Bypass strategy (7 layers)

Ordered by priority. Layers 1-3 are the most important; 4-7 are coverage.

1. **RootBeer.isRooted()** → return `false` (high-level decision)
2. **Each individual check** → return `false` (the sample app shows them one by one)
3. **RootBeerNative.checkForRoot()** → return `0` (native JNI, `fopen` in C++)
4. **Build.TAGS** → `"release-keys"` (detectTestKeys)
5. **File.exists()** → `false` for su/magisk/busybox paths
6. **Runtime.exec()** → intercept `which su`, `getprop`, `mount`
7. **PackageManager.getPackageInfo()** → throw `NameNotFoundException` for root apps

## Workflow

### Prerequisites

- Rooted Genymotion with `frida-server` at `/data/local/tmp/frida-server`
- ADB forward TCP 27042: `adb forward tcp:27042 tcp:27042`
- Frida 17+ on the host
- RootBeer Sample APK installed

### 1. Build the APK (if no pre-built one exists)

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home
export ANDROID_HOME=~/Library/Android/sdk
git clone https://github.com/scottyab/rootbeer.git
cd rootbeer
# Adjust ndkVersion in gradle/libs.versions.toml to the installed NDK:
#   ~/Library/Android/sdk/ndk/  →  check the installed version
./gradlew :app:assembleDebug
# APK: app/build/outputs/apk/debug/RootBeerSample-*-debug.apk
```

### 2. Install and verify the baseline (root detected)

```bash
adb -s 127.0.0.1:6555 install -r RootBeerSample-0.1.2-debug.apk
adb -s 127.0.0.1:6555 shell am start -n \
  com.scottyab.rootbeer.sample.debug/com.scottyab.rootbeer.sample.MainActivity
# Tap FAB → should show "ROOTED*"
```

### 3. Bypass with Frida

```bash
# Make sure frida-server is up
adb -s 127.0.0.1:6555 forward tcp:27042 tcp:27042

# Spawn with the bypass, eternalize the hooks
frida -H 127.0.0.1:27042 -f com.scottyab.rootbeer.sample.debug \
  -l bypass_rootbeer_frida.js -q --eternalize

# Tap FAB → should show "NOT ROOTED"
adb -s 127.0.0.1:6555 shell input tap 964 2181
```

### 4. Verify

```bash
adb -s 127.0.0.1:6555 shell uiautomator dump /sdcard/ui.xml
adb -s 127.0.0.1:6555 shell cat /sdcard/ui.xml | grep -o 'NOT ROOTED\|ROOTED'
# Expected: NOT ROOTED
```

## Frida script (bypass_rootbeer_frida.js)

The full script is in `auxiliar/bypass_rootbeer_frida.js`. Structure:

```javascript
Java.perform(function () {
    // 1. RootBeer.isRooted() → false
    // 2. Each individual check → false (use .overload() for methods with overloads)
    // 3. RootBeerNative.checkForRoot() → 0
    // 4. Build.TAGS = 'release-keys'
    // 5. File.exists() → false for root paths
    // 6. Runtime.exec() → intercept which su / getprop / mount
    // 7. PackageManager.getPackageInfo() → NameNotFoundException for root apps
});
```

## Critical gotchas

- **Overloads**: `detectRootManagementApps`, `detectPotentiallyDangerousApps`, and
  `detectRootCloakingApps` have 2 overloads (no-arg and `String[]`). Use
  `.overload().implementation` and `.overload('[Ljava.lang.String;').implementation`
  separately. If you use `.implementation` without `.overload()`, Frida throws:
  `has more than one overload, use .overload(<signature>)`.
- **`--eternalize`**: keeps the hooks alive after Frida exits. Without it,
  the hooks disappear on exit. Combine with `-q` for a no-CLI run.
- **`-H` vs `-D`**: on Genymotion with frida-server over TCP, use `-H 127.0.0.1:27042`.
  `-D 127.0.0.1:6555` can give `need Gadget to attach on jailed Android`.
- **Native check**: `RootBeerNative.checkForRoot()` uses `fopen()` in C++ (libtoolChecker.so).
  Hooking the Java JNI method is enough: no native Interceptor hook needed.
- **Spawn timing**: use `-f` (spawn), not attach. If the app already ran without hooks, force-stop
  before spawning.
- **JDK 17**: AGP 8.6 requires JDK 17 to build. Set
  `JAVA_HOME=/opt/homebrew/opt/openjdk@17/...`.
- **NDK version**: the repo specifies `27.0.12077973` in `gradle/libs.versions.toml`.
  Adjust to the NDK installed at `~/Library/Android/sdk/ndk/`.

## How to extend to other apps with RootBeer

1. Identify the target app's package name.
2. If it imports RootBeer as a dependency, the methods are the same
   (`com.scottyab.rootbeer.RootBeer`).
3. Change the package in the `frida -f <package>` command.
4. If the app calls `isRooted()` and blocks (closes/shows an error), hooking `isRooted()` → false
   is enough.
5. If the app calls individual checks to show UI or make partial decisions, hook
   each one.
6. If the app does server-side attestation (Play Integrity, SafetyNet), the Frida bypass
   is not enough: deeper hooks or mock attestation are needed.

## Reference clean values

```
rooted/jailbroken → false
isRooted() → false
detectTestKeys() → false (Build.TAGS = "release-keys")
checkForBinary("su") → false
checkForBinary("magisk") → false
checkForBinary("busybox") → false
checkSuExists() → false
checkForRWPaths() → false
checkForDangerousProps() → false (ro.debuggable=0, ro.secure=1)
checkForRootNative() → false (checkForRoot() → 0)
detectRootManagementApps() → false
detectPotentiallyDangerousApps() → false
detectRootCloakingApps() → false
```
