---
name: frida-spawn-vs-attach
description: Use when Frida hooks install but never fire on a running Android app (common with Frida 17.x and JIT-compiled ART classes); switches from attach to spawn mode (-f flag) so hooks apply before any app code runs. Triggers - "hooks not firing", "spawn vs attach", "frida -f", "Frida 17", "JIT compiled"
platform: [android]
stack: [native]
category: enabling
tier: A
related: []
---

# Skill: Frida Spawn vs Attach on Android (Frida 17.x)

## When to use
When you need to hook methods of an Android app with Frida and the hooks "install but never fire". This is very common on Frida 17.x when you attach to an **already running** process.

## The problem
- `frida -U -n <App>` (attach to a running process) installs the hook (`implementation = ...`) **but the methods are not intercepted** on Frida 17.5.x with certain Kotlin/Compose apps. The hook reports "installed" but `onCreate`/`verify` never log.
- Cause: attaching to a process whose ART already loaded and JIT-compiled the classes can leave the hook without effect on existing calls/compiled paths.
- Also, on Frida 17.x the **`Java` bridge** is not available by default in scripts loaded via the **Python API** (`frida` package) on the QJS/V8 runtime. Only the **`frida` CLI** loads it automatically (it has an internal bundler).

## Solution: spawn + CLI
```bash
# CORRECT: spawn (not attach) with the frida CLI
frida -U -f <package> -l exploit.js
# -f spawns and auto-resumes. The hooks are applied before any
# app method runs (including Application.onCreate).

# INCORRECT (hooks do not fire):
frida -U -n <App> -l exploit.js   # attach to a running process

# INCORRECT (Java undefined on Frida 17 with the Python API):
python3 -c "import frida; ..."   # Java is not in globalThis
```

## Accessing Kotlin singletons/Companions in Frida
```javascript
Java.perform(function(){
  // Kotlin `object` (singleton) -> INSTANCE field with .value
  var Canonicalizer = Java.use('com.example.Canonicalizer');
  var instance = Canonicalizer.INSTANCE.value;   // NOT .INSTANCE.value if it is a data class Companion

  // Kotlin `data class` with @Serializable -> Companion (not INSTANCE)
  var Presentation = Java.use('com.example.Presentation');
  var serializer = Presentation.Companion.value.serializer();

  // To find out which: inspect Object.keys
  var c = Java.use('com.example.X');
  console.log(Object.keys(c).filter(function(k){ return k==='INSTANCE'||k==='Companion'; }));
});
```

## Calling the original method inside a hook (Frida 17.x)
On Frida 17.5.1, `this.verify(...)` inside `implementation` can give "TypeError: not a function" (recursion or broken reference). Patterns that work:

```javascript
// Pattern A: hook via overload and call the original with .call(this, ...)
var orig = Clazz.method.overload('java.lang.String','java.lang.String');
orig.implementation = function(a, b){
  // ... mutate ...
  return orig.call(this, a, b);   // sometimes fails
};

// Pattern B (more robust): do NOT recurse. Better to hook an EARLIER method
// in the chain (e.g. fromClaim) that does not need to call the original,
// or hook the result and parse it yourself.

// Pattern C: if you only need to force a return value, hook a simpler
// method (a getter, a fromClaim) that does not require calling the original.
```

## Diagnostic commands
```bash
# List a method's overloads
# (in script) Clazz.method.overloads.forEach(function(o,i){ console.log(i, o.argumentTypes); });

# See if the hook applies: does the PID change when launching the activity?
adb shell pidof com.example   # before and after am start

# frida-server version vs client: they must match (minor)
adb shell /data/local/tmp/frida-server --version
frida --version

# If there is a mismatch: kill the server and start the matching one
adb shell "su -c 'pkill frida-server; /data/local/tmp/frida-server-<ver> -D &'"
```

## Pitfalls and edge cases
- **frida-tools (CLI) vs frida (python package)** can have different versions (`frida --version` vs `python -c "import frida; print(frida.__version__)"`). Use the CLI (`frida -U -f`) which has its own bundler with the Java bridge; avoid the Python API for scripts that use `Java`.
- **Spawn resume**: `frida -f` auto-resumes. If you use the Python API, you must call `dev.resume(pid)` after `script.load()`.
- **`am start` from inside an app fails** (`SecurityException: package=com.android.shell does not belong to uid=...`). An app cannot launch another app's non-exported activities. Use `adb shell am start` (UID 2000) or Frida to invoke `startActivity` from the target app's process.
- **`am start` from adb shell CAN** launch non-exported activities if the app is `debuggable` (present in the manifest): the shell has the `START_ACTIVITIES_FROM_BACKGROUND`/debug permission. This is key for challenges where the app is debuggable.
