---
name: android-tls-mitm
description: Use when an Android app makes HTTPS requests and you need to intercept/modify the traffic. Covers system proxy setup, reverse-proxy with Frida Socket.connect hook, and TLS 1.2 forced upgrade for apps with weak validation (TrustAll, permissive HostnameVerifier, insecure networkSecurityConfig). Triggers - "mitm android", "intercepta trafico https android", "bypass ssl android", "trustall android", "captura trafico okhttp"
platform: [android]
stack: [native]
category: enabling
tier: A
kind: technique
related: []
---

# SKILL: android-tls-mitm

> Plug-and-play skill to intercept HTTPS traffic from Android apps that
> implement weak or missing TLS validation (TrustAllManager, permissive
> HostnameVerifier, insecure networkSecurityConfig).
>
> **Trigger**: "mitm android", "intercept android https traffic", "bypass ssl
> pinning android", "trustall android", "the app does not validate certificates android",
> "capture okhttp traffic android".

## When to use

- The Android app makes HTTPS requests and you want to see/modify the traffic.
- Static analysis reveals an empty `checkServerTrusted`, a `HostnameVerifier`
  that returns `true`, or a `networkSecurityConfig` with `certificates src="user"`.
- The app crashes with `SSLHandshakeException` due to obsolete cipher suites on
  modern Android (11+).
- You want to demonstrate MITM in an app with a low targetSdk (< 24).

## Do not use if

- The app does real **certificate pinning** (uses `OkHttp CertificatePinner` or
  `X509TrustManagerExtensions` with pins). Use the `android-ssl-pinning-bypass` skill.
- The app uses `javax.net.ssl.SSLContext` with an `X509TrustManager` that does validate
  against a specific keystore. You need a deeper Frida hook.

## Pipeline (5 steps)

### 1. Static analysis: search for TrustAll / HostnameVerifier

```bash
# Decompile
jadx -d jadx-out app.apk
apktool d -f -o apktool-out app.apk

# Grep for missing-validation patterns
grep -rniE "checkServerTrusted|TrustAllX509|checkClientTrusted" jadx-out/sources/
grep -rniE "HostnameVerifier|ALLOW_ALL_HOSTNAME|verify.*return true" jadx-out/sources/
grep -rniE "SSLContext.getInstance" jadx-out/sources/
grep -rniE "ConnectionSpec.CLEARTEXT|cleartextTrafficPermitted" jadx-out/ apktool-out/

# Review networkSecurityConfig
cat apktool-out/res/xml/network_security_config.xml 2>/dev/null
# Red flags: src="user", certificateTransparency enabled="false", cleartextTrafficPermitted="true"
```

**Easy-bypass indicators**:
- `checkServerTrusted` with an empty body or just `Log.w(...)`
- `getAcceptedIssuers` returns `new X509Certificate[0]`
- `HostnameVerifier` with lambda `-> true`
- `networkSecurityConfig` with `<certificates src="user"/>`

### 2. Set up the MITM proxy

There are two methods. **Method B (reverse proxy + Frida Socket hook)** is the
one that works 100% reproducibly with OkHttp 2 (R8 inlines the app's methods
and the system proxy is not honored).

#### Method A: system proxy (works with OkHttp 3, Volley, WebView)

```bash
mitmdump --listen-host 0.0.0.0 --listen-port 8080 -w out.pcap --ssl-insecure &
adb shell "settings put global http_proxy 10.0.3.2:8080"
```

> ⚠️ **OkHttp 2 with targetSdk 23 on Android 11+**: the system proxy is **NOT**
> honored. Use Method B.

#### Method B: reverse proxy + Frida Socket.connect hook (recommended, 100% reproducible)

The hook intercepts `java.net.Socket.connect` at the **framework** level (not the
app, avoiding R8 inlining) and redirects each domain to a mitmproxy reverse proxy
on the host.

```bash
# 1. Stand up 4 reverse proxies (one per domain/endpoint)
mitmdump --listen-host 0.0.0.0 --listen-port 8081 --mode reverse:http://DOMAIN_HTTP --flow-detail 3 --ssl-insecure > valid.txt 2>&1 &
mitmdump --listen-host 0.0.0.0 --listen-port 8443 --mode reverse:https://DOMAIN1 --flow-detail 3 --ssl-insecure > d1.txt 2>&1 &
mitmdump --listen-host 0.0.0.0 --listen-port 8444 --mode reverse:https://DOMAIN2 --flow-detail 3 --ssl-insecure > d2.txt 2>&1 &
mitmdump --listen-host 0.0.0.0 --listen-port 8445 --mode reverse:https://DOMAIN3 --flow-detail 3 --ssl-insecure > d3.txt 2>&1 &
```

Frida hook `hook_reverse_ssl.mjs` (see the attached file in this dir):

```javascript
// Redirects Socket.connect(SocketAddress, int) to the host's reverse proxy.
// Maps domain -> reverse proxy port.
Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, timeout) {
    var isa = Java.cast(addr, InetSocketAddress);
    var host = isa.getHostName();
    var port = isa.getPort();
    var newPort = port;
    if (host === 'DOMAIN_HTTP') { newPort = 8081; }
    else if (host === 'DOMAIN1') { newPort = 8443; }
    // ... map each domain
    var newAddr = InetSocketAddress.$new('10.0.3.2', newPort);  // Genymotion host
    return this.connect(newAddr, timeout);
};
```

> If the app has a TrustAllManager, you do NOT need to install the proxy CA in
> the system keystore. The app will accept any cert.

### 3. Frida hook if the app crashes due to cipher suites (Android 11+)

**Symptom**: `SSLHandshakeException: SSLV3_ALERT_HANDSHAKE_FAILURE` in logcat
when making the HTTPS request.

**Cause**: the app requests `SSLContext.getInstance("SSL")` or `"TLSv1.1"` + obsolete
cipher suites (DES, NULL, anon DH) that BoringSSL/Conscrypt no longer supports.

**Fix**: hook that forces TLS 1.2. **Important**: hook at the framework level
(`SSLContext`, `Socket.connect`), NOT at the app level (R8 inlines OkHttp 2/3
methods and the hooks do not fire).

File `hook_reverse_ssl.mjs` (combines the SSL fix + socket redirect):

```javascript
import Java from 'frida-java-bridge';
Java.perform(function () {
    // Fix: force TLSv1.2
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.getInstance.overload('java.lang.String').implementation = function (p) {
        return this.getInstance('TLSv1.2');
    };
    // Redirect: Socket.connect -> host's reverse proxy
    var Socket = Java.use('java.net.Socket');
    var InetSocketAddress = Java.use('java.net.InetSocketAddress');
    Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, t) {
        var isa = Java.cast(addr, InetSocketAddress);
        var host = isa.getHostName();
        var port = isa.getPort();
        var newPort = port; // map domain -> port
        var newAddr = InetSocketAddress.$new('10.0.3.2', newPort);
        return this.connect(newAddr, t);
    };
});
```

> ⚠️ **Frida 17+**: the `Java` runtime is no longer global. Compile with:
> ```bash
> npm init -y && npm i frida-java-bridge
> frida-compile hook_reverse_ssl.mjs -o hook_reverse_ssl.bundle.js
> ```

> ⚠️ **R8 inlining**: hooks on `OkHttpClient.setConnectionSpecs`, `Call.execute`,
> `newCall`, `RouteSelector` do **NOT fire** in release apps with R8. Use hooks
> at the framework level (`SSLContext`, `Socket`, `TrustManager`) which always fire.

### 4. Capture the traffic

```bash
# Launch the app with Frida + interaction
python3 - << 'EOF'
import frida, time, subprocess
dev = frida.get_device('DEVICE_ID', timeout=10)
pid = dev.spawn(['PACKAGE_NAME'])
s = dev.attach(pid)
s.create_script(open('hook_fix_ssl.bundle.js').read()).load()
dev.resume(pid)
time.sleep(3)
# UI dump to find the button
subprocess.run(['adb','shell','uiautomator','dump','/sdcard/ui.xml'])
# ... parse coords and tap
subprocess.run(['adb','shell','input','tap','X','Y'])
time.sleep(20)
EOF

# View the capture
mitmdump -r out.pcap --flow-detail 3 -n
```

### 5. Confirm with logcat

```bash
adb logcat -d | grep -iE "trust|allow|host|verify|ssl"
# TrustAll: "Server not trusted", "All issuers accepted"
# Permissive HostnameVerifier: "Do not verify host, allow: <domain>"
```

## Variants per HTTP stack

| Stack | Class to hook | Method |
|---|---|---|
| OkHttp 2 (com.squareup.okhttp) | `com.squareup.okhttp.Call` | `execute()`, `newCall()` |
| OkHttp 3 (okhttp3) | `okhttp3.OkHttpClient` | `newCall()`, `ConnectionSpec` |
| HttpURLConnection | `java.net.URL.openConnection` | hook `openConnection` |
| WebView | `android.webkit.WebViewClient` | `onReceivedSslError` (if `handler.proceed()` → vulnerable) |
| Volley | `com.android.volley.toolbox.HurlStack` | `performRequest` |
| Retrofit (on OkHttp) | same as OkHttp | same |

## Troubleshooting

| Symptom | Cause | Solution |
|---|---|---|
| `Java is not Defined` on Frida 17 | Java runtime removed | `frida-compile` + `frida-java-bridge` |
| `Address already in use` frida-server | Two frida-servers running | `killall frida-server*` and leave one |
| App never reaches the proxy | Proxy on 127.0.0.1 | Change to `0.0.0.0`; on Genymotion host=`10.0.3.2` |
| `SSLV3_ALERT_HANDSHAKE_FAILURE` | Obsolete cipher suites | Hook SSLContext + ConnectionSpec (step 3) |
| `frida-ls-devices` crashes (OSError stdin) | No TTY available | Use `python3 -c "import frida; ..."` instead |
| Proxy set but app ignores it | App uses `Proxy.NO_PROXY` | Hook `OkHttpClient.setProxy` or `URL.openConnection` |

## Output artifacts

- `out.pcap`: mitmproxy binary capture
- `flows_detail.txt`: flow text (`mitmdump -r out.pcap --flow-detail 3 -n`)
- `logcat_evidence.txt`: runtime TrustAll evidence
- Device screenshots (optional)
