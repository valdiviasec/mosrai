---
name: capacitor-deeplink-ato-no-binding
description: Use when testing Capacitor/Cordova/React Native apps that use custom-scheme OAuth callbacks (app://auth/callback?code=X). If the exchange code lacks device binding (no PKCE, no device fingerprint, no session binding), an attacker can complete OAuth externally, capture the code, and deliver it to a victim's device via deep link. The victim's app redeems the attacker's code and adopts the attacker's identity. Works WITHOUT root/Frida on production apps. Triggers - "deep link", "OAuth callback", "exchange code", "custom scheme", "app://", "ATO", "account takeover", "PKCE", "code replay", "Capacitor auth"
platform: [android, ios]
stack: [capacitor, cordova, react-native]
category: auth
tier: B
related: []
---

# Account Takeover via Deep Link OAuth Without Binding

## When to use

- Hybrid app (Capacitor, Cordova, React Native) uses OAuth/OIDC for authentication
- The OAuth callback uses a custom URL scheme (`myapp://`, `com.app://`) instead of App Links / Universal Links
- The exchange code in the callback URL has no device or session binding

## Recognition

In the decompiled code or traffic, look for:

```
// AndroidManifest.xml or intent-filter
<data android:scheme="myapp" android:host="auth" android:pathPrefix="/callback" />

// Or in Capacitor config
"appUrlOpen" handler that extracts "code" parameter

// In traffic
GET https://idp.example.com/authorize?redirect_uri=myapp://auth/callback&response_type=code&client_id=...
→ 302 Location: myapp://auth/callback?code=EXCHANGE_CODE_HERE
```

## The vulnerability

OAuth exchange codes are meant to be single-use and bound to the requesting client. But if:
1. The code is NOT bound to a device fingerprint
2. There is no PKCE (`code_verifier`/`code_challenge`) at redemption
3. The code is NOT bound to the session that initiated the auth flow

Then an attacker who obtains the code can redeem it on ANY device.

## Workflow

### Step 1: Map the OAuth flow

Intercept the full OAuth flow (login → redirect → token exchange):

1. The app opens `https://idp.example.com/authorize?...&redirect_uri=myapp://auth/callback`
2. User authenticates at the IdP
3. IdP redirects to `myapp://auth/callback?code=XXXXXXXX`
4. The app exchanges the code for tokens at `POST /token`

### Step 2: Check for PKCE

Look at the `/authorize` request:
- If `code_challenge` and `code_challenge_method` are present → PKCE is used → check if `/token` actually enforces `code_verifier`
- If absent → no PKCE → code is potentially replayable

### Step 3: Check for device binding

Look at the `/token` exchange request:
- Is there a device fingerprint, hardware attestation, or client certificate?
- Is there a session cookie or state parameter bound to the originating device?
- If the only proof is `client_id` + `client_secret` (which are embedded in the APK) → no binding

### Step 4: Test cross-device replay

Complete the OAuth flow on your attack device:
1. Capture the callback URL: `myapp://auth/callback?code=XXXXXXXX`
2. On the VICTIM device (or emulator), deliver the deep link:

```bash
# Via ADB (physical access or malware scenario)
adb shell am start -a android.intent.action.VIEW -d "myapp://auth/callback?code=XXXXXXXX"

# Via malicious web page (remote scenario)
# <a href="myapp://auth/callback?code=XXXXXXXX">Click here</a>
# Or auto-redirect: <script>location='myapp://auth/callback?code=XXXXXXXX'</script>

# Via QR code (social engineering)
# Encode the deep link URL in a QR code
```

3. If the victim's app opens and authenticates as the ATTACKER → confirmed ATO

### Step 5: Escalate with privileges

If the IdP supports roles:
1. Authenticate as an admin account
2. Capture the admin's exchange code
3. Deliver to victim device → victim now has admin access
4. Document the privilege escalation chain

### Step 6: Document

- The exact deep link scheme and path
- Proof that no PKCE/binding exists
- The cross-device replay demonstration
- CVSS: typically 9.0+ (network attack, no user interaction beyond clicking a link)
- Remediation: implement PKCE (RFC 7636), bind codes to device attestation, use App Links/Universal Links instead of custom schemes

## Delivery vectors (for impact assessment)

| Vector | Requires | Scope |
|---|---|---|
| ADB command | Physical access or ADB-over-network | Targeted |
| Malicious web page | Victim clicks a link | Remote, scalable |
| QR code | Victim scans a code | Social engineering |
| NFC tag | Physical proximity | Targeted |
| SMS/messaging link | Victim's phone number | Remote, targeted |

## Gotchas

- **Code expiry:** exchange codes typically expire in 30-120 seconds. The replay must happen within this window.
- **Single-use codes:** the code may work only once. If the attacker's device already redeemed it, the victim's attempt fails. Test if the IdP enforces single-use.
- **App Links vs custom schemes:** if the app uses Android App Links (verified HTTPS domain) or iOS Universal Links, the OS routes the URL to the app only if the domain's `.well-known/assetlinks.json` matches. Custom schemes (`myapp://`) have no such verification: any app can register the same scheme.
- **State parameter:** even without PKCE, a `state` parameter bound to the app's local session would prevent replay. Check if `state` is validated.
- **Production testing:** this attack works on PRODUCTION builds without root or Frida: the deep link handler is a standard Android intent. No modification needed.
