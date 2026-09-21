---
name: mob-analyze
description: Use when starting a mobile app security assessment. This is the main entry point that orchestrates the full evaluation flow: from enabling through hunting to findings. Load this skill first for ANY new engagement. It routes to the correct per-stack skills, enforces gates (enabling must pass before hunting), and manages engagement state. Triggers - "analyze app", "start assessment", "mobile pentest", "new engagement", "security assessment", "APK analysis", "IPA analysis", "mob-analyze"
platform: [android, ios]
stack: [any]
category: recon
tier: A
related: [mob-enabling, mob-native, mob-flutter, mob-react-native, mob-capacitor, mob-retest]
---

# Mobile App Security Assessment

This skill orchestrates a complete mobile app security assessment. Follow the phases in order. Do NOT skip phases or reorder them: each phase gates the next.

## Before you start

Confirm with the human operator:
1. What app? (APK/IPA path or package name)
2. What scope? (full assessment, specific features, retest only)
3. What device? (physical device, emulator, or both)
4. What proxy? (Burp, Caido: must be running and configured)

If an `engagement.state` file exists in the current directory, read it to resume from where the last session left off. If not, scaffold a new engagement:
- Copy `templates/engagement-state.yaml` to `./engagement.state`
- Fill in app metadata from the APK/IPA manifest
- Set phase to "enabling"

## Phase 0: Enabling (mandatory gate)

**This phase MUST succeed before any security testing.** No exceptions. For the full procedure, load `mob-enabling`.

1. Install the app on the target device
2. **Root/jailbreak bypass**: escalation ladder:
   - Try seed scripts first: `tools/seeds/root-bypass-android.js` or `tools/seeds/jb-bypass-ios.js`
   - If seeds fail, search SKILL_INDEX.txt for stack-specific `enabling` skills
   - If those fail, triage the decompiled code for custom detection logic and derive a bypass
   - If stuck, ESCALATE to the human: do not guess
3. **SSL/TLS bypass**: same ladder:
   - Native Android: `tools/seeds/ssl-unpin-android.js` (OkHttp3, X509TrustManager, Conscrypt)
   - Native iOS: `tools/seeds/ssl-unpin-ios.js` (NSURLSession, SecTrust, AFNetworking)
   - Flutter: `tools/seeds/ssl-unpin-flutter.js`: generic hooks do NOT work on Flutter
   - React Native: try `ssl-unpin-android.js` or `ssl-unpin-ios.js` first (RN uses platform HTTP stack)
   - If seeds fail, search index for stack-specific bypass skills
4. **Verify:** trigger a network request in the app. It MUST appear in the proxy (Burp/Caido). If it doesn't, the bypass is not working: go back to step 2.
5. **Lock:** write `enabling.lock` in the engagement dir with the working scripts and config. This file is replay-deterministic for retests.
6. Update `engagement.state`: set `enabling.status: active`, `phase: recon`

**Gate check:** if proxy shows no app traffic after 3 attempts, STOP and escalate to the human.

## Phase 1: Reconnaissance

### Static analysis

1. **Fingerprint the app stack:**
   - Search for `libflutter.so` / `Flutter.framework` → Flutter
   - Search for `index.android.bundle` / `hermes` → React Native
   - Search for `capacitor.config.json` / `cordova.js` → Capacitor/Cordova
   - Search for `assemblies/*.dll` / `libmonosgen` → Xamarin
   - None of the above → Native (Java/Kotlin or Swift/ObjC)
   - Update `engagement.state` with detected stack

2. **Decompile per-stack:**
   - Flutter → `blutter` (output to `/tmp/re_<appname>/`)
   - React Native → `hermes-dec` on the JS bundle
   - Native Android → `jadx -d /tmp/re_<appname>/ app.apk`
   - Native iOS → `class-dump` or Hopper/Ghidra
   - Xamarin → `monodis` on assemblies/*.dll
   - Output MUST go to `/tmp/re_<appname>/`: NEVER inside the project directory

3. **Surface map:** identify and document in `engagement.state`:
   - API endpoints (grep for URLs, Retrofit interfaces, fetch calls)
   - Auth flows (login, OAuth, token refresh)
   - Crypto usage (AES, RSA, HMAC: search for `Cipher`, `SecretKey`, `crypto`)
   - Local storage (SharedPreferences, Keychain, SQLite, Realm)
   - IPC surfaces (exported activities, content providers, deep links, intents)
   - WebViews (check for JavaScript bridges, `addJavascriptInterface`)

4. **Suggest skills:** search SKILL_INDEX.txt for skills matching:
   - The detected stack
   - Patterns found in the surface map (crypto → crypto skills, deeplinks → deeplink skills)
   - Present the suggestions to the human for approval before loading

### Dynamic analysis

5. **Permissions audit:** check dangerous permissions in manifest/entitlements
6. **Logging check:** monitor logcat/Console for sensitive data leaks during normal app usage

## Phase 2: Traffic Analysis

The human samples traffic by interacting with the app while proxy is active.

1. **Read proxy traffic** using the proxy's MCP tools (Burp MCP / Caido MCP):
   - Use specific regex filters targeting the app's domains: NEVER use `.*`
   - Request small batches (5-10 items), iterate with offset
   - Ignore noise: googleapis.com, gstatic.com, firebase, crashlytics, dynatrace, cloudflare
   - For large histories: dump filtered results to `/tmp/re_<appname>/traffic.json`

2. **Map endpoints:** for each endpoint found, document:
   - Auth mechanism (Bearer token, cookie, API key, client cert)
   - Request/response format (JSON, protobuf, XML, encrypted)
   - Interesting parameters (user IDs, file paths, amounts, enum values)
   - Server errors or debug info in responses

3. **Identify encrypted traffic:** if request/response bodies are encrypted:
   - Search index for `crypto` skills matching the scheme
   - Load `envelope` skills to wrap/unwrap payloads for testing

4. **OOB testing setup:** if Burp Collaborator is available:
   - Generate a collaborator payload for SSRF/XXE/header injection testing
   - Note the payload for use in hunting phase

Update `engagement.state`: set `phase: hunting`, add tested surfaces.

## Phase 3: Hunting

For each attack surface identified in Phase 1-2, search SKILL_INDEX.txt for matching skills and test systematically.

### Auth testing
- Search index: `category:auth` + detected stack
- Key checks: session management, token expiry, privilege escalation, OAuth flow weaknesses, IDOR

### Crypto testing
- Search index: `category:crypto` + detected stack
- Key checks: hardcoded keys, weak algorithms, key derivation, encrypted storage

### IPC / Deep link testing
- Search index: `category:ipc` or `category:deeplink` + platform
- Key checks: exported components, deep link hijacking, intent injection, URL scheme abuse

### Storage testing
- Search index: `category:storage` + platform
- Key checks: plaintext secrets in SharedPrefs/Keychain, world-readable files, backup extraction

### WebView testing
- Search index: `category:webview` + platform
- Key checks: JavaScript bridge abuse, XSS via WebView, file:// access, mixed content

### Backend pivot
- Search index: `category:backend-pivot`
- Key checks: SSRF, IDOR on API, rate limiting, business logic, mass assignment

### LLM testing (if applicable)
- If the app has AI/LLM features: load `llm-prompt-injection-multiframe`
- Gate rule: an LLM finding is NOT closed until N distinct framings confirm negative

### For EACH potential finding:
1. Create a draft using `templates/finding.md` → `findings/FIND-NNN.md`
2. Document reproduction steps (must be specific enough for someone else to reproduce)
3. Capture evidence (screenshots, request/response, Frida output) → `evidence/`
4. **Verification gate:** the finding is NOT confirmed until:
   - Reproduced at least once independently
   - Human has reviewed and approved
   - For LLM findings: N-framing gate passed
5. Update `engagement.state`: add finding to items list

## Phase 4: Reporting

1. Review all findings in `findings/`
2. Ensure each has: severity, reproduction steps, evidence, impact, remediation
3. Initialize `LEDGER.md` from `templates/LEDGER.md` with all confirmed findings
4. **Confidentiality gate:** before sharing any output externally, run `python3 mosrai scrub findings/ evidence/`. If it fails, scrub the flagged items before distributing. This is fail-closed: any match or error = do not distribute.
5. Present findings summary to the human for review
6. Update `engagement.state`: set `phase: reporting`

## Phase 5: Retest (when applicable)

When the client reports fixes and requests a retest:

1. Create a new retest round: add column to `LEDGER.md`
2. Replay enabling from `enabling.lock` (if app version changed, may need re-derivation)
3. For each open finding:
   - Re-execute the original reproduction steps
   - Apply verdict: MITIGATED / PARTIAL / PERSISTS / PENDING / NOT VERIFIABLE / RISK ACCEPTED
   - Update `LEDGER.md` with verdict and notes
4. Check for new vulnerabilities introduced by fixes → create the finding as FIND-NNN and add it with its own verdict
5. Update `engagement.state`: increment retest round

## Rules (always active)

- **Output size:** NEVER dump large outputs (decompiled code, traffic logs) into the conversation. Write to file, return path + summary.
- **Deterministic routing:** stack detection → tool selection is deterministic. Flutter → blutter, RN → hermes-dec, Native → jadx. No "trying" random tools.
- **Fail-hard:** if a required tool is missing, STOP and tell the human. Do not silently degrade.
- **State persistence:** update `engagement.state` after every phase transition and every finding. The next session must be able to resume without re-explaining what was done.
- **Proxy traffic rules:** aggressive filters, small counts, ignore noise domains. See MOSRAI.md Phase 2 for full rules.
- **Confidentiality:** findings and evidence contain client data. NEVER commit engagement dirs to the MOSRAI repo. NEVER include client PII in skill descriptions. Before distributing ANY engagement output, run `python3 mosrai scrub <path>`: fail = do not distribute. Use as pre-commit hook: `tools/pre-commit-scrub`.
