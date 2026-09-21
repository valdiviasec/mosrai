# Context pack: {app name}

> Human-authored seed for the engagement (cycle Step 3). This is the single most
> useful input to a mobile assessment: a map of the app's own traffic and the
> business meaning behind it. The harness reasons over this instead of rediscovering
> the surface request by request. Keep it factual; mark unknowns explicitly.

| Field | Value |
|---|---|
| Engagement | {app name / id} |
| Intake tier | {gray-box: package + credentials · white-box: + source, docs, full proxy capture} |
| Artifact | {app.apk / app.ipa} · SHA-256 {hash} |
| Platform / Stack | {android/ios} · {native / flutter / react-native / capacitor / xamarin} |
| Backend(s) | {base URLs, environments in scope} |
| Proxy capture | {path to Burp/Caido project export, date, flows covered} |

## Business flows (what a real user does)

| # | Flow | Endpoints involved | Notes / impact if broken |
|---|---|---|---|
| 1 | {login / OTP / biometric} | {...} | {...} |
| 2 | {...} | {...} | {...} |

## Credentials and accounts

| Account | Role | Notes |
|---|---|---|
| {user_x} | {role} | {rate-limited? locked? shared?} |

> Do not paste production secrets into this file in plain text if the engagement
> directory will be shared. Reference a secret manager or a local `.env` instead,
> and run `mosrai scrub` before any distribution.

## Out of scope

- {hosts, features, test types explicitly excluded}
- {destructive actions requiring human go/no-go}

## Known defenders

| Control | Where | Observed behavior |
|---|---|---|
| {root/JB detection} | {client} | {blocking / warning / compiled out} |
| {TLS pinning} | {native / Dart / JS} | {...} |
| {RASP / attestation} | {...} | {...} |

## Traps noticed by the requester

{Anything the requester flagged as noise, decoy, or a known false positive.}

## Open questions for the testers

{What the requester wants answered, in their words.}