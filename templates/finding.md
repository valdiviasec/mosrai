# FIND-{NNN}: {title}

| Field | Value |
|---|---|
| ID | FIND-{NNN} |
| Severity | {critical / high / medium / low / info} |
| Category | {auth / crypto / ipc / storage / injection / webview / deeplink / backend-pivot / vectors-misc / enabling} |
| Platform | {android / ios / both} |
| Stack | {native / flutter / react-native / capacitor / xamarin} |
| Status | {first-cut / confirmed / reported / disputed} |
| Created | {ISO 8601} |
| Skill used | {slug of the skill that guided this finding, if any} |
| MASVS group | {MASVS-STORAGE / CRYPTO / AUTH / NETWORK / PLATFORM / CODE / RESILIENCE / PRIVACY} |
| MASWE | {MASWE-XXXX, or n/a + external taxonomy (e.g. OWASP LLM Top 10)} |
| MASTG test | {MASTG-TEST-XXXX backing the verification, or n/a} |

## Operator decision (cycle Step 6)

| Field | Value |
|---|---|
| Decision | {pending / accepted / discarded / path-built} |
| By | {operator name} |
| Date | {ISO 8601} |
| Rationale | {one or two lines: why accepted, discarded, or which path was built} |
| Journal ref | {journal entry id, or n/a} |

## Summary

{One paragraph: what the vulnerability is, where it lives, and why it matters.}

## Affected endpoint / component

{Specific endpoint, class, deep link scheme, or component.}

## Reproduction steps

1. {Precondition: device state, proxy config, enabling scripts}
2. {Step-by-step to trigger the vulnerability}
3. {Expected vs observed behavior}

## Evidence

{Screenshots, request/response pairs, Frida console output, code snippets. Reference files in evidence/ directory.}

## Impact

{What an attacker gains. Data accessed, privilege escalated, action performed. Concrete, not theoretical.}

## Chain

{CHAIN-NNN if this finding is part of a confirmed chain, else n/a.}

## Remediation

{Specific fix recommendation. Code-level when possible.}

## Verification

| Check | Result |
|---|---|
| Reproduced independently | {yes/no} |
| Reproduced on different device | {yes/no} |
| N-framing (LLM findings only) | {N/K passed, or N/A} |
| Human verified | {yes/pending} |
