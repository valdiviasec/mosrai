# CHAIN-{NNN}: {title}

> A reproducible kill chain confirmed with operator insight (cycle Step 8).
> The exploit is the verifier: every link below must reproduce end to end.

| Field | Value |
|---|---|
| ID | CHAIN-{NNN} |
| Status | {draft / confirmed / reported / refuted} |
| Severity | {critical / high / medium / low} |
| Platform / Stack | {android/ios} · {native / flutter / react-native / capacitor / xamarin} |
| Entry point | {deep link / endpoint / IPC component / attachment / WebView} |
| Impact | {data accessed / privilege gained / action performed: concrete} |
| Findings | {FIND-NNN, FIND-NNN, ...} |
| Journal refs | {journal entries that were required, or "fully autonomous, flagged"} |
| MASVS group | {e.g. MASVS-PLATFORM} |
| MASWE | {MASWE-XXXX per link, or n/a + external taxonomy} |
| MASTG test | {MASTG-TEST-XXXX backing the verification, or n/a} |

## Chain

| # | Link | Executed by | Evidence |
|---|---|---|---|
| 1 | {e.g. attacker crafts unbound auth code} | agent | {evidence path} |
| 2 | {victim device redeems deep link → ATO} | human (physical tap) | {evidence path} |
| 3 | {escalation to admin} | agent | {evidence path} |
| 4 | {impact} | agent + human go/no-go | {evidence path} |

**Legend (Executed by):** `agent` (AI-driven, deterministic tooling), `human`
(manual intervention, cite the journal entry), `both`.

## Prerequisites

- Enabling: {enabling.lock scripts, device state, proxy config}
- Credentials / artifacts: {what the tester needs before starting}
- Order matters: {state the strict ordering if any, e.g. TLS bypass before traffic capture}

## Reproduction (cold start)

1. {step with exact request/command}
2. {...}

Expected result: {what proves the chain closed}

## Controls that held

{Defenses that blocked parts of the chain and how the chain routed around them,
or where it honestly stopped. Reporting where the defense holds is part of the
truth of the report.}

## Remediation direction

{Specific fix recommendation per link. Code-level when possible. Anchor client-side
controls to something the attacker cannot forge (server-side signal) where relevant.}

## Open questions

{What remains unproven, environment-dependent, or probabilistic. LLM-in-the-loop
chains are probabilistic: record the sampling performed and the observed rate.}