# Retest Ledger

> Canonical taxonomy (paper + repo): six verdicts. Legacy names from older rounds map as noted below.
> Rows are added by `mosrai ledger . --finding FIND-NNN --round N --verdict V` (or by hand).

| Finding | Severity | MASWE | R1 | R2 | R3 | R4 | Notes |
|---|---|---|---|---|---|---|---|

## Verdicts (canonical: six)

- **MITIGATED**: The control works; the original proof no longer reproduces. Alternate paths checked too.
- **PARTIAL**: Part of the vector was mitigated; another part persists or is exploitable via an alternate path.
- **PERSISTS**: The vector is still exploitable as reported.
- **PENDING**: Scheduled for the round but not yet executed.
- **NOT VERIFIABLE**: The environment or tooling broke the test (endpoint moved, offsets shifted, account locked). This is NOT a fix.
- **RISK ACCEPTED**: A client business decision to defer a still-open finding. Not a fix either.

### Legacy mapping (previous pack versions → canonical)

| Legacy | Canonical |
|---|---|
| fixed | MITIGATED |
| not-fixed | PERSISTS |
| partial | PARTIAL |
| regressed | PERSISTS + regression note (compare to original severity) |
| deferred | RISK ACCEPTED |
| new | Retest outcome, not a verdict: create the new finding as FIND-NNN and add it to the ledger with its own verdict |

## Round {N}

- **Date:** {ISO 8601}
- **Scope:** {all-open / specific findings}
- **Enabling:** {replayed from enabling.lock / re-derived}
- **App version:** {version tested in this round} · **Artifact:** {APK/IPA filename + SHA-256}
- **Tester:** {name}
- **Notes:** {any changes in app behavior, new defenses, scope changes}