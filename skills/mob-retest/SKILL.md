---
name: mob-retest
description: Use when retesting an app after the client reports fixes. Orchestrates the retest workflow: replay enabling, re-verify each finding, check for regressions, and update the LEDGER with evidence-backed verdicts. Triggers - "retest", "re-test", "verify fixes", "check fixes", "retest round", "retesting", "regression check", "mob-retest"
platform: [android, ios]
stack: [any]
category: recon
tier: A
related: [mob-analyze, mob-enabling, mob-flutter, mob-native, mob-react-native, mob-capacitor]
---

# Retest Workflow

This skill orchestrates a structured retest of an app after the client reports fixes. Every finding gets a verdict backed by evidence. No verdict is valid without proof.

## Before you start

Confirm with the human operator:
1. New app version received from client (APK/IPA path)
2. Which findings are the client claiming as fixed?
3. Is this a partial retest (specific findings) or full retest (all open findings)?
4. Retest round number (check `engagement.state` for previous rounds)

## Step 1: Pre-Retest Preparation

### Read existing state

1. Read `engagement.state`: understand the engagement history, previous retest rounds, app version changes
2. Read `LEDGER.md`: list all findings, their current status, and previous verdicts
3. Read each open finding in `findings/FIND-NNN.md`: understand the original vulnerability, reproduction steps, and evidence
4. Read `enabling.lock`: understand the previous enabling setup

### Build retest plan

For each open finding, document:
- Finding ID and title
- Original reproduction steps (exact)
- What the client claims to have fixed
- Expected behavior if properly fixed
- Alternate exploitation paths to check (a fix might close one path but leave another open)

Present the retest plan to the human for approval before executing.

## Step 2: Re-Enabling

The new app version may break previous enabling. Handle this explicitly.

### Replay enabling.lock

1. Install the new app version on the target device
2. Execute the root/JB bypass scripts from `enabling.lock`
3. Execute the SSL bypass scripts from `enabling.lock`
4. Verify: trigger a network request, confirm it appears in the proxy

### If enabling breaks

If the new version's root detection or SSL pinning has changed:
1. Document what broke (new detection method, updated pinning, etc.)
2. Load `mob-enabling` to re-derive the bypass
3. Follow the full enabling ladder from mob-enabling
4. Update `enabling.lock` with the new bypass configuration
5. Add a note to `enabling.lock` documenting what changed between versions

### If enabling succeeds unchanged

Update `enabling.lock` with the new app version number but keep the same scripts. Note that the bypass was replayed successfully without modification.

## Step 3: Per-Finding Retest

For EACH open finding in `LEDGER.md`, execute this sequence. Do not batch or skip.

### 3.1: Read the original finding

Read `findings/FIND-NNN.md` completely:
- Understand the vulnerability mechanism
- Identify the exact reproduction steps
- Note the original evidence (request/response, Frida output, screenshots)
- Understand the reported remediation from the client

### 3.2: Execute original reproduction steps

Follow the documented reproduction steps exactly as written:
- Same endpoint, same parameters, same Frida hooks
- Same payload structure, same bypass technique
- Do not improvise or modify steps at this stage: the original steps are the baseline

### 3.3: Apply verdict

Canonical taxonomy: six verdicts. Apply exactly one:

**MITIGATED**: The original reproduction steps no longer work AND alternate paths have been checked:
- The vulnerability mechanism has been properly addressed
- The fix is not merely cosmetic (e.g., hiding the field but still accepting the parameter)
- Alternate exploitation paths have been tested and do not work
- Evidence: the request/response or behavior that proves the fix

**PERSISTS**: The original reproduction steps still work:
- The vulnerability is still exploitable using the documented technique
- Evidence: the request/response or behavior showing the vulnerability persists
- Note whether the behavior is identical to the original or slightly changed
- If a fix made it worse or introduced a variant, still use PERSISTS and add a regression note comparing to the original severity

**PARTIAL**: The attack surface was reduced but the vulnerability is still exploitable via a different path:
- The client's fix addressed one aspect but missed another
- Document the alternate path in detail: this becomes the new reproduction method
- Evidence: the alternate exploitation and its results
- Update `findings/FIND-NNN.md` with the alternate path documentation

**PENDING**: Scheduled for this round but not yet executed (placeholders are allowed while the round is open).

**NOT VERIFIABLE**: The environment or tooling broke the test (endpoint moved, enabling offsets shifted, account locked):
- This is NOT a fix. Never record it as MITIGATED.
- Document exactly what blocked the test and what would be needed to retry

**RISK ACCEPTED**: The client made a business decision to defer a still-open finding:
- Document the justification. Do not change this verdict without human approval.

**New findings during the round** are not a verdict: create `findings/FIND-NNN.md` and add the row with its own verdict (typically PERSISTS).

### 3.4: Capture evidence

For every verdict, capture new evidence:
- Screenshots of the relevant app state
- Request/response pairs from the proxy (Burp/Caido export)
- Frida hook output if applicable
- Before/after comparison with original evidence

Save evidence to `evidence/retest_round_N/FIND-NNN/`

### 3.5: Update LEDGER.md

For each finding, update the LEDGER with:
- Verdict (MITIGATED / PARTIAL / PERSISTS / PENDING / NOT VERIFIABLE / RISK ACCEPTED)
- Date of retest
- New app version tested · artifact filename + SHA-256
- Brief notes on what was observed
- Reference to new evidence files
- MASWE mapping when applicable (`MASWE-XXXX`), or `n/a` for non-MASWE weaknesses (e.g., LLM findings)

## Step 4: Regression Check

While retesting individual findings, actively watch for NEW vulnerabilities introduced by the fixes.

### What to look for

- **New attack paths:** a fix that changes a code path may introduce a new vulnerability in the changed code
- **Shifted storage:** if a fix moves data from insecure storage to a different location, verify the new location is actually secure
- **Broken functionality:** a fix that disables a feature may have disabled a security control along with it
- **New dependencies:** if the fix introduces new libraries or plugins, check them for known vulnerabilities
- **Error handling changes:** fixes sometimes change error handling, revealing more information in error messages

### If a new vulnerability is found

1. Create a new finding: `findings/FIND-NNN.md` using the finding template
2. Set status to "confirmed" in the finding file
3. Add to `LEDGER.md` with its own verdict (typically PERSISTS) for this retest round
4. Capture full evidence as for any other finding
5. Document the relationship to the original fix (e.g., "FIND-012 was introduced by the fix for FIND-007")

## Step 5: Deferred Findings

Some findings may have been accepted by the client as known risks.

### Handling deferred findings

- If the client communicated that a finding is "accepted risk" or "deferred", use the verdict `RISK ACCEPTED` in the LEDGER
- Document the client's justification verbatim: do not editorialize
- Do NOT re-test deferred findings unless the human operator specifically requests it
- If during other testing you notice a deferred finding has been quietly fixed or changed, note it in the LEDGER but do not change the verdict from `RISK ACCEPTED` without human approval

## Step 6: Complete the Retest

### Update engagement.state

```yaml
retest:
  round: N
  date: YYYY-MM-DD
  tester: [tester name]
  app_version: [new version]
  artifact_sha256: [hash of the APK/IPA tested this round]
  summary:
    total_findings: X
    mitigated: Y
    persists: Z
    partial: W
    pending: P
    not_verifiable: Q
    risk_accepted: D
    new: N
```

### Generate summary

Present to the human operator:
1. Total findings retested
2. Verdicts breakdown (MITIGATED / PARTIAL / PERSISTS / PENDING / NOT VERIFIABLE / RISK ACCEPTED + new findings)
3. Findings that require attention (PERSISTS, PARTIAL, new)
4. Findings reported honestly as NOT VERIFIABLE (with the blocker) and RISK ACCEPTED (client decision): never conflate them with MITIGATED
5. Changes to enabling (if any)
6. Recommendation for next steps (another retest round? escalation? close engagement?)

### Handoff

The retest round is complete when:
- Every open finding has a verdict in the LEDGER
- Every verdict has evidence in `evidence/retest_round_N/`
- `engagement.state` is updated with the retest summary
- The human operator has reviewed the results

## Rules (always active)

- **Every verdict needs evidence:** "it works now" is not a verdict. Show the request that fails, the response that changed, the Frida output that is different. Without evidence, the verdict is NOT VERIFIABLE, not MITIGATED.
- **MITIGATED requires alternate path check:** the original repro failing is necessary but not sufficient. Check if the same vulnerability is exploitable via a modified approach (different parameter, different endpoint, different encoding). Only if alternate paths also fail is the verdict MITIGATED.
- **PARTIAL must document the alternate path:** if the fix reduced but did not eliminate the attack surface, the alternate exploitation path becomes the new reproduction method. Document it with the same rigor as the original finding.
- **Do not skip findings:** every open finding in the LEDGER gets retested unless explicitly excluded by the human operator. Silent skipping is a methodology failure.
- **New vulnerabilities are first-class:** a regression or new finding discovered during retest gets the same treatment as an original finding: template, evidence, LEDGER entry.
- **Enabling changes are documented:** if the new app version required re-derivation of root/SSL bypass, document what changed. This is valuable information for the client's security team.
- **State persistence:** update `engagement.state` and `LEDGER.md` after every finding verdict. If the session is interrupted, the next session must be able to resume at the exact finding where it left off.
- **No editorial on deferrals:** the client's risk acceptance decision is theirs. Record the justification, do not argue it in the LEDGER.
