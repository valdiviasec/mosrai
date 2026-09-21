# Operator Journal: {YYYY-MM-DD}-{NNN}

> Record of a manual intervention by the operator during an engagement.
> This is the operational trace behind the Human-Required Map: what the harness
> did not see, what the human did about it, and how it was validated.

| Field | Value |
|---|---|
| Date | {ISO 8601} |
| Engagement | {app name / engagement id} |
| Phase | {enabling / recon / traffic / hunting / chain / retest} |
| Human-Required Map category | {1-7, see below} |
| Related finding(s) | {FIND-NNN, or "none yet"} |
| Related chain | {CHAIN-NNN, or "none yet"} |

## Map categories (paper, Section 8)

1. **Physical-world actuation**: the agent cannot touch the device (login, tap, confirm, cable).
2. **Ground-truth verification**: telling a real signal from an artifact (echo vs leak, timing vs noise).
3. **Hypothesis selection**: knowing which attack to try.
4. **Adaptation under drift**: re-deriving when the deterministic tool breaks (offsets shifted, endpoint moved).
5. **Calibrated abstention**: deciding the evidence is not there, and saying so.
6. **Ethical restraint**: the line between a canary and a payload (go/no-go gates).
7. **Impact truth**: owning the truth of the report (honest rating, retracting refuted findings).

## What the harness did

{What the setup reported, attempted, or missed. Concrete: the tool run, the output,
the false positive, the dead end.}

## Operator insight / action

{What the human saw that the setup did not. The prompting insight, the hunch, the
business-logic reading, the manual derivation. Specific enough to repeat.}

## Manual steps executed

1. {command / action, with the exact parameters when sharing is allowed}
2. {...}

## Validation

| Check | Result |
|---|---|
| Reproduced by the operator | {yes/no} |
| Reproduced by the harness after the insight | {yes/no/n-a} |
| Evidence | {path(s) in evidence/} |
| Should this become a skill? | {yes/no: slug suggestion if yes} |

## Upstream (flywheel)

{If this intervention generalizes beyond this client, what skill should be written
or amended? If not, say why. This is how field work compounds into the pack.}