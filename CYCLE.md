# MOSRAI Engagement Cycle

> The operational contract of MOSRAI: ten steps from receiving an app to closing remediation.
> This is the operational contract of MOSRAI: ten steps from receiving an app to
> closing remediation, deployable on any harness + skillset + model setup.

MOSRAI is not a harness, a model, or a CLI. It is the methodology layer that any
harness can load. This document defines **what happens**, **which artifact records
it**, and **where the human gate sits**, so the same cycle runs on OpenCode,
Claude Code, Cursor, or a direct API call.

> Before anything: **fidelity to the paper.** Two jargon traps worth stating once.
> *Operator plane* = your harness + skillset + models (heavy and soft) driving the
> engagement. *Target plane* = the model the audited app happens to ship with
> (e.g. a self-hosted LLM in a RAG feature). They are different slots and never
> collapse into one. When this document says "model", it means the **operator plane**
> unless stated otherwise.

## The cycle at a glance

```
1 intake → 2 setup → 3 resources → 4 test → 5 first cut
   → 6 human review → 7 operator journal → 8 chain confirm
   → 9 retest checklist → 10 remediation + standards
```

Each step below lists: **input**, **who acts** (agent / human / both), **artifact**,
and the **gate** that must pass before moving on.

---

## Step 1: Intake (the app arrives in a directory)

- **Input:** an APK/IPA (or a source bundle) plus whatever context the requester has.
- **Who:** human (provides), agent (inventories).
- **Action:** scaffold the engagement directory and record what exists and what does not.
- **Artifact:** `engagement.state` (app block) + `intake/` folder with the raw artifact.
- **Gate:** artifact hash recorded; platform and stack fingerprinted; scope noted
  (full / partial / retest-only). Missing inputs are listed, not invented.

Layout (created by `mosrai init`):

```
<engagement>/
  engagement.state        # machine-readable state (phase, findings, rounds, models)
  intake/                 # the app and unprocessed inputs (APK/IPA, notes)
  sources/                # white-box material: source, docs, backend code
  traffic/                # captured HTTP (Burp/Caido project export, samples)
  findings/               # FIND-NNN.md, one per finding
  evidence/               # raw evidence referenced by findings
  journal/                # operator journal entries (Step 7)
  chains/                 # CHAIN-*.md kill chains (Step 8)
  retest/                 # round-N/ checklists and evidence (Step 9)
  LEDGER.md               # append-only retest ledger
```

## Step 2: Setup (harness + skillset + model)

- **Input:** the engagement directory from Step 1.
- **Who:** human.
- **Action:** point the harness at the skillset and declare the operator models.
  MOSRAI is harness-agnostic: symlink `MOSRAI.md` into whatever system-prompt slot
  the harness uses (see `SETUP.md`). Declare a **heavy** model for deep reasoning
  and a **soft** model for mechanical, high-volume work. Swapping either mid-
  engagement is expected and is part of the thesis (the model is the interchangeable slot).
- **Artifact:** `engagement.state > models` block (with per-phase overrides if used).
- **Gate:** preflight passes: device reachable, proxy configured, required tools
  present (`TOOLCHAIN.lock`). A missing critical tool is a STOP, not a warning.

## Step 3: Resources (what the requester gave us)

- **Input:** traffic captures, credentials, source, documentation, backend access.
- **Who:** human (provides), agent (structures).
- **Action:** normalize every resource into the engagement tree and write the
  **context pack**: the human-authored summary of business flows, endpoints that
  matter, and what "impact" means for this app. In a gray-box engagement this is
  the APK/IPA + credentials. In a white-box engagement it also includes source and
  a full proxy project, which the harness consumes through the proxy MCP bridge and
  treats as a first-class seed.
- **Artifact:** `traffic/` + `templates/context-pack.md` filled in (copy to `context-pack.md`).
- **Gate:** the agent can name the app's main flows and their endpoints from the
  context pack + capture, without having tested anything yet. If it cannot, Step 5
  will be thin. Say so now.

## Step 4: Test on the available surface

- **Input:** everything from Steps 1-3.
- **Who:** agent executes; human handles device-gated actions.
- **Action:** run the MOSRAI phases (enabling, recon, traffic analysis, hunting),
  routing mechanical work to deterministic tools, and loading skills on demand.
  Before any vector testing, generate the **Attack Surface Matrix** (load
  `skills/mob-surface-matrix/SKILL.md`): map every endpoint to every applicable
  vector. The operator approves the matrix before hunting starts. Every candidate
  finding gets a reproducible chain (the exploit is the verifier).
- **Artifact:** `attack-surface-matrix.md` + `evidence/` + draft findings in
  `findings/`.
- **Gate:** enabling is locked (`enabling.lock`); the matrix is operator-approved;
  no finding is recorded without a reproduction path and raw evidence.

## Step 5: First cut (findings from the provided inputs)

- **Input:** Step 4 output.
- **Who:** agent.
- **Action:** consolidate what the harness found **on its own** into a first-cut
  finding list. This is the machine's honest output, and it is explicitly not the
  final word: some candidates will be false positives, and some real chains will
  still be missing.
- **Artifact:** findings with `status: first-cut` + a first-cut summary section in
  `engagement.state`.
- **Gate:** every first-cut finding has: repro, evidence, impact, and an honest
  confidence note. The human is now expected in the loop. This is the hand-off.

## Step 6: Human review (decide which paths are worth building)

- **Input:** the first cut.
- **Who:** **human** (the man-in-the-loop step).
- **Action:** the operator reviews each finding and decides: discard (false positive),
  accept as-is, or **build a path** toward a larger chain. This is where operator
  judgment outranks the model: a prompting insight, a business-logic hunch, a piece
  of context the harness did not have.
- **Artifact:** for each finding, an `operator_decision` block in the finding file
  (`accepted / discarded / path-built` + one-line rationale).
- **Gate:** no finding advances to Step 8 without a recorded human decision. The
  agent may not self-approve a chain.

## Step 7: Operator journal (record the manual work)

- **Input:** Step 6 decisions and everything the operator did by hand.
- **Who:** human (narrates), agent (records).
- **Action:** log each manual intervention in the **operator journal**. This is the
  operational trace behind the paper's Human-Required Map: which of the seven
  categories fired, what the harness failed to see, what the operator's insight was,
  and how it was validated. This artifact is the difference between "the AI found
  it" and the truth: **the human closed it**.
- **Artifact:** `journal/YYYY-MM-DD-NNN.md` from `templates/operator-journal.md`.
- **Gate:** every Step-8 chain must cite at least one journal entry, or state
  explicitly that it was fully autonomous (rare, and worth flagging).

## Step 8: Chain confirmation with the human insight

- **Input:** Step 6 decisions + Step 7 journal.
- **Who:** both.
- **Action:** MOSRAI confirms the operational details to complete the chain using
  the operator's insight: prerequisites, order of operations, exact requests/hooks,
  and the reproducible path from entry point to impact. Record whether each link
  was AI-executed or human-closed.
- **Artifact:** `chains/CHAIN-NNN.md` from `templates/CHAIN.md` + the finding(s)
  upgraded with the full chain.
- **Gate:** the full chain reproduces end to end from a cold start; human go/no-go
  before any destructive or high-volume action.

## Step 9: Retest checklist (automatic reproduction package)

- **Input:** consolidated findings + chains.
- **Who:** agent generates; human reviews.
- **Action:** generate a per-finding retest checklist that reproduces every finding:
  original repro steps, expected-fixed vs expected-persists behavior, artifact hash
  of the build tested, and which steps need a human (physical device, MFA, etc.).
  When the developer ships a new build, the retest runs from this checklist.
- **Artifact:** `retest/round-N/CHECKLIST.md` + round evidence folder.
- **Gate:** the checklist runs top to bottom without missing evidence; each item
  produces a canonical verdict (MITIGATED / PARTIAL / PERSISTS / PENDING /
  NOT VERIFIABLE / RISK ACCEPTED) recorded in `LEDGER.md`.

## Step 10: Remediation lifecycle + standards

- **Input:** the ledger across rounds.
- **Who:** both.
- **Action:** track remediation round after round. Each finding carries a weakness
  classification (MASWE when the weakness maps; `n/a` + the right external taxonomy
  otherwise, e.g. LLM findings map to the OWASP LLM Top 10, not MASWE), a MASTG
  test reference for the verification procedure, and a MASVS group for reporting.
  The ledger is the client-facing truth: what is fixed, what persists, and what
  could not be proven.
- **Artifact:** `LEDGER.md` (append-only) + the finding's standards block.
- **Gate:** the cycle closes when every open finding carries an evidence-backed
  verdict and the client can act on it. NOT VERIFIABLE and RISK ACCEPTED are never
  counted as fixes.

---

## Rules that hold across the whole cycle

1. **The exploit is the verifier.** A finding is real when a reproducible chain
   stands as ground truth.
2. **Determinism to tool; exploration to AI; judgment to human.** Mechanical work
   (state, ledger, checksums, scaffolding) belongs in scripts, not in model memory.
3. **Two planes, never conflated.** Operator-plane models (this setup) and
   target-plane models (inside the audited app) are tracked separately.
4. **Honest verdicts.** An untested fix is NOT VERIFIABLE; a client deferral is
   RISK ACCEPTED. Neither is MITIGATED.
5. **The human is on the record.** Step 6-8 artifacts exist so the manual work is
   visible, auditable, and upstream-able into new skills.
6. **No client data leaves.** Run `mosrai scrub` (fail-closed) before sharing any
   engagement output.

## Standards reference (short)

| Layer | Use in MOSRAI |
|---|---|
| **MASVS** | Grouping for reports (STORAGE / CRYPTO / AUTH / NETWORK / PLATFORM / CODE / RESILIENCE / PRIVACY) |
| **MASWE** | Weakness ID per finding when it maps (e.g. insecure deep links to MASWE-0029; pinning to MASWE-0028; root/JB detection missing to MASWE-0051). LLM/web-API classes may not have a MASWE: record `n/a` + the external taxonomy used |
| **MASTG** | Test procedures that back the verification steps of each finding |

Standards are used as shared vocabulary and procedure, not as a claim of full
coverage.
