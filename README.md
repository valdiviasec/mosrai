<div align="center">

<img src="assets/logo.svg" width="128" alt="MOSRAI"/>

# MOSRAI

**Mobile Offensive Security Research AI Agent**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![Skills: 58](https://img.shields.io/badge/Skills-58-green.svg)](SKILL_INDEX.txt)
[![Platforms: Android + iOS](https://img.shields.io/badge/Platform-Android%20%7C%20iOS-lightgrey.svg)](#)

*Determinism goes to tools. Exploration goes to AI. Judgment goes to humans.*

</div>

---

## Why MOSRAI

AI agents promise autonomous pentests. In mobile, that promise hits three realities: business logic lives in bytecode or AOT snapshots, the runtime resists instrumentation, and real impact almost always sits in the backend. There is no autonomous shortcut through that.

MOSRAI is the methodology layer that loads into any harness (OpenCode, Claude Code, Cursor, direct API) and provides:

| | MOSRAI | Static scanners | Autonomous agents |
|---|---|---|---|
| Structured methodology | 58 skills | Fixed rules | Improvises |
| Mandatory human gates | Yes (6-8) | No | No |
| Retest ledger (rounds) | Yes | No | No |
| Attack surface matrix | Yes | No | No |
| Works with any model | Yes | N/A | Vendor-locked |

## Quickstart

```bash
git clone https://github.com/valdiviasec/mosrai.git
cd mosrai

python3 mosrai validate          # self-test
python3 mosrai init ~/engagements/my-app --app target.apk
python3 mosrai start              # verify environment
```

Then connect your harness and the agent follows the cycle in `CYCLE.md`:

```
init → start → matrix → hunt → report
  ↑                        ↑
  scaffold            attack surface
                     (exhaustive)
```

## The flow

```bash
python3 mosrai init ~/engagements/app --app target.apk   # scaffold + auto-detect
python3 mosrai start                                       # verify device + proxy + frida
python3 mosrai matrix                                      # attack surface matrix
# ... the harness does the hunting ...
python3 mosrai report                                      # scrub + redacted dist/
```

## Structure

```
mosrai/               Unified CLI (14 subcommands)
MOSRAI.md              System prompt (loads into the harness)
CYCLE.md               Engagement cycle (10 steps)
SETUP.md               Per-harness installation
CONTRIBUTING.md        Skill authoring standard
skills/                58 skills + 8 orchestrators (curated starter set)
templates/             7 artifact templates
tools/
  seeds/               5 Frida scripts (ssl unpin, root bypass)
  lint.py              Skill linter (structure)
  provenance-lint.py   Origin gate (no third-party references)
  build_index.py       Regenerate SKILL_INDEX.txt
  allowlist.txt        Scrub technical signatures
```

## Bring your own skills

MOSRAI is modular by design. The 58 skills in this repository are a **curated
starter set**, not a fixed catalog — you extend it with skills for the stacks,
frameworks and bug classes your engagements actually hit.

A skill is just a folder with a `SKILL.md`. The authoring standard is in
`CONTRIBUTING.md`; the short version is:

```bash
python3 mosrai new skills/my-skill-slug     # scaffold
# ... write the technique with generic placeholders (no target-specific names) ...
python3 tools/lint.py && python3 tools/provenance-lint.py
python3 tools/build_index.py                # refresh SKILL_INDEX.txt
```

Skills are technique-anchored and portable across harnesses. They follow the open
Agent Skills format, so anything you add here works in the same clients as the
shipped skills.

## Commands

| Command | What it does |
|---|---|
| `mosrai init` | Scaffold engagement + auto-detect platform |
| `mosrai start` | Verify device, proxy, frida, model |
| `mosrai status` | Engagement snapshot (phase, findings, gaps) |
| `mosrai matrix` | Generate attack surface matrix (endpoint x vector) |
| `mosrai journal` | Log a human intervention (Human-Required Map) |
| `mosrai chain` | Confirm a kill chain |
| `mosrai retest` | Generate retest checklist per round |
| `mosrai ledger` | Record a verdict (6 values) |
| `mosrai scrub` | Confidentiality gate (fail-closed) |
| `mosrai report` | Consolidate + redact + distribute |
| `mosrai validate` | Repo self-test |
| `mosrai lint` | Verify skills |

## Verification

```bash
python3 mosrai validate
# [PASS] lint: 0 failures
# [PASS] index: up to date
# [PASS] scrub-controls: PII blocked
# [PASS] cycle: verified
# [PASS] seeds-syntax: 5 scripts parse
# Result: PASS (5/5)
```

## Confidentiality

`mosrai scrub` is a fail-closed gate: checks emails, phone numbers, government IDs, credentials, high-entropy strings, and internal hostnames. If there is a match, it does not distribute.

## License

[MIT](LICENSE)
