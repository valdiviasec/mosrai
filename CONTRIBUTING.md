# Contributing skills

MOSRAI is a **modular skill pack**. The skills under `skills/` are a curated
starter set; you are expected to add your own. This document is the authoring
standard — it is enforced in CI, so contributions stay portable and generic.

## The format

Every skill is a folder with a `SKILL.md` file. The `name` and `description`
fields are required; the rest are MOSRAI extensions used for routing and tiers.

```
skills/<slug>/
├── SKILL.md          # required: YAML frontmatter + instructions
├── scripts/          # optional: executable helpers
├── references/       # optional: long-form documentation
└── assets/           # optional: templates, resources
```

Frontmatter:

```yaml
---
name: my-skill-slug
description: Use when ... . Triggers - "keyword1", "keyword2"
platform: [android, ios]
stack: [native]            # native | flutter | react-native | capacitor | any
category: recon            # enabling | recon | crypto | vectors-misc | ipc | storage | injection | webview | deeplink | auth | backend-pivot
tier: B                    # A = every engagement, B = stack/category match, C = niche
kind: technique            # optional: primitive | technique | enabling | tooling
related: [other-skill]
---
```

The `description` is what the agent sees first, so it must state **when to use
the skill** and include the trigger keywords. Keep it self-contained: an agent
reading only the description should know whether to load the skill.

## Authoring rules

1. **Technique-anchored, not target-anchored.** Write the general pattern and
   how to apply it. Do not describe a single app, challenge or engagement.
2. **Generic placeholders.** Use `<package>`, `<binary>`, `<app>` — never real
   package names, module names, offsets or URLs from a specific target.
3. **No third-party origins.** Do not name real targets, training apps,
   write-ups, their authors or repositories, and do not add origin metadata to
   shipped skills.
4. **Determinism where possible.** Prefer a command or script over prose. Resolve
   values at runtime (symbol lookup, pattern scan) instead of hardcoding them.
5. **Say the pitfalls.** The most valuable part of a skill is what fails and why.
6. **No secrets, no client data, no engagement artifacts.**

## Add a skill

```bash
python3 mosrai new skills/my-skill-slug     # scaffold from the template
# edit skills/my-skill-slug/SKILL.md
python3 tools/lint.py                        # structural checks
python3 tools/provenance-lint.py             # origin gate
python3 tools/build_index.py                 # regenerate SKILL_INDEX.txt
```

## CI gates

A pull request must pass:

- `tools/lint.py` — frontmatter, required fields, duplicate names, structure.
- `tools/provenance-lint.py` — fails on named targets, training-app names,
  write-up references and origin metadata.
- `tools/build_index.py` — `SKILL_INDEX.txt` must be up to date.

Third-party content is never vendored. Techniques are re-expressed from first
principles; do not copy text or code from other repositories or write-ups.
