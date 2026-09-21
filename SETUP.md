# MOSRAI Setup Guide

MOSRAI (Mobile Offensive Security Research AI Agent) is a methodology layer for mobile app security testing. It enhances any LLM harness with structured skills covering Android and iOS across native, Flutter, React Native, and Capacitor stacks.

MOSRAI is not a harness, not a model, not a CLI. It is the methodology layer. You bring the harness and model. MOSRAI brings the skills.

## Requirements

| Tool | Version | Install |
|------|---------|---------|
| jadx | 1.5.1 | `brew install jadx` |
| apktool | 2.10.0 | `brew install apktool` |
| frida-tools | 12.5.1 | `pip3 install frida-tools==12.5.1` |
| blutter | 2.7.0 | `git clone https://github.com/worawit/blutter` |
| hermes-dec | 0.4.0 | `npm install -g hermes-dec` |
| adb | any | `brew install android-platform-tools` |
| python3 | >=3.10 | system or `brew install python@3.12` |

Optional: radare2, ghidra, mobsf, class-dump. Pinned versions in `TOOLCHAIN.lock`. Device: rooted Android (Magisk) or jailbroken iOS (palera1n/Dopamine). Proxy: Burp or Caido on port 8080.

## Quickstart

```bash
python3 mosrai init ~/engagements/client-app --app Client.apk --platform android
python3 mosrai start
```

The CLI scaffolds the engagement tree, runs preflight, and records state in `engagement.state`.

## Per-harness install

### OpenCode (primary, tested)

```bash
cd ~/engagements/client-app
ln -s ~/mosrai/MOSRAI.md SYSTEM_PROMPT.md
```

OpenCode reads `SYSTEM_PROMPT.md` on launch. The model loads `mob-analyze` first, asks what app and scope, then runs Phase 0 (enabling).

### Claude Code

```bash
cd ~/engagements/client-app
mkdir -p .claude && ln -s ~/mosrai/MOSRAI.md .claude/CLAUDE.md
```

### Cursor

```bash
cd ~/engagements/client-app
ln -s ~/mosrai/MOSRAI.md .cursorrules
```

### Codex (roadmap)

Not yet supported. Planned: feed `MOSRAI.md` as the system prompt via the Codex config.

### Hermes (roadmap)

Not yet supported. Planned: direct API integration with the heavy/soft model split.

## Engagement directory

After init: `engagement.state`, `intake/`, `sources/`, `traffic/`, `context-pack.md`, `enabling.lock`, `findings/`, `evidence/`, `journal/`, `chains/`, `retest/`, `LEDGER.md`.

Engagement dirs contain client PII. Never commit them. Run `python3 mosrai scrub <path>` before sharing any output.

## Seed scripts

Pre-built Frida scripts in `tools/seeds/`: SSL unpin (Android/iOS/Flutter), root bypass Android, jailbreak bypass iOS.

```bash
frida -U -f com.target.app -l tools/seeds/ssl-unpin-android.js --no-pause
```

If a seed fails, the model derives a custom bypass from the decompiled code.
