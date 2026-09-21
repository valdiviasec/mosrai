#!/usr/bin/env python3
"""provenance-lint — fail if a shipped skill leaks third-party origin references.

The public pack ships skills as original, technique-anchored knowledge. This gate
blocks named targets, training-app names, write-up references, solver-file paths
and origin metadata from reaching the public repository.

Run:  python3 tools/provenance-lint.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKILLS = ROOT / "skills"

# Generic origin markers. Matched case-insensitively per line.
PATTERNS = [
    (r"\bCTF\b", "CTF framing"),
    (r"CTF\{", "CTF flag format"),
    (r"\bwrite-?up\b", "write-up reference"),
    (r"provenance\s*:", "provenance metadata"),
    (r"aux/solve", "challenge solver path"),
    (r"solve_static", "challenge solver path"),
]

# Optional local extras (gitignored): one regex per line, '#' for comments.
# Maintainers can keep a richer denylist without shipping it.
_LOCAL_DENYLIST = ROOT / "tools" / "provenance-denylist.local.txt"
if _LOCAL_DENYLIST.is_file():
    for _line in _LOCAL_DENYLIST.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#"):
            PATTERNS.append((_line, "local denylist"))

COMPILED = [(re.compile(p, re.IGNORECASE), why) for p, why in PATTERNS]


def main() -> int:
    files = sorted(SKILLS.glob("*/SKILL.md"))
    if not files:
        print("[FAIL] provenance-lint: no skills found")
        return 1

    failures = []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for rx, why in COMPILED:
                if rx.search(line):
                    failures.append((f.relative_to(ROOT), lineno, why, line.strip()[:140]))

    if failures:
        print(f"[FAIL] provenance-lint: {len(failures)} origin leak(s) in {len({str(x[0]) for x in failures})} file(s)\n")
        for rel, lineno, why, snippet in failures:
            print(f"  {rel}:{lineno}: {why} -> {snippet}")
        return 1

    print(f"[PASS] provenance-lint: {len(files)} skills clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
