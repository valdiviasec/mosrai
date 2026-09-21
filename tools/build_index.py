#!/usr/bin/env python3
"""Generate SKILL_INDEX.txt from skills/*/SKILL.md frontmatter.

Output: one line per skill, pipe-delimited:
  slug|category|tier|platform|stack

The index is designed for grep-based discovery by a harness/model.
Slugs are descriptive (e.g., frida-root-bypass, ssl-pinning-okhttp3)
and double as search keywords.

Usage:
  python3 tools/build_index.py
"""

import os
import re
import glob
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")
OUT = os.path.join(REPO, "SKILL_INDEX.txt")


def parse_frontmatter(path):
    with open(path) as f:
        text = f.read()
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    if not m:
        return None
    d = {}
    for line in m.group(1).splitlines():
        mm = re.match(r"^(\w+):\s*(.*)$", line)
        if mm:
            key = mm.group(1)
            val = mm.group(2).strip()
            if val.startswith("["):
                val = val.strip("[]")
                val = ",".join(v.strip().strip("'\"") for v in val.split(","))
            d[key] = val
    return d


def main():
    lines = []
    for p in sorted(glob.glob(os.path.join(SKILLS_DIR, "*/SKILL.md"))):
        fm = parse_frontmatter(p)
        if not fm:
            continue
        slug = os.path.basename(os.path.dirname(p))
        cat = fm.get("category", "?")
        tier = fm.get("tier", "?")
        platform = fm.get("platform", "?")
        stack = fm.get("stack", "?")
        lines.append(f"{slug}|{cat}|{tier}|{platform}|{stack}")

    header = f"# MOSRAI Skill Index: {len(lines)} skills"
    header += "\n# Format: slug|category|tier|platform|stack"
    header += "\n# Search with grep: grep -i 'flutter' SKILL_INDEX.txt"
    header += "\n# Then read: skills/<slug>/SKILL.md"

    with open(OUT, "w") as f:
        f.write(header + "\n")
        for line in lines:
            f.write(line + "\n")

    print(f"Wrote {len(lines)} skills to {OUT}")
    size = os.path.getsize(OUT)
    print(f"Index size: {size} bytes ({size // 1024}KB)")


if __name__ == "__main__":
    main()
