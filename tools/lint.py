#!/usr/bin/env python3
"""MOSRAI Skill Linter: validates skills/*/SKILL.md frontmatter and structure.

Checks performed:
  1. Frontmatter is parseable YAML (between --- markers)
  2. Required fields present and non-empty: name, description, category, platform, tier
  3. Description quality: > 80 chars, starts with "Use when"
  4. Category is one of the allowed values
  5. Related links resolve to existing skills/<slug>/SKILL.md on disk
  6. No two skills share the same name field
  7. Each slug directory has exactly one SKILL.md

Usage:
  python3 tools/lint.py            # plain text report
  python3 tools/lint.py --json     # machine-readable JSON
  python3 tools/lint.py --fix      # auto-fix broken related links
"""

import os
import re
import sys
import json
import glob
import argparse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKILLS_DIR = os.path.join(REPO, "skills")

VALID_CATEGORIES = {
    "enabling", "recon", "crypto", "vectors-misc", "ipc",
    "storage", "injection", "webview", "deeplink", "auth", "backend-pivot",
}

REQUIRED_FIELDS = ["name", "description", "category", "platform", "tier"]

DESC_MIN_LENGTH = 80
DESC_REQUIRED_PREFIX = "Use when"


# ---------------------------------------------------------------------------
# Frontmatter parsing (mirrors build_skill_index.py logic)
# ---------------------------------------------------------------------------

def parse_frontmatter(path):
    """Return (dict, raw_text) or (None, raw_text) if frontmatter is missing/broken."""
    with open(path, encoding="utf-8", errors="replace") as f:
        text = f.read()
    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    if not m:
        return None, text
    d = {}
    for line in m.group(1).splitlines():
        mm = re.match(r'^(\w[\w-]*):\s*(.*)$', line)
        if mm:
            key = mm.group(1)
            val = mm.group(2).strip()
            # Strip surrounding quotes (YAML scalars)
            if (val.startswith('"') and val.endswith('"')) or \
               (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            # Parse inline YAML list [a, b, c]
            if val.startswith("["):
                raw = val.strip("[]")
                if raw.strip():
                    val = [v.strip().strip("'\"") for v in raw.split(",")]
                else:
                    val = []
            d[key] = val
    return d, text


def get_all_slugs():
    """Return set of slug names that have a SKILL.md."""
    slugs = set()
    for p in glob.glob(os.path.join(SKILLS_DIR, "*/SKILL.md")):
        slugs.add(os.path.basename(os.path.dirname(p)))
    return slugs


# ---------------------------------------------------------------------------
# Lint checks
# ---------------------------------------------------------------------------

class LintResult:
    FAILURE = "FAILURE"
    WARNING = "WARNING"

    def __init__(self, slug, code, message, severity=FAILURE):
        self.slug = slug
        self.code = code
        self.message = message
        self.severity = severity

    def __str__(self):
        return f"  [{self.code}] {self.slug}: {self.message}"

    def to_dict(self):
        return {
            "slug": self.slug,
            "code": self.code,
            "message": self.message,
            "severity": self.severity.lower(),
        }


def lint_skill(slug, path, all_slugs):
    """Run all checks on a single skill. Returns list of LintResult."""
    results = []

    fm, text = parse_frontmatter(path)

    # Check 1: Frontmatter parseable
    if fm is None:
        results.append(LintResult(slug, "BAD_FRONTMATTER", "YAML frontmatter missing or unparseable"))
        return results  # Can't check anything else

    # Check 2: Required fields present and non-empty
    for field in REQUIRED_FIELDS:
        val = fm.get(field)
        if val is None:
            results.append(LintResult(slug, "MISSING_FIELD", f"missing required field '{field}'"))
        elif isinstance(val, str) and not val.strip():
            results.append(LintResult(slug, "EMPTY_FIELD", f"required field '{field}' is empty"))
        elif isinstance(val, list) and len(val) == 0:
            results.append(LintResult(slug, "EMPTY_FIELD", f"required field '{field}' is empty"))

    # Check 3: Description quality
    desc = fm.get("description", "")
    if isinstance(desc, str) and desc:
        if len(desc) < DESC_MIN_LENGTH:
            results.append(LintResult(
                slug, "BAD_DESC",
                f"description too short ({len(desc)} chars, minimum {DESC_MIN_LENGTH})"
            ))
        if not desc.startswith(DESC_REQUIRED_PREFIX):
            results.append(LintResult(
                slug, "BAD_DESC",
                f"description must start with '{DESC_REQUIRED_PREFIX}'"
            ))

    # Check 4: Valid category
    cat = fm.get("category", "")
    if isinstance(cat, str) and cat and cat not in VALID_CATEGORIES:
        results.append(LintResult(
            slug, "BAD_CATEGORY",
            f"category '{cat}' not in allowed set: {sorted(VALID_CATEGORIES)}"
        ))

    # Check 5: Related links resolve
    related = fm.get("related", [])
    if isinstance(related, str):
        related = [related] if related else []
    broken = []
    for rel_slug in related:
        rel_slug = rel_slug.strip()
        if not rel_slug:
            continue
        if rel_slug not in all_slugs:
            broken.append(rel_slug)
            results.append(LintResult(
                slug, "BROKEN_LINK",
                f"related '{rel_slug}' not found"
            ))

    return results


def check_duplicate_names(slug_fm_map):
    """Check for duplicate name fields across all skills. Returns list of LintResult."""
    results = []
    name_to_slugs = {}
    for slug, fm in slug_fm_map.items():
        if fm is None:
            continue
        name = fm.get("name", "")
        if not name:
            continue
        name_to_slugs.setdefault(name, []).append(slug)
    for name, slugs in name_to_slugs.items():
        if len(slugs) > 1:
            slugs_str = " and ".join(sorted(slugs))
            for s in slugs:
                results.append(LintResult(
                    s, "DUPLICATE",
                    f"{slugs_str} have the same name '{name}'",
                    severity=LintResult.WARNING,
                ))
    return results


def check_file_structure(slug, skill_dir):
    """Check that the slug dir has exactly one SKILL.md. Returns list of LintResult."""
    results = []
    md_files = [f for f in os.listdir(skill_dir) if f.upper() == "SKILL.MD"]
    if len(md_files) == 0:
        results.append(LintResult(slug, "NO_SKILL_MD", "directory has no SKILL.md"))
    elif len(md_files) > 1:
        results.append(LintResult(
            slug, "MULTI_SKILL_MD",
            f"directory has multiple SKILL.md files: {md_files}"
        ))
    return results


# ---------------------------------------------------------------------------
# Auto-fix: remove broken related links
# ---------------------------------------------------------------------------

def fix_broken_links(path, all_slugs):
    """Remove broken slugs from the related: field in-place. Returns count of removals."""
    with open(path, encoding="utf-8") as f:
        text = f.read()

    m = re.match(r"^---\n(.*?)\n---", text, re.S)
    if not m:
        return 0

    fm_block = m.group(1)
    fixed_count = 0

    def fix_related_line(line_match):
        nonlocal fixed_count
        line = line_match.group(0)
        # Extract the list portion
        list_m = re.search(r'\[([^\]]*)\]', line)
        if not list_m:
            return line
        items_raw = list_m.group(1)
        if not items_raw.strip():
            return line
        items = [v.strip().strip("'\"") for v in items_raw.split(",")]
        kept = [i for i in items if i in all_slugs or not i.strip()]
        removed = len(items) - len(kept)
        if removed == 0:
            return line
        fixed_count += removed
        new_list = ", ".join(kept) if kept else ""
        return f"related: [{new_list}]"

    new_fm = re.sub(r'^related:\s*\[.*?\]', fix_related_line, fm_block, flags=re.M)

    if fixed_count > 0:
        new_text = text[:m.start(1)] + new_fm + text[m.end(1):]
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_text)

    return fixed_count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MOSRAI Skill Linter")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--fix", action="store_true", help="Auto-fix broken related links")
    args = parser.parse_args()

    all_slugs = get_all_slugs()
    skill_paths = sorted(glob.glob(os.path.join(SKILLS_DIR, "*/SKILL.md")))

    # Collect all frontmatter for duplicate-name check
    slug_fm_map = {}
    all_results = []
    fix_count = 0

    for p in skill_paths:
        slug = os.path.basename(os.path.dirname(p))
        skill_dir = os.path.dirname(p)

        # File structure check
        all_results.extend(check_file_structure(slug, skill_dir))

        # Parse and lint
        fm, text = parse_frontmatter(p)
        slug_fm_map[slug] = fm
        all_results.extend(lint_skill(slug, p, all_slugs))

        # Auto-fix if requested
        if args.fix:
            fixed = fix_broken_links(p, all_slugs)
            fix_count += fixed

    # Also scan for directories that exist but have no SKILL.md
    for entry in sorted(os.listdir(SKILLS_DIR)):
        entry_path = os.path.join(SKILLS_DIR, entry)
        if os.path.isdir(entry_path) and entry not in {os.path.basename(os.path.dirname(p)) for p in skill_paths}:
            all_results.append(LintResult(entry, "NO_SKILL_MD", "directory has no SKILL.md"))

    # Duplicate name check
    all_results.extend(check_duplicate_names(slug_fm_map))

    # Partition results
    failures = [r for r in all_results if r.severity == LintResult.FAILURE]
    warnings = [r for r in all_results if r.severity == LintResult.WARNING]
    total = len(skill_paths)
    failed_slugs = {r.slug for r in failures}
    passed = total - len(failed_slugs)

    if args.json:
        output = {
            "skills_scanned": total,
            "passed": passed,
            "failed": len(failed_slugs),
            "failures": [r.to_dict() for r in failures],
            "warnings": [r.to_dict() for r in warnings],
        }
        if args.fix:
            output["fixes_applied"] = fix_count
        print(json.dumps(output, indent=2))
    else:
        print("=== MOSRAI Skill Lint ===")
        print(f"Skills scanned: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {len(failed_slugs)}")
        print()

        if failures:
            print("FAILURES:")
            for r in sorted(failures, key=lambda x: (x.slug, x.code)):
                print(str(r))
            print()

        if warnings:
            print("WARNINGS:")
            for r in sorted(warnings, key=lambda x: (x.slug, x.code)):
                print(str(r))
            print()

        if args.fix:
            print(f"Fixes applied: {fix_count} broken related links removed")
            print()

        f_count = len(failures)
        w_count = len(warnings)
        print(f"Summary: {f_count} failure{'s' if f_count != 1 else ''}, "
              f"{w_count} warning{'s' if w_count != 1 else ''}")

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
