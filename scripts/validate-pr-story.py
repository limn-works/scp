#!/usr/bin/env python3
"""Validate a PR against its referenced PRD story.

Cross-references the PR contents (body, changed files) against the
original PRD story to flag mismatches, missing work, gaps, and stubs.

Input:
  stdin or --body-file: PR body (markdown from template)
  --files-file: path to changed files list (one per line)
  --story-id: override story ID extraction from body

Output: JSON to stdout with structured report.

Exit codes:
  0 — all checks passed
  1 — validation findings (warnings or errors)
  2 — parse error (could not extract story ID or find story)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def extract_story_id(body: str) -> str | None:
    """Extract story ID from PR body.

    Checks for:
      1. <!-- story-id: PREFIX-NNN -->
      2. **ID** | `PREFIX-NNN`  (table row)
      3. Bare PREFIX-NNN pattern in first 500 chars
    """
    # HTML comment marker
    m = re.search(r"<!--\s*story-id:\s*([A-Z]+-\d{3})\s*-->", body)
    if m:
        return m.group(1)

    # Table row: | **ID** | `PREFIX-NNN` |
    m = re.search(r"\*\*ID\*\*\s*\|\s*`([A-Z]+-\d{3})`", body)
    if m:
        return m.group(1)

    # Fallback: first story ID pattern in the first 500 chars
    m = re.search(r"\b([A-Z]+-\d{3})\b", body[:500])
    if m:
        return m.group(1)

    return None


def extract_checked_ac(body: str) -> tuple[list[str], list[str]]:
    """Extract acceptance criteria and their check status.

    Returns (checked, unchecked) lists of criterion text.
    """
    checked: list[str] = []
    unchecked: list[str] = []

    # Find the AC section between markers or under ## Acceptance Criteria
    ac_section = ""
    m = re.search(
        r"<!--\s*ac:start\s*-->(.*?)<!--\s*ac:end\s*-->",
        body, re.DOTALL
    )
    if m:
        ac_section = m.group(1)
    else:
        m = re.search(
            r"## Acceptance Criteria\s*\n(.*?)(?=\n## |\Z)",
            body, re.DOTALL
        )
        if m:
            ac_section = m.group(1)

    for line in ac_section.splitlines():
        line = line.strip()
        cm = re.match(r"-\s*\[([xX ])\]\s*(.+)", line)
        if cm:
            text = cm.group(2).strip()
            if text.startswith("_") and text.endswith("_"):
                continue  # skip template placeholders
            if cm.group(1).lower() == "x":
                checked.append(text)
            else:
                unchecked.append(text)

    return checked, unchecked


# ---------------------------------------------------------------------------
# Story lookup
# ---------------------------------------------------------------------------

def find_story(story_id: str) -> tuple[dict | None, str | None]:
    """Find a story by ID across all PRD files.

    Returns (story_dict, prd_filename) or (None, None).
    """
    prd_dir = REPO_ROOT / ".docs" / "prds"
    if not prd_dir.is_dir():
        return None, None

    for prd_file in prd_dir.glob("*.json"):
        try:
            with open(prd_file, encoding="utf-8") as f:
                data = json.load(f)
            for story in data.get("stories", []):
                if story.get("id") == story_id:
                    return story, prd_file.stem
        except (json.JSONDecodeError, OSError):
            continue

    return None, None


def collect_all_stories() -> dict[str, dict]:
    """Collect all stories across PRD files."""
    prd_dir = REPO_ROOT / ".docs" / "prds"
    all_stories: dict[str, dict] = {}
    if not prd_dir.is_dir():
        return all_stories
    for prd_file in prd_dir.glob("*.json"):
        try:
            with open(prd_file, encoding="utf-8") as f:
                data = json.load(f)
            for story in data.get("stories", []):
                sid = story.get("id", "")
                if sid:
                    all_stories[sid] = story
        except (json.JSONDecodeError, OSError):
            pass
    return all_stories


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_file_coverage(
    story_files: list[str],
    changed_files: list[str],
) -> tuple[list[str], list[str], list[str]]:
    """Compare story files vs PR changed files.

    Returns (missing, extra, matched).
    - missing: in story but not in PR
    - extra: in PR but not in story (not necessarily bad)
    - matched: in both
    """
    story_set = set(story_files)
    changed_set = set(changed_files)

    matched = sorted(story_set & changed_set)
    missing = sorted(story_set - changed_set)
    extra = sorted(changed_set - story_set)

    return missing, extra, matched


def check_dependencies(story: dict) -> list[dict]:
    """Check that all blockedBy stories are done.

    Returns list of {id, status, title} for non-done dependencies.
    """
    all_stories = collect_all_stories()
    blocking: list[dict] = []

    for dep_id in story.get("blockedBy", []):
        dep = all_stories.get(dep_id)
        if dep is None:
            blocking.append({
                "id": dep_id,
                "status": "not-found",
                "title": "(story not found)",
            })
        elif dep.get("status") != "done":
            blocking.append({
                "id": dep_id,
                "status": dep.get("status", "unknown"),
                "title": dep.get("title", ""),
            })

    return blocking


def check_stubs(story_id: str, changed_files: list[str]) -> list[dict]:
    """Find stubs referencing this story ID in changed files."""
    stubs: list[dict] = []
    stub_pattern = re.compile(
        rf"(Stub|TODO|FIXME|HACK)\s*[-—:]\s*(see\s+)?{re.escape(story_id)}",
        re.IGNORECASE,
    )

    for filepath in changed_files:
        resolved = REPO_ROOT / filepath
        if not resolved.is_file():
            continue
        try:
            for lineno, line in enumerate(
                resolved.read_text(encoding="utf-8").splitlines(), 1
            ):
                if stub_pattern.search(line):
                    stubs.append({
                        "file": filepath,
                        "line": lineno,
                        "text": line.strip(),
                    })
        except (OSError, UnicodeDecodeError):
            continue

    return stubs


def check_test_coverage(changed_files: list[str]) -> dict:
    """Assess test file presence among changed files."""
    test_files: list[str] = []
    src_files: list[str] = []

    test_patterns = [
        r"tests?/",
        r"_test\.\w+$",
        r"\.test\.\w+$",
        r"test_\w+\.\w+$",
        r"#\[cfg\(test\)\]",  # Rust inline tests (detected by filename heuristic)
    ]

    for f in changed_files:
        if any(re.search(p, f) for p in test_patterns[:4]):
            test_files.append(f)
        else:
            src_files.append(f)

    # Also check for inline test modules in Rust source files
    for f in src_files:
        if f.endswith(".rs"):
            resolved = REPO_ROOT / f
            if resolved.is_file():
                try:
                    content = resolved.read_text(encoding="utf-8")
                    if "#[cfg(test)]" in content:
                        test_files.append(f"{f} (inline)")
                except (OSError, UnicodeDecodeError):
                    pass

    return {
        "test_files": test_files,
        "src_files": src_files,
        "has_tests": len(test_files) > 0,
    }


def check_source_freshness(story: dict) -> list[dict]:
    """Check if source files have been modified more recently than expected.

    Uses git log to see if source files were touched after the story
    was presumably created. Returns list of potentially stale sources.
    """
    stale: list[dict] = []

    for source in story.get("sources", []):
        if isinstance(source, dict):
            source_file = source.get("file", "")
            source_section = source.get("section", "")
        elif isinstance(source, str):
            source_file = source
            source_section = ""
        else:
            continue

        if not source_file:
            continue

        resolved = REPO_ROOT / source_file
        if not resolved.is_file():
            stale.append({
                "file": source_file,
                "section": source_section,
                "reason": "file does not exist",
            })
            continue

        # Check if section heading still exists
        if source_section:
            try:
                content = resolved.read_text(encoding="utf-8")
                if source_section not in content:
                    stale.append({
                        "file": source_file,
                        "section": source_section,
                        "reason": "section heading not found in file",
                    })
            except (OSError, UnicodeDecodeError):
                pass

    return stale


def check_ac_vs_story(
    story: dict,
    checked_ac: list[str],
    unchecked_ac: list[str],
) -> dict:
    """Compare PR acceptance criteria against story criteria."""
    story_ac = story.get("acceptanceCriteria", [])
    pr_ac = checked_ac + unchecked_ac

    # Fuzzy match: normalize whitespace and check containment
    def normalize(s: str) -> str:
        return re.sub(r"\s+", " ", s.strip().lower())

    story_normalized = {normalize(ac): ac for ac in story_ac}
    pr_normalized = {normalize(ac): ac for ac in pr_ac}

    # Find story ACs not in PR
    missing_from_pr = []
    for norm, orig in story_normalized.items():
        if norm not in pr_normalized:
            # Check partial match
            found = any(norm in pn or pn in norm for pn in pr_normalized)
            if not found:
                missing_from_pr.append(orig)

    # Find PR ACs not in story (extra/modified)
    extra_in_pr = []
    for norm, orig in pr_normalized.items():
        if norm not in story_normalized:
            found = any(norm in sn or sn in norm for sn in story_normalized)
            if not found:
                extra_in_pr.append(orig)

    return {
        "story_ac_count": len(story_ac),
        "pr_ac_count": len(pr_ac),
        "checked_count": len(checked_ac),
        "unchecked_count": len(unchecked_ac),
        "missing_from_pr": missing_from_pr,
        "extra_in_pr": extra_in_pr,
        "all_checked": len(unchecked_ac) == 0 and len(pr_ac) > 0,
    }


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def build_report(
    story_id: str,
    story: dict,
    prd_name: str,
    findings: dict,
) -> str:
    """Build a markdown report from findings."""
    lines = ["## PRD Story Review\n"]
    lines.append(
        f"**Story:** `{story_id}` — {story.get('title', '<untitled>')}"
    )
    lines.append(f"**PRD:** `{prd_name}.json`")
    lines.append(
        f"**Gate:** `{story.get('gate', '?')}` | "
        f"**Priority:** {story.get('priority', '?')} | "
        f"**Severity:** {story.get('severity', '?')}"
    )
    lines.append("")

    errors: list[str] = []
    warnings: list[str] = []
    info: list[str] = []

    # --- File coverage ---
    fc = findings["file_coverage"]
    if fc["missing"]:
        errors.append(
            f"**Missing files** (in story but not in PR): "
            + ", ".join(f"`{f}`" for f in fc["missing"])
        )
    if fc["extra"]:
        info.append(
            f"**Extra files** (in PR but not in story): "
            + ", ".join(f"`{f}`" for f in fc["extra"][:10])
            + (f" (+{len(fc['extra']) - 10} more)" if len(fc["extra"]) > 10 else "")
        )

    # --- Dependencies ---
    if findings["blocking_deps"]:
        for dep in findings["blocking_deps"]:
            errors.append(
                f"**Blocking dependency** `{dep['id']}` is "
                f"`{dep['status']}`: {dep['title']}"
            )

    # --- Stubs ---
    if findings["stubs"]:
        for stub in findings["stubs"]:
            errors.append(
                f"**Stub remaining** at `{stub['file']}:{stub['line']}`: "
                f"`{stub['text'][:100]}`"
            )

    # --- Story status ---
    status = story.get("status", "")
    if status == "done":
        warnings.append(
            "Story is already marked `done` — this PR may be redundant "
            "or the story status was set prematurely"
        )
    elif status not in ("pending", "in-progress"):
        warnings.append(f"Unexpected story status: `{status}`")

    # --- Source freshness ---
    if findings["stale_sources"]:
        for ss in findings["stale_sources"]:
            if ss["reason"] == "file does not exist":
                errors.append(
                    f"**Source file missing:** `{ss['file']}`"
                )
            else:
                warnings.append(
                    f"**Source drift:** `{ss['file']}` — {ss['reason']}"
                    + (f" (section: `{ss['section']}`)" if ss.get("section") else "")
                )

    # --- Acceptance criteria ---
    ac = findings["ac_comparison"]
    if ac["missing_from_pr"]:
        for criterion in ac["missing_from_pr"]:
            errors.append(
                f"**Missing AC** (in story, not in PR): {criterion}"
            )
    if ac["extra_in_pr"]:
        for criterion in ac["extra_in_pr"]:
            info.append(
                f"**Extra AC** (in PR, not in story): {criterion}"
            )
    if not ac["all_checked"] and ac["pr_ac_count"] > 0:
        warnings.append(
            f"**{ac['unchecked_count']}/{ac['pr_ac_count']} acceptance "
            f"criteria unchecked**"
        )

    # --- Test coverage ---
    tc = findings["test_coverage"]
    if not tc["has_tests"]:
        warnings.append(
            "**No test files detected** among changed files — "
            "every AC should have a corresponding test"
        )
    else:
        info.append(
            f"Test files: {len(tc['test_files'])} "
            f"({', '.join(f'`{f}`' for f in tc['test_files'][:5])})"
        )

    # --- Assemble report ---
    if errors:
        lines.append(f"### Action Required ({len(errors)})\n")
        for e in errors:
            lines.append(f"- {e}")
        lines.append("")

    if warnings:
        lines.append(f"### Warnings ({len(warnings)})\n")
        for w in warnings:
            lines.append(f"- {w}")
        lines.append("")

    if info:
        lines.append(f"### Info ({len(info)})\n")
        for i in info:
            lines.append(f"- {i}")
        lines.append("")

    if not errors and not warnings:
        lines.append("**PASSED** — PR aligns with story.\n")

    lines.append("---")
    lines.append(
        "*Cross-referenced against "
        f"[`{prd_name}.json`](.docs/prds/{prd_name}.json) by "
        "[`scripts/validate-pr-story.py`](scripts/validate-pr-story.py)*"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate PR against PRD story"
    )
    parser.add_argument(
        "--body-file",
        help="Path to PR body file (default: stdin)",
    )
    parser.add_argument(
        "--files-file",
        help="Path to changed files list (one per line)",
    )
    parser.add_argument(
        "--story-id",
        help="Override story ID (skip body parsing)",
    )
    args = parser.parse_args()

    # Read PR body
    if args.body_file:
        body = Path(args.body_file).read_text(encoding="utf-8")
    else:
        body = sys.stdin.read()

    if not body.strip():
        print(json.dumps({
            "valid": False,
            "parse_error": "Empty PR body",
        }))
        return 2

    # Extract story ID
    story_id = args.story_id or extract_story_id(body)
    if not story_id:
        print(json.dumps({
            "valid": False,
            "parse_error": (
                "Could not extract story ID from PR body. "
                "Use <!-- story-id: PREFIX-NNN --> or pass --story-id."
            ),
        }))
        return 2

    # Find story in PRD files
    story, prd_name = find_story(story_id)
    if story is None:
        print(json.dumps({
            "valid": False,
            "parse_error": f"Story {story_id} not found in any PRD file",
        }))
        return 2

    # Read changed files
    changed_files: list[str] = []
    if args.files_file:
        changed_files = [
            line.strip()
            for line in Path(args.files_file).read_text().splitlines()
            if line.strip()
        ]

    # Run all checks
    story_files = story.get("files", [])
    missing, extra, matched = check_file_coverage(story_files, changed_files)
    blocking_deps = check_dependencies(story)
    stubs = check_stubs(story_id, changed_files)
    test_coverage = check_test_coverage(changed_files)
    stale_sources = check_source_freshness(story)
    checked_ac, unchecked_ac = extract_checked_ac(body)
    ac_comparison = check_ac_vs_story(story, checked_ac, unchecked_ac)

    findings = {
        "file_coverage": {
            "missing": missing,
            "extra": extra,
            "matched": matched,
        },
        "blocking_deps": blocking_deps,
        "stubs": stubs,
        "test_coverage": test_coverage,
        "stale_sources": stale_sources,
        "ac_comparison": ac_comparison,
    }

    report = build_report(story_id, story, prd_name, findings)

    has_errors = bool(
        missing
        or blocking_deps
        or stubs
        or stale_sources
        or ac_comparison.get("missing_from_pr")
    )

    result = {
        "valid": not has_errors,
        "story_id": story_id,
        "prd_file": prd_name,
        "story_title": story.get("title", ""),
        "findings": findings,
        "error_count": sum([
            len(missing),
            len(blocking_deps),
            len(stubs),
            len([s for s in stale_sources if s["reason"] == "file does not exist"]),
            len(ac_comparison.get("missing_from_pr", [])),
        ]),
        "warning_count": sum([
            1 if not test_coverage["has_tests"] else 0,
            1 if not ac_comparison.get("all_checked", True) else 0,
            len([s for s in stale_sources if s["reason"] != "file does not exist"]),
            1 if story.get("status") == "done" else 0,
        ]),
        "report": report,
    }

    print(json.dumps(result))
    return 0 if not has_errors else 1


if __name__ == "__main__":
    sys.exit(main())
