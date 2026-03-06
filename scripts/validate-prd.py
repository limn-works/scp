#!/usr/bin/env python3
"""PRD validation script.

Validates .docs/prds/*.json files against the PRD standard
(.docs/standards/prd.md). Exits non-zero on any violation.

Checks:
  1. Schema — required fields on every story
  2. Gate registration — story listed in its gate's stories array
  3. Source file existence — sources[].file exists in repo
  4. Source section existence — sources[].section is a heading in the file
  5. Dependency validity — blockedBy references existing story IDs (same or cross-PRD)
  6. No orphaned stories — story's gate exists in gates array
  7. ID uniqueness — no duplicate story IDs
  8. Gate story completeness — gate stories array only references existing stories
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_STORY_FIELDS = [
    "id", "title", "gate", "priority", "severity", "status",
    "files", "description", "acceptanceCriteria", "actionItems",
    "blockedBy", "sources", "details",
]

VALID_PRIORITIES = {"P0", "P1", "P2"}
VALID_SEVERITIES = {"critical", "major", "moderate", "minor"}
VALID_STATUSES = {"pending", "in-progress", "done"}


def extract_headings(filepath: Path) -> set[str]:
    """Extract markdown headings from a file."""
    headings: set[str] = set()
    try:
        text = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return headings
    for line in text.splitlines():
        match = re.match(r"^(#{1,6})\s+(.+)$", line.strip())
        if match:
            headings.add(match.group(0).strip())
    return headings


def validate_prd(prd_path: Path, all_story_ids: set[str] | None = None) -> list[str]:
    """Validate a single PRD file. Returns list of error strings."""
    errors: list[str] = []

    try:
        with open(prd_path, encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return [f"{prd_path}: invalid JSON — {e}"]

    stories = data.get("stories", [])
    gates = data.get("gates", [])

    # Build indexes
    story_ids: dict[str, dict] = {}
    gate_ids: dict[str, dict] = {}
    gate_story_sets: dict[str, set[str]] = {}

    for gate in gates:
        gid = gate.get("id", "")
        gate_ids[gid] = gate
        gate_story_sets[gid] = set(gate.get("stories", []))

    # --- Check 7: ID uniqueness ---
    seen_ids: set[str] = set()
    for story in stories:
        sid = story.get("id", "<missing>")
        if sid in seen_ids:
            errors.append(f"duplicate story ID: {sid}")
        seen_ids.add(sid)
        story_ids[sid] = story

    # Heading cache for source section checks
    heading_cache: dict[str, set[str]] = {}

    for story in stories:
        sid = story.get("id", "<missing>")
        prefix = f"{sid}:"

        # --- Check 1: Required fields ---
        for field in REQUIRED_STORY_FIELDS:
            if field not in story:
                errors.append(f"{prefix} missing required field '{field}'")

        # Validate field values
        priority = story.get("priority", "")
        if priority and priority not in VALID_PRIORITIES:
            errors.append(
                f"{prefix} invalid priority '{priority}' "
                f"(expected {VALID_PRIORITIES})"
            )

        severity = story.get("severity", "")
        if severity and severity not in VALID_SEVERITIES:
            errors.append(
                f"{prefix} invalid severity '{severity}' "
                f"(expected {VALID_SEVERITIES})"
            )

        status = story.get("status", "")
        if status and status not in VALID_STATUSES:
            errors.append(
                f"{prefix} invalid status '{status}' "
                f"(expected {VALID_STATUSES})"
            )

        # --- Check 6: Gate exists ---
        gate = story.get("gate", "")
        if gate and gate not in gate_ids:
            errors.append(f"{prefix} references non-existent gate '{gate}'")

        # --- Check 2: Gate registration ---
        if gate and gate in gate_story_sets:
            if sid not in gate_story_sets[gate]:
                errors.append(
                    f"{prefix} gate '{gate}' does not list this story "
                    f"in its stories array"
                )

        # --- Check 5: Dependency validity (same-PRD and cross-PRD) ---
        valid_ids = (all_story_ids or set()) | seen_ids
        for dep in story.get("blockedBy", []):
            if dep not in valid_ids:
                errors.append(
                    f"{prefix} blockedBy references non-existent "
                    f"story '{dep}'"
                )

        # --- Check 5b: blockedByIssues must be positive integers ---
        for issue_num in story.get("blockedByIssues", []):
            if not isinstance(issue_num, int) or issue_num <= 0:
                errors.append(
                    f"{prefix} blockedByIssues contains invalid "
                    f"value '{issue_num}' (must be positive integer)"
                )

        # --- Check 3 & 4: Source existence and section headings ---
        for source in story.get("sources", []):
            if isinstance(source, str):
                source_file = source
                source_section = None
            elif isinstance(source, dict):
                source_file = source.get("file", "")
                source_section = source.get("section")
            else:
                errors.append(
                    f"{prefix} invalid source format: {source}"
                )
                continue

            if not source_file:
                continue

            resolved = REPO_ROOT / source_file
            if not resolved.is_file():
                errors.append(
                    f"{prefix} source file does not exist: "
                    f"{source_file}"
                )
                continue

            # Check section heading exists in the file
            if source_section:
                cache_key = str(resolved)
                if cache_key not in heading_cache:
                    heading_cache[cache_key] = extract_headings(resolved)

                headings = heading_cache[cache_key]
                if source_section not in headings:
                    errors.append(
                        f"{prefix} source section not found in "
                        f"{source_file}: '{source_section}'"
                    )

    # --- Check 8: Gate stories reference existing story IDs ---
    for gate in gates:
        gid = gate.get("id", "<missing>")
        for ref_sid in gate.get("stories", []):
            if ref_sid not in story_ids:
                errors.append(
                    f"gate '{gid}': references non-existent story "
                    f"'{ref_sid}'"
                )

    return errors


def collect_all_story_ids(prd_dir: Path) -> set[str]:
    """Collect all story IDs across all PRD files for cross-PRD ref validation."""
    all_ids: set[str] = set()
    for prd_file in prd_dir.glob("*.json"):
        try:
            with open(prd_file, encoding="utf-8") as f:
                data = json.load(f)
            for story in data.get("stories", []):
                sid = story.get("id", "")
                if sid:
                    all_ids.add(sid)
        except (json.JSONDecodeError, OSError):
            pass
    return all_ids


def main() -> int:
    prd_dir = REPO_ROOT / ".docs" / "prds"
    if not prd_dir.is_dir():
        print(f"No PRD directory found at {prd_dir}")
        return 1

    prd_files = sorted(prd_dir.glob("*.json"))
    if not prd_files:
        print("No PRD files found in .docs/prds/")
        return 0

    # First pass: collect all story IDs for cross-PRD validation
    all_story_ids = collect_all_story_ids(prd_dir)

    total_errors: list[str] = []
    for prd_file in prd_files:
        errors = validate_prd(prd_file, all_story_ids)
        total_errors.extend(errors)

    if total_errors:
        print(f"PRD validation failed with {len(total_errors)} error(s):\n")
        for err in total_errors:
            print(f"  - {err}")
        return 1

    story_count = 0
    for prd_file in prd_files:
        with open(prd_file) as f:
            data = json.load(f)
        story_count += len(data.get("stories", []))

    print(
        f"PRD validation passed: {len(prd_files)} file(s), "
        f"{story_count} stories"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
