#!/usr/bin/env python3
"""Validate a PRD story from a GitHub issue body.

Parses structured issue form output, extracts the story JSON block,
and runs the same validations as validate-prd.py. Designed to be called
from a GitHub Action with the issue body on stdin.

Supports two input formats:
  1. GitHub issue form markdown (### headers with content)
  2. Agent JSON — direct JSON submission for programmatic creation:
     {"prd": "main", "action": "Add new story", "story": {...}}
     or bare story JSON: {"id": "SCP-042", "title": "...", ...}

Exit codes:
  0 — valid
  1 — validation errors (printed as JSON to stdout)
  2 — parse error (could not extract story JSON)
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
VALID_PRD_FILES = {
    "agent-binding", "bridge-cooperative", "capability-registry",
    "content-access", "governance-gaps", "governance-integration",
    "http-features", "main", "participation-admission", "persistence",
    "reachability", "transport-expansion",
}

ID_PATTERN = re.compile(r"^[A-Z]+-\d{3}$")


def extract_form_fields(body: str) -> dict[str, str]:
    """Extract fields from GitHub issue form markdown output.

    Issue forms render as:
      ### Label\n\n value \n\n### Next Label\n\n ...
    """
    fields: dict[str, str] = {}
    sections = re.split(r"^### (.+)$", body, flags=re.MULTILINE)
    # sections[0] is before first ###, then alternating label/content
    for i in range(1, len(sections) - 1, 2):
        label = sections[i].strip()
        content = sections[i + 1].strip()
        fields[label] = content
    return fields


def extract_story_json(fields: dict[str, str]) -> dict | None:
    """Extract and parse the story JSON from form fields."""
    raw = fields.get("Story JSON", "")
    if not raw:
        return None

    # Strip markdown code fences if present
    raw = re.sub(r"^```(?:json)?\s*\n?", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\n?```\s*$", "", raw, flags=re.MULTILINE)
    raw = raw.strip()

    if not raw:
        return None

    return json.loads(raw)


def extract_prd_file(fields: dict[str, str]) -> str:
    """Extract PRD file selection from form fields."""
    return fields.get("PRD File", "").strip()


def extract_action(fields: dict[str, str]) -> str:
    """Extract action selection from form fields."""
    return fields.get("Action", "").strip()


def collect_all_story_ids() -> set[str]:
    """Collect all story IDs across all PRD files."""
    prd_dir = REPO_ROOT / ".docs" / "prds"
    all_ids: set[str] = set()
    if not prd_dir.is_dir():
        return all_ids
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


def collect_gate_ids(prd_name: str) -> set[str]:
    """Collect gate IDs from a specific PRD file."""
    prd_path = REPO_ROOT / ".docs" / "prds" / f"{prd_name}.json"
    if not prd_path.is_file():
        return set()
    try:
        with open(prd_path, encoding="utf-8") as f:
            data = json.load(f)
        return {g.get("id", "") for g in data.get("gates", []) if g.get("id")}
    except (json.JSONDecodeError, OSError):
        return set()


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


def validate_story(story: dict, prd_name: str) -> list[str]:
    """Validate a single story object. Returns list of error strings."""
    errors: list[str] = []
    sid = story.get("id", "<missing>")

    # --- Required fields ---
    for field in REQUIRED_STORY_FIELDS:
        if field not in story:
            errors.append(f"Missing required field `{field}`")

    # --- ID format ---
    if "id" in story and not ID_PATTERN.match(sid):
        errors.append(
            f"ID `{sid}` does not match required format `PREFIX-NNN` "
            f"(zero-padded 3 digits)"
        )

    # --- Field value validation ---
    priority = story.get("priority", "")
    if priority and priority not in VALID_PRIORITIES:
        errors.append(
            f"Invalid priority `{priority}` — "
            f"must be one of {sorted(VALID_PRIORITIES)}"
        )

    severity = story.get("severity", "")
    if severity and severity not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity `{severity}` — "
            f"must be one of {sorted(VALID_SEVERITIES)}"
        )

    status = story.get("status", "")
    if status and status not in VALID_STATUSES:
        errors.append(
            f"Invalid status `{status}` — "
            f"must be one of {sorted(VALID_STATUSES)}"
        )

    # --- Array field types ---
    for field in ("files", "acceptanceCriteria", "actionItems", "blockedBy", "sources"):
        val = story.get(field)
        if val is not None and not isinstance(val, list):
            errors.append(f"`{field}` must be an array, got {type(val).__name__}")

    # --- Details must be object ---
    details = story.get("details")
    if details is not None and not isinstance(details, dict):
        errors.append(f"`details` must be an object, got {type(details).__name__}")

    # --- Gate exists in target PRD ---
    gate = story.get("gate", "")
    if gate and prd_name and prd_name != "(new PRD)":
        gate_ids = collect_gate_ids(prd_name)
        if gate_ids and gate not in gate_ids:
            errors.append(
                f"Gate `{gate}` does not exist in `{prd_name}.json` — "
                f"available gates: {sorted(gate_ids)}"
            )

    # --- Dependency validity ---
    all_ids = collect_all_story_ids()
    for dep in story.get("blockedBy", []):
        if dep not in all_ids and dep != sid:
            errors.append(f"`blockedBy` references non-existent story `{dep}`")

    # --- ID uniqueness ---
    if sid in all_ids:
        errors.append(
            f"Story ID `{sid}` already exists in an existing PRD file"
        )

    # --- blockedByIssues validation ---
    for issue_num in story.get("blockedByIssues", []):
        if not isinstance(issue_num, int) or issue_num <= 0:
            errors.append(
                f"`blockedByIssues` contains invalid value `{issue_num}` "
                f"(must be positive integer)"
            )

    # --- Source file and section validation ---
    for source in story.get("sources", []):
        if isinstance(source, str):
            source_file = source
            source_section = None
        elif isinstance(source, dict):
            source_file = source.get("file", "")
            source_section = source.get("section")
        else:
            errors.append(f"Invalid source format: `{source}`")
            continue

        if not source_file:
            continue

        resolved = REPO_ROOT / source_file
        if not resolved.is_file():
            errors.append(f"Source file does not exist: `{source_file}`")
            continue

        if source_section:
            headings = extract_headings(resolved)
            if source_section not in headings:
                errors.append(
                    f"Source section not found in `{source_file}`: "
                    f"`{source_section}`"
                )

    # --- Acceptance criteria quality (basic checks) ---
    vague_patterns = [
        (r"\bworks? correctly\b", "works correctly"),
        (r"\bhandles? edge cases?\b", "handles edge cases"),
        (r"\bis wired\b", "is wired"),
        (r"\basync/await works?\b", "async/await works"),
    ]
    for criterion in story.get("acceptanceCriteria", []):
        if not isinstance(criterion, str):
            errors.append(f"Acceptance criterion must be a string, got: `{criterion}`")
            continue
        for pattern, label in vague_patterns:
            if re.search(pattern, criterion, re.IGNORECASE):
                errors.append(
                    f"Vague acceptance criterion ('{label}'): `{criterion}` — "
                    f"must be machine-verifiable"
                )

    # --- Description quality ---
    desc = story.get("description", "")
    if isinstance(desc, str) and len(desc) < 20:
        errors.append(
            "Description is too short — must give an implementer enough "
            "context to work autonomously"
        )

    # --- Empty sources without explanation ---
    sources = story.get("sources", [])
    if isinstance(sources, list) and len(sources) == 0:
        if isinstance(desc, str) and "infer" not in desc.lower() and "context" not in desc.lower():
            errors.append(
                "Empty `sources` array — per standard, explain the origin in "
                "`description` when no external source exists"
            )

    return errors


def format_report(
    story: dict,
    errors: list[str],
    prd_name: str,
    action: str,
) -> str:
    """Format validation results as a markdown comment."""
    sid = story.get("id", "<missing>")
    title = story.get("title", "<untitled>")

    lines = ["## PRD Story Validation\n"]
    lines.append(f"**Story:** `{sid}` — {title}")
    lines.append(f"**PRD:** `{prd_name}.json`")
    lines.append(f"**Action:** {action}\n")

    if not errors:
        lines.append("**PASSED** — Story conforms to PRD standard.\n")
        lines.append(
            "This story can be added to the PRD file. "
            "Run `python3.12 scripts/validate-prd.py` after integration "
            "to verify gate registration and cross-PRD dependencies."
        )
    else:
        lines.append(f"**FAILED** — {len(errors)} validation error(s):\n")
        for err in errors:
            lines.append(f"- {err}")
        lines.append(
            "\nFix these issues and update the Story JSON field. "
            "Validation will re-run automatically."
        )

    lines.append(
        "\n---\n*Validated against "
        "[`.docs/standards/prd.md`](.docs/standards/prd.md) by "
        "[`scripts/validate-issue-story.py`](scripts/validate-issue-story.py)*"
    )

    return "\n".join(lines)


def try_parse_agent_json(body: str) -> tuple[dict | None, str, str]:
    """Try to parse body as direct agent JSON.

    Agent format:
      {"prd": "main", "action": "Add new story", "story": {...}}
    Or bare story:
      {"id": "SCP-042", "title": "...", ...}

    Returns (story, prd_name, action) or (None, "", "") if not agent JSON.
    """
    stripped = body.strip()
    if not stripped.startswith("{"):
        return None, "", ""

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return None, "", ""

    if not isinstance(data, dict):
        return None, "", ""

    # Wrapped format: {"prd": "...", "action": "...", "story": {...}}
    if "story" in data and isinstance(data["story"], dict):
        return (
            data["story"],
            data.get("prd", ""),
            data.get("action", "Add new story"),
        )

    # Bare story format: {"id": "SCP-042", ...}
    if "id" in data:
        # Infer PRD from story ID prefix if possible
        prd = data.pop("_prd", "")
        action = data.pop("_action", "Add new story")
        return data, prd, action

    return None, "", ""


def main() -> int:
    body = sys.stdin.read()
    if not body.strip():
        print("Error: empty issue body", file=sys.stderr)
        return 2

    # Try agent JSON format first (no ### headers needed)
    story, prd_name, action = try_parse_agent_json(body)

    if story is None:
        # Fall back to GitHub issue form markdown parsing
        fields = extract_form_fields(body)
        prd_name = extract_prd_file(fields)
        action = extract_action(fields)

        try:
            story = extract_story_json(fields)
        except json.JSONDecodeError as e:
            result = {
                "valid": False,
                "parse_error": f"Invalid JSON in Story JSON field: {e}",
            }
            print(json.dumps(result))
            return 2

    if story is None:
        result = {
            "valid": False,
            "parse_error": "Could not find Story JSON in issue body",
        }
        print(json.dumps(result))
        return 2

    # For removals, only check ID exists
    if action == "Remove story":
        sid = story.get("id", "")
        all_ids = collect_all_story_ids()
        if sid and sid not in all_ids:
            errors = [f"Story `{sid}` does not exist in any PRD file"]
        else:
            errors = []
    else:
        errors = validate_story(story, prd_name)

    report = format_report(story, errors, prd_name, action)

    # Output both structured JSON (for the action) and the report
    result = {
        "valid": len(errors) == 0,
        "story_id": story.get("id", "<missing>"),
        "prd_file": prd_name,
        "action": action,
        "error_count": len(errors),
        "errors": errors,
        "report": report,
    }
    print(json.dumps(result))
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
