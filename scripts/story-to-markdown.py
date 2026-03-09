#!/usr/bin/env python3
"""Convert a validated PRD story JSON to GitHub issue markdown.

Usage: python3 story-to-markdown.py <prd.json> <story-id>

Reads a PRD JSON file, finds the story by ID, and outputs markdown
suitable for a GitHub issue body. Nothing is truncated or dropped —
every field is included verbatim.
"""

import json
import sys
from pathlib import Path


def story_to_markdown(story: dict) -> str:
    """Convert a single PRD story dict to markdown."""
    lines = []

    # Header
    lines.append(f"# {story['id']}: {story['title']}")
    lines.append("")

    # Metadata table
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| **ID** | `{story['id']}` |")
    lines.append(f"| **Gate** | `{story['gate']}` |")
    lines.append(f"| **Priority** | {story['priority']} |")
    lines.append(f"| **Severity** | {story['severity']} |")
    lines.append(f"| **Status** | {story['status']} |")
    if story.get("blockedBy"):
        blocked = ", ".join(f"`{b}`" for b in story["blockedBy"])
        lines.append(f"| **Blocked By** | {blocked} |")
    lines.append("")

    # Description
    lines.append("## Description")
    lines.append("")
    lines.append(story["description"])
    lines.append("")

    # Details
    if story.get("details"):
        lines.append("## Details")
        lines.append("")
        lines.append(story["details"])
        lines.append("")

    # Files
    if story.get("files"):
        lines.append("## Files")
        lines.append("")
        for f in story["files"]:
            lines.append(f"- `{f}`")
        lines.append("")

    # Sources
    if story.get("sources"):
        lines.append("## Sources")
        lines.append("")
        for src in story["sources"]:
            lines.append(f"- **{src['file']}** — {src['section']}")
        lines.append("")

    # Acceptance Criteria
    lines.append("## Acceptance Criteria")
    lines.append("")
    for i, ac in enumerate(story["acceptanceCriteria"], 1):
        lines.append(f"{i}. {ac}")
    lines.append("")

    # Action Items
    if story.get("actionItems"):
        lines.append("## Action Items")
        lines.append("")
        for item in story["actionItems"]:
            lines.append(f"- [ ] {item}")
        lines.append("")

    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 story-to-markdown.py <prd.json> <story-id>", file=sys.stderr)
        sys.exit(1)

    prd_path = Path(sys.argv[1])
    story_id = sys.argv[2]

    with open(prd_path) as f:
        prd = json.load(f)

    for story in prd.get("stories", []):
        if story["id"] == story_id:
            print(story_to_markdown(story))
            return

    print(f"Story {story_id} not found in {prd_path}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
