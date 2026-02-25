---
name: prd
description: Generate a structured PRD from spec files, planning docs, or design sketches. Decomposes documents into atomic stories grouped into prioritized gates with dependency tracking.
argument-hint: "<files...> [append] [prefix <PREFIX>] [max <#>]"
disable-model-invocation: false
allowed-tools: Read, Write, Edit, Glob, Grep, Bash, Task
---

# /prd

Generates a PRD (`.loom/prd.json`) from `$ARGUMENTS`. Any source is valid, remote or local. Some examples: artifacts like specs, docs, architecture, sketches, ADRs, planning sessions; a URL; an external source available via MCP or cli like Linear, GitHub, Sentry, or Figma; or a plain text prompt.

To execute this skill, use `.claude/skills/prd/exec.md`.
