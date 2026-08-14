---
name: ci-aggregation-gate-pattern
description: SCP ci.yml uses a single roll-up job as the required status; new CI jobs must be added to its needs+results or they are non-blocking
metadata:
  type: project
---

`.github/workflows/ci.yml` ends with an aggregation job ("Check job results" step)
that fans in every real job via a `needs:` list AND a parallel `results=( ... )`
bash array of `${{ needs.<job>.result }}`. The loop fails only on `failure`/`cancelled`
(so `skipped` == pass — conditional/path-filtered jobs are safely listed there).

**Why:** This roll-up is the repo's canonical single required status for branch
protection. Individual jobs are gated by `if: needs.changes.outputs.<lang> == 'true'`
path filters and are NOT independently required.

**How to apply:** When a PR ADDS a new CI job, verify it is wired into BOTH the
aggregation `needs:` list and the `results` array. If it's only defined, it runs and
shows a check mark on the PR but does NOT block merge — a gate that doesn't gate.
Cross-check any sibling job (e.g. `typescript-check`) for the correct two-place wiring.

Seen: PR #2183 (feat/scp-ts-wasm-packaging) added `typescript-wasm-check` but omitted
it from the aggregation gate — flagged as the sole remaining finding on the double-zero pass.
