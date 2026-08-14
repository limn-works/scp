# check-map.py (MAP.md structural gate) — bug findings

Reviewed uncommitted `worktree-codebase-map` branch (scripts/check-map.py + hooks + CI).
50-test suite passes; full mode passes on the 34 real nodes.

## Confirmed defects (demonstrated with fixtures)
1. **Section scanner ignores fenced code blocks (MEDIUM).** `check_sections`
   (check-map.py ~L333) scans body lines for `line.startswith("## ")` with no
   awareness of ``` fences. A fenced markdown example containing `## Purpose`
   etc. → (a) false-FAIL "duplicated/out-of-order section" on a legit node that
   shows a node-format example; (b) false-PASS: a node missing a real section
   passes if that title appears only inside a fence (map lies). Latent now (no
   real node trips it) but realistic — the standard itself uses fenced examples.
   Fix: track fence state (toggle on lines matching ^```|^~~~) and skip fenced
   lines when collecting `found`.
2. **Rename detection collapses cross-area renames → source area escapes
   freshness (MEDIUM).** `collect_changed_files` uses `git diff --name-only`
   (rename detection default ON). `git mv crates/alpha/x crates/beta/x` reports
   ONLY `crates/beta/x`; source area `crates/alpha` is NOT flagged delinquent,
   so alpha/MAP.md can silently go stale on a move. Affects `--staged`
   (pre-commit), `--diff base...HEAD`, and `--status-areas`. Fix: add
   `--no-renames` to all git diff invocations (reports old+new as delete+add).

## Verified SOUND (no bug)
- Symlink confinement (resolve()+relative_to) correctly rejects direct,
  in-area, and intermediate-symlink-dir escapes.
- Section ORDER check does NOT false-positive on interleaved non-required
  `##` sections (required_seen filtered before compare).
- Freshness delinquency logic, ownership longest-prefix, root-area exemption,
  --status-areas fail-open all correct.
- BOM-prefixed MAP.md fails CLOSED (rejected) — strictness edge, not a hole.
