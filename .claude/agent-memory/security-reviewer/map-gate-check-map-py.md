# Codebase-map gate (scripts/check-map.py + hooks) — fork-PR threat model

Reviewed 2026-07-03 on branch worktree-codebase-map (uncommitted MAP.md system).
Fork-PR attacker controls MAP.md content, file/dir names, sizes, committed symlinks.
Gate runs full-mode on fork-PR CI (`map-check` job, read-only token).

## Findings
- MEDIUM DoS (unfixed): no per-node ANCHOR-COUNT ceiling. Each `relpath#symbol`
  anchor triggers read_text of target up to MAX_ANCHOR_TARGET_BYTES=10MB +
  substring scan, no caching/budget. MAP.md size ceiling (1MB) bounds anchor
  count (~131k) but NOT work: 1MB map -> 131k anchors x 10MB = ~1.3TB scan.
  DEMONSTRATED: 100k anchors (800KB map, under ceiling) x 10MB target = 130s for
  ONE area. Attacker adds dozens of crates/* subdirs -> compounds past job timeout.
  Fix: cap anchors/node (real nodes have <~20) OR cache target reads OR global budget.
- MEDIUM (unfixed): MAP.md itself is NOT symlink-refused. check_area uses
  is_file()/read_text() which FOLLOW symlinks (line ~403/417). A committed MAP.md
  symlink -> arbitrary out-of-tree file read; unrecognized frontmatter lines echo
  target content ({stripped!r}) into fork-readable CI logs. Constraint: target must
  start with `---` on line 1 (else early-return, no echo). DEMONSTRATED both the
  read and the content echo. Inconsistent with the careful anchor symlink refusal
  (lines 308-312). Fix: `if map_path.is_symlink(): reject` before reading.
- OBS: derived areas refuse symlinked dirs (mapped_areas 146-150) but FIXED
  top-level + root areas use is_dir() which follows symlinks (line 152). Minor.

## Verified SOLID (do not re-flag)
- INLINE_COMMENT_RE `(?<=\s)#.*$` fixed-width lookbehind — linear (prior quadratic
  `\s+#` fixed). STAMP_ONLY/SCALAR/LIST/VERIFIED regexes all linear (measured).
- Anchor confinement: rejects abs/`..`, resolve()+relative_to(area) confines,
  refuses symlinked final+intermediate components. Solid file-oracle defense.
- --stamp-audit / --diff argv: area names always `crates/`|`bindings/`-prefixed and
  placed after `--` separator -> no git option injection. `base` interpolated before
  `--` but is reviewer/CI-supplied (CI binds github.base_ref via env, prefixed
  origin/) not repo-controlled. Safe; would break only if base wired to attacker input.
- stop-map-freshness.sh: json.dumps + `[^A-Za-z0-9._/-]->?` filter + backtick-wrap +
  128-char + 20-name cap. Structural + NL-instruction injection both closed. "$areas"
  passed as argv (no shell eval).
- git file listing uses `-z` NUL (immune to C-quoted paths); --no-renames flags both
  move endpoints.
- Non-issues: TOCTOU stat/read (static CI checkout, no racer); sparse files (git
  checkouts dense; st_size = logical size, caught by ceiling); hardlinks (git can't
  commit); case tricks (ubuntu CI case-sensitive).
