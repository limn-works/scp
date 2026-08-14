---
name: review-class-s-gate-wave12-lexer
description: Class-S fail-closed gate wave-12 lexer hardening (nested block comments + multi-line ordinary/byte strings) — SOUND STRENGTHENING, CLEAN
metadata:
  type: project
---

# check-class-s-fail-closed.sh wave-12 lexer (commit a756b0280, worktree xctx-saga) — CLEAN

Audited NARROW: only `git log -p -1 -- scripts/check-class-s-fail-closed.sh`. Verdict: pure STRENGTHENING, no weakening / no new false-negative.

**What changed:** `strip_code` (the awk brace-depth body model) gained two multi-line carries:
- `block_depth` COUNTER replaces boolean `in_block` + new `scan_block_comment(s,bi)` helper — Rust block comments NEST (`/* a /* b */ c */` ends at SECOND `*/`); boolean closed one `*/` early, leaking trailing braces into code residue.
- `in_string` carry for ordinary/byte strings UNTERMINATED at EOL (Rust normal string spans lines via trailing `\` continuation OR bare newline); prior scan treated unterminated-at-EOL as closed, leaking a later-line `}`/`{`.

**Soundness verified:**
1. Pure strengthening — only ADDS detection (closes nested-comment + multi-line-string brace-leak bypasses). No marker / GOVHIT / GOVFN / govleaf allowlist / fixture 1-25 touched. Per-file `BEGIN` resets all 4 state vars (block_depth/in_raw_string/raw_hash/in_string) — no cross-file bleed; `scan_file` runs awk once per file.
2. No over-strip false-negative. `scan_block_comment` while-loop: each iter consumes a `*/` and advances `m`≥2 (strictly increasing → terminates); returns 0 ONLY when line genuinely has no close (correct carry). `in_string` continuation clears on first unescaped `"`; stays set ONLY when line has no closing quote. Neither can stick >0/set over a line that actually terminates the literal → cannot hide a real marker/brace in CODE.
3. Fixtures 26-31 lock both fixes: 26 nested-comment deflation MUST HIT, 27 nested-comment inflation victim MUST HIT, 28 `\`-cont string deflation MUST HIT, 29 bare-newline string deflation MUST HIT, 30 string inflation victim MUST HIT, 31 over-strip guard (fail-closed fn w/ nested comment + multi-line string) MUST NOT HIT.

**Empirical proof (real tree crates/scp-runtime/src/context):**
- `bash scripts/check-class-s-fail-closed.sh` → PASS exit 0.
- Patched BOTH prev (HEAD~1) and new scripts to dump internal record stream; diff = BYTE-IDENTICAL: 871 FNDEF, 28 FC, 30 GOVFN, 61 SCANNED, 0 HIT/GOVHIT in both. No real function newly flagged, none newly hidden.
