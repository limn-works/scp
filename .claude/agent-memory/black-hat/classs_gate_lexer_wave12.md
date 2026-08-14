# Class-S fail-closed gate lexer (check-class-s-fail-closed.sh) — wave-12 convergence

File: `scripts/check-class-s-fail-closed.sh`. Pure awk lexer `strip_code` strips
comment/literal CONTENT before the brace-depth fn-body model + marker match. A leaked
brace closes a fn early (deflation → later Class-S mutations invisible) or never balances
(inflation → swallows every later fn). Soundness hole = ordinary rustc/fmt-clean Rust that
leaks a brace so a best-effort Class-S mutation produces NO HIT.

## Prior state (2 class-A holes found earlier, now FIXED)
- nested block comments (boolean → now `block_depth` counter + `scan_block_comment`)
- multi-line strings (now `in_string` carry; raw via `in_raw_string`+`raw_hash`)

## Wave-12 NEW state attacked (commit a756b0280): block_depth, scan_block_comment, in_string carry
Drove the REAL `scan_file` (sourced lib, instrumented to dump in_string/block_depth/in_raw
per line) against 25+ scratch fixtures. ALL SOUND — every probe HIT (or victim-HIT for
inflation), controls clean, live gate PASSES end-to-end.

Probes that resisted (each = ordinary Rust, real scan_file, traced state):
- `/*`,`*/` INSIDE string/char never touch block_depth (resumers run before comment logic, only scan `\`/`"`/`#`)
- `"`/`'` INSIDE block comment never start string/char (block_depth carry inspects only `/*`/`*/`)
- div/deref `a / *b`, `c/ *d`, `*ptr=`, `x*y/z` never form comment-open (needs adjacent `/*`)
- BACKSLASH PARITY both directions, inline scanner AND resumer (k+=2/i+=2 pair-consume):
  - even-bs `\\"` at EOL → string CLOSED (in_string=0), marker next line HIT (the false-neg-other-way: carry does NOT wrongly keep eating)
  - odd-bs `\\\"` → escaped quote, continues, in-string `}` suppressed, later marker HIT
  - dangling EOL `\` → i past n, in_string stays 1, correct Rust continuation
- nested comment ending MID-LINE with marker on SAME physical line → HIT (off-by-one clean: `*/state` → one space placeholder, no char dropped/doubled; offset math `m+(c2t-1)+2` correct)
- INFLATION (most dangerous): leaked `{` from nested-comment OR carried-string must NOT swallow later fn — both defeated, victim fn scanned independently → HIT

## Harness (reusable)
`awk 'NR<2032' script > lib.sh` (cuts before executable tail), `source lib.sh; FC_FUNCS="" scan_file <ABS_PATH>`.
NOTE: sourced lib does `cd REPO_ROOT` → pass ABSOLUTE paths to scan_file. Instrument by
injecting a stderr printf after `line = strip_code(raw)`.

VERDICT: wave-12 new lexer state is SOUND on the new surface. Convergence confirmed — no
new class-A hole. This is review-pass evidence the approach has converged (per CLAUDE.md
§"non-convergent enforcement" — 3+ passes surfacing new spellings = reframe; here the last
two waves closed the genuine holes and this pass found none).
