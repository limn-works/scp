# Class-S fail-closed gate — string-strip unsoundness (escaped quotes + raw strings)

File: `scripts/check-class-s-fail-closed.sh`, awk `scan_file`, lines ~544-558 (strip), ~574-575 + ~703 (brace depth), ~696 (terminator reset).

## Root flaw
String stripping uses `gsub(/"[^"]*"/, "", line)` — a naive quote-pair matcher that CANNOT
handle Rust escaped quotes (`"a\"b"`) or raw strings (`r#"..."#`). The escaped/early `"`
terminates the match early, leaving a RESIDUE of in-string characters in `line`.

If that residue contains `}` (or `{`), the brace counter `closes=gsub(/}/...)` /
`opens=gsub(/{/...)` then `depth += opens-closes` reads it as a REAL brace. A stray `}`
prematurely closes the function in the scanner's depth model (`depth <= fn_floor`), so the
function is considered ENDED at the poison line — every Class-S mutation after it is invisible
and `fn_mutates`/`fn_besteffort` never get set. A stray `{` inflates depth so the fn never
appears to close (no FNDEF emitted).

## Minimal evasion (LEGAL Rust, survives cargo fmt)
```rust
pub async fn evil() {
    let label = "oops\"}";                                  // escaped-quote string w/ }
    state.xctx_caller_reservations.insert(saga_id, record); // Class-S, single line
    persist_state_best_effort(state, deps, ctx);            // NON fail-closed
}
```
Real gate => NO HIT. Control with plain `"oops}"` (no `\"`) => HIT. The ONLY difference is `\"`.
Raw-string variant `r#"has " and } inside"#` also evades (the inner `"` ends `[^"]*` early).

## Scope / severity
- General bypass of the gate's PRIMARY guarantee. Works for EVERY marker tested: insert,
  suspend_all, membership.remove_member, role_state.ceiling= (governance leaf — no GOVHIT either).
- Poison may sit anywhere from fn-open brace through the mutation's own logical line, EXCEPT
  strictly after it (marker fires before the depth reset on a later line).
- NOT carry-forward-specific, but the wave-10 carry-forward work touches exactly this
  strip/buffer/brace machinery; fixtures 18/19/20 exercise these lines.

## Fix direction
Make string stripping escape-aware (consume `\\.` inside string scan) AND handle raw strings
(`r#*"..."#*` with matching hash count) BEFORE brace/paren/terminator counting. Until then the
brace-depth function model is unsound on any body containing such a literal.

## Harness
`/tmp/xctx_bh/runscan.sh <file>` sources lines 321-755 of the gate (var defs + scan_file) and
runs `FC_FUNCS="" scan_file`. Reproduces real gate output (validated vs fixtures 18/20).
