# Class-S fail-closed gate — strip_code soundness (check-class-s-fail-closed.sh)

`scan_file`'s awk `strip_code(s)` (lines ~510-639) is a per-line lexical
stripper that carries multi-line state across physical lines via awk globals.
It carries `in_block` (block comment) and `in_raw_string`+`raw_hash` (raw
string) — but the brace-depth model that closes a fn body trusts its residue.
A leaked brace closes the fn early (deflation → mutation after it hidden) OR
inflates depth (leaked `{` → fn never closes → EVERY later fn in the file
swallowed, SCANNED count drops). Both directions are exploitable.

## CONFIRMED CLASS-A (ordinary rustc-accepted, cargo-fmt-stable Rust) — 2 root causes

### CLASS-A #1: NESTED BLOCK COMMENTS not modeled
strip_code runs a block comment to the FIRST `*/` (lines 531-539 carry, 550-560
open) — does NOT model Rust's comment nesting. Real-world trigger: commenting
out a chunk of code that itself contains a `/* */` block comment AND braces
(e.g. `fn legacy() { /* ... */ }`). After the INNER `*/`, the `}` of the
commented-out block leaks as code.
- Deflation fixture: `/* outer /* inner */ } ... */` before a best-effort mutation → NO-HIT.
- Inflation fixture: `/* x /* y */ { still comment */` in fn_a hides fn_b entirely (SCANNED=1).
- rustc exit 0, rustfmt --check exit 0. Idiomatic (nested comments exist precisely for this).

### CLASS-A #2: ORDINARY-STRING line-continuation state not carried
A `\` at physical end-of-line inside an ordinary `"..."` string is a Rust
line-continuation; the string continues on the next physical line. strip_code's
string loop (586-596) runs `k` to end-of-THIS-line, the trailing `\` does
`k+=2` past EOL, loop exits with string unterminated — but NO `in_string`
global is set, so the next physical line is scanned as FRESH CODE. Any brace on
the continuation line leaks.
- Deflation fixture: wrapped error message ending in `}` → NO-HIT (residue L3 close=1).
- Inflation fixture: continuation line ending in `{` hides the next fn entirely.
- rustc exit 0, rustfmt --check exit 0. Idiomatic (wrapping long error/SQL/format strings).
- NOTE: input-dependent — if the continuation line re-opens/closes a balancing
  string the brace can re-land inside a re-detected literal (false negative on
  the bypass). But the lone-brace case is deterministic and ordinary.

## CONFIRMED HANDLED CORRECTLY (all HIT)
byte char b'}' b'{'; unicode esc '\u{7d}'; '\\' '\''; `///` `//!` `/** */`
`/*! */` doc comments; r#"..}"# / r##".."# hash edges / r"..}" / br#"..}"#;
multi-line raw string; multi-line ORDINARY block comment w/ brace (in_block
carry); escaped-quote string `"x\"}"`; byte-string escaped quote `b"\"}"`;
plain char `'{' '}'`; lifetimes `<'a>` `&'a` `'static` `'_`; HRTB `for<'a>`;
loop labels `'outer:`; char-containing-doublequote `'"'`; lifetime-then-string.

## Harness (reusable)
Extract defs-only lib: `sed -n '1,1778p' script > gatelib.sh` (stops before the
exec block that runs self_test + exits). `source` it, then
`FC_FUNCS="" scan_file <abs-path>`; grep `^HIT` = detected, none = HIDDEN.
Residue dumper: copy strip_code + `BEGIN{SQ=sprintf("%c",39)}` + per-line
`gsub` open/close printer. Marker used: `xctx_caller_reservations.insert(` +
`persist_state_best_effort()` body = best-effort mutation (MUST HIT).
Control: same with `persist_state_fail_closed()` = MUST NOT HIT.

## Fix direction (for the human's batch)
Both are missing multi-line lexer state. (1) Track block-comment NESTING DEPTH
(increment on `/*`, decrement on `*/`) instead of a boolean in_block. (2) Add an
`in_string` carry: if an ordinary/byte string's scan ends with the line still
open because of a trailing `\` (odd backslash run at EOL), set in_string and
resume on the next line honoring escapes. Until fixed, both are live gate
bypasses on legal cargo-fmt-clean code.
