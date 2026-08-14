# ADR-056 keying-gate awk lexer (scripts/check-context-id-keying.sh, branch feat/123)

The test-scope tracker strips literals with single-line regexes then counts braces.
THREE proven soundness holes in the "code-only" view (all verified end-to-end against
the gate in a synthetic temp tree):

1. **Char-literal regex eats a real brace between a lifetime and a char literal.**
   `'([^'\\]|\\.)*'` pairs a Rust lifetime/turbofish-lifetime quote (`'a`, `<'a>`)
   with the opening quote of a later char literal on the same line, deleting any
   `{`/`}` in the span. Idiomatic divergent lines:
   - `let m = HashMap::<&'a, char>::new(); m.insert(k, '}');` true net 0 → stripped −1
   - `let _ = foo::<'a>(); } let c = '!';` true net −1 → stripped 0 (FAIL-OPEN)
   - `fn z<'a>(c: char) { assert_eq!(c, '}'); }` true net 0 → stripped −2 (false-pos)
   Net-too-negative → window closes early → legit test call wrongly DENIED (CI break).
   Net-too-positive / eaten `}` on the mod-close line → window stays open → production
   raw-primitive call SILENTLY EXEMPTED (fail-OPEN — the exact regression class the
   gate exists to catch).

2. **Block comments `/* … */` are NOT stripped (documented as "safe" — wrong).**
   A brace inside a trailing `/* … */` on a brace-COUNTING line corrupts depth.
   `} /* comment with a stray { brace */` true net −1 → stripped 0. If this is the
   `#[cfg(test)] mod` closing line, the window never closes → production call after
   it is silently exempted (FAIL-OPEN, gate PASSES). Header's justification only
   considers attribute/keying lines, not brace-counting lines.

3. **Multi-line / raw strings with inner quotes defeat the single-line string regex**
   (`r#"…"#`, `"…\n…"`). Single-line `r#"…"#` mostly survives by accident (inner
   `"…"` matches), but inner-quote raw strings and line-spanning strings can shift
   depth either way. Lower-severity than 1/2 (harder to trigger reliably).

LATENT today: no lifetime+char or `/* { */`-on-close-line collision currently exists
in the 3 scanned roots, so the live gate passes correctly. But this is a tripwire
meant to survive future code; the holes WILL fire as test code evolves.

Raw-primitive CALL detection runs on the ORIGINAL line, so these never hide an
*addition* of a raw call — only mis-track whether an existing call is test-scoped.

`//` line comments ARE stripped (safe). Attribute stacking + same-line item arm
correctly. The 4 FFI reroutes + node.rs + context_id_to_bytes (64-lowercase-hex
decode else SHA256) + mod.rs doc (no fence/intra-doc link) are all CORRECT.

Root cause: a regex-based pseudo-lexer cannot tokenize Rust. The header itself
points at the real fix — a `ContextDigest` newtype only the chokepoint can mint,
making evasion a compile error. Until then, the depth tracker is unsound.
