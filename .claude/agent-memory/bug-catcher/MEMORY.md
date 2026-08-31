# Bug Catcher Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

## Index — one line per entry, detail lives in the linked file

- [Per-review findings archive (Feb 2026 – Jun 2026)](review_history.md) — every dated review's findings verbatim; search it before re-reporting a known bug.
- [UniFFI Swift checksum staleness](uniffi_checksum_staleness.md) — hand-edited throwing sig + stale checksum int → Swift SDK fatalError on init; detect by regen+diff (#1543).
- [Custody vocabulary PR #2415](custody_vocabulary_pr2415.md) — derived Deserialize re-opens a privacy invariant; one shared helper, three bridge error codes; SDK docs name the wrong bridge's code.
- [SCP-294 custody name means one thing](scp294_custody_name_one_thing.md)
- [Event-log unification phase 2](eventlog_unification_phase2.md)
- [Phase-4 facade delete](phase4-facade-delete.md)
- [SCP-1717 pre-rotation fix](scp-1717-pre-rotation-fix.md) · [its rotation/migration re-review](scp-1717-rotation-migration-review.md)
- [Storage foundation / ADR-049](storage_foundation_adr049.md)

## The recurring patterns — check these first on any review

1. **TOCTOU across an async lock boundary** (read-check-drop-write-act). The #1 pattern here, 8+ instances. Fix: one write lock for check-and-mutate, or `entry()`.
2. **A lock guard held across `.await`** — DashMap `Ref`, `RwLock` guard, tokio `Mutex`. Clone the Arc, drop the guard, then await.
3. **Bulk change missing call sites.** A type swap, a rename, a serde-format change, or a new parameter gets applied to the main path and misses the migration chain, a second bridge, or a test helper. Grep every call site of the old name before believing a conversion is complete.
4. **FFI bridges passing `None`/default for a newly added parameter** rather than wiring it through. Also `let _ = result;` on a fallible cleanup, which produces split-brain state.
5. **Types and logic shipped without call-site wiring** — a verifier written but never called, a defense field defined but never included in the hash, a doc listing behavior the function body does not implement.
6. **Re-implementations drift from the reference** — WASM vs scp-core, one bridge vs the other three, an SDK doc vs the bridge it actually wraps. Verify parity per target, never by analogy.
7. **A test that passes resolved values bypasses the transformation it claims to test**, and `let _ = function_name;` calls nothing. Read what the test actually invokes.
8. **kotlinx.serialization `?.jsonObject` is not a safe accessor** for a possibly-primitive value; check `is JsonObject` first.

## Key files

- `/Users/alec/Developer/limn/scp/.docs/specs/` — protocol specs (`00-open-questions.md` holds open and resolved design decisions).
- `/Users/alec/Developer/limn/scp/.docs/architecture.md` — build document. `/Users/alec/Developer/limn/scp/.docs/sketch.md` — API surfaces.
- `/Users/alec/Developer/limn/scp/.docs/adrs/` — ADRs by phase.
- `/Users/alec/Developer/limn/scp/.docs/standards/sdk-capability-matrix.json` — the operation × SDK matrix; empty cells are findings.
