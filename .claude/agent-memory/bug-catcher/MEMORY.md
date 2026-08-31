# Bug Catcher Memory

Index only — one line per entry. Put detail in a topic file and link it here.

Working notes:
- A bash call resets cwd between invocations, so write every path absolute.
- Report absolute paths in the final message, and quote a snippet only when its
  exact text is load-bearing.
- No emojis. No colon before a tool call.

## Topic files

- [Recurring bug shapes](recurring-patterns.md) — the 11 shapes that keep turning up, ranked, each with the grep that finds it. Read this first.
- [Per-review findings, Feb-Jun 2026](historical-findings-2026.md) — the instance archive: PR #127, transport expansion, #310-#357, Phase 5, event-log Phase 2, enforcement gates.
- [UniFFI Swift checksum staleness](uniffi_checksum_staleness.md) — a hand-edited throwing signature plus a stale checksum makes the Swift SDK `fatalError` on init; detect by regenerating and diffing. Found in 8bcd520c2 (#1543).
- [FileKeyCustody v0x02 header](filekeycustody_v2_header.md) — the verified 85-byte layout, plus two open defects: write paths re-seal the HMAC over bytes they never verified, and a crash mid-create leaves a permanent zero-byte file.

## Repo landmarks

- `/Users/alec/Developer/limn/scp/.docs/specs/` — protocol specs.
- `/Users/alec/Developer/limn/scp/.docs/specs/00-open-questions.md` — open and resolved design decisions.
- `/Users/alec/Developer/limn/scp/.docs/architecture.md` — build document.
- `/Users/alec/Developer/limn/scp/.docs/sketch.md` — API surfaces.
- `/Users/alec/Developer/limn/scp/.docs/adrs/` — ADRs by phase.

## Standing environment facts

- System `awk` is mawk 1.3.4, not gawk. Gate scripts must avoid gawk extensions.
- `cargo test -p scp-ffi` and `cargo test --workspace` need
  `DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))")`.
- The workspace denies `unwrap_used`, `expect_used`, `panic`, `todo`,
  `unimplemented`, `too_many_lines`, `too_many_arguments`, and
  `await_holding_lock`; clippy pedantic and nursery are warnings, and CI runs
  `-D warnings`, so a pedantic lint is a build failure.
