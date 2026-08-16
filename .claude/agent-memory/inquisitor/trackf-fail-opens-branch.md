---
name: trackf-fail-opens-branch
description: Interrogation of branch fix/trackf-remaining-fail-opens — five capability-selection fixes landed with zero artifact edits; SCP-CAPINJECT-010 already governed the relay work; napi returns Debug-formatted governance results
metadata:
  type: project
---

Branch `fix/trackf-remaining-fail-opens` (5 commits on `origin/main` aeba9c24f, 2026-08-15) changed
20 files across Rust, Python, Swift, TypeScript, and Kotlin, and edited zero files under `.docs/`.

**Why this matters:** each of the five commits resolved a conflict between shipped code and a
human-authored acceptance criterion by editing the code and recording the reasoning in a Rust
doc comment. The repo's artifact-flow invariant (CLAUDE.md, "plans → specs → ADRs → stories →
code") requires the artifact edit first.

**How to apply:** before judging a capability-selection fix in this repo, check these three
things, because a later branch will hit them again.

1. **A story may already govern the work.** `.docs/prds/adr062-capability-injection.json`
   carries SCP-CAPINJECT-000/001/006/009/010/011, every one `status: "pending"` while much of
   their scope has already landed on `main` (e.g. `impl Default for BlobStorageBackend` is
   already deleted, which is SCP-CAPINJECT-010's first acceptance criterion). The PRD is stale
   against `main`. Search this PRD before concluding that only a spec governs a
   capability-selection change.
2. **Issue #342 (relay blob storage backends) is human-authored.** `alecmarcus` wrote its
   acceptance criterion 2 verbatim as "`sqlite` (default when unset)", citing "§17.6 — SQLite as
   universal default storage". §17.6 and §17.17 of `.docs/specs/17-persistence-and-storage.md`
   later replaced that default with SCP-CAPSEL-8000 (selection mandatory, no default). The
   issue's premise expired; the issue was never annotated.
3. **"Track A/B4/F" names no artifact.** `grep -r "Track B4" .docs/` returns nothing. The track
   taxonomy lives only in pull-request titles.

**Standing code facts this interrogation established** (verify before relying on them):
- `crates/scp-ffi/napi/src/context.rs:3482` returns `Ok(format!("{result:?}"))` for
  `GovernanceActionResult`, so the 9 payload-carrying variants of the 29 emit a Debug string no
  SDK enum matches. PyO3 and UniFFI each use an exhaustive 29-arm `match` on bare variant names.
- No gate anywhere enforces parity between a Rust enum and its hand-duplicated SDK copies.
  `scripts/check-protocol-sync.py` checks for `async fn` in `scp-protocol`, not enum sync.
- The `ViolationStore` trait (`crates/scp-protocol/src/trust/custody_violation.rs:661`) has
  exactly one implementation and zero consumers in the workspace.

See [[scp-out-046-streaming-saga-seal-fsm]] and [[adr057-reciprocal-announce-mesh]] for the
other interrogations in this ledger.
