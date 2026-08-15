---
name: project-track-e-kotlin-stub-scaffold
description: Track E Kotlin stub-scaffold deletion — the 56 broken matrix cells are ALL exported by the UniFFI bridge, so "capability does not exist" exemptions would be false; deletion landed at b7a7846aa, matrix treatment escalated
metadata:
  type: project
---

Branch `refactor/track-e-remove-kotlin-stub-scaffold` off `925f18c6f`. Commit
`b7a7846aa` deletes the Kotlin `bridge/CoroutineBridge.kt` scaffold (2,804
lines, zero production implementors of `NativeBindings`) and the 11 domain
wrappers stacked on it.

**The load-bearing finding — the deletion is right, the prescribed matrix
treatment was not.** Deleting the scaffold breaks exactly **56** Kotlin cells
in `.docs/standards/sdk-capability-matrix.json`. Every one of those 56 is
**exported by the UniFFI bridge and generated into
`works/limn/scp/internal/uniffi/scp/scp.kt`** — verified by grepping the
generated `uniffi_scp_ffi_uniffi_checksum_{func,method}_*` symbols. Zero are
genuine capability absences. Swift, the sibling UniFFI SDK, ships real
wrappers over the same handles (`Server.swift` over `NodeHandle`/`RelayHandle`).
So an exemption reading "the capability does not exist" would put 56 false
statements into an enforcement file.

**Why:** the task prompt prescribed flipping the cells to `kotlin: false` with
"no Kotlin wrapper ships … the capability was never present", plus an
Android-backgrounding platform rationale for the Server rows. Both are
contradicted by evidence: `scp-kt` is a plain `kotlin("jvm")` library (the
Android code lives in the separate `scp-kt-android` module), and the bridge
exports node/relay lifecycle. Per CLAUDE.md's scar-tissue rule this is an
inherited premise that does not survive tracing.

**How to apply:** the honest resolutions are (a) write the thin `SCP`
forwarders over the already-generated `uniffi.scp.*` surface so the cells stay
truthfully `true` — the no-deferral tenet's answer — or (b) flip to `false`
with wording that states the real gap (bridge exports it; no idiomatic wrapper
ships), which is the phrasing the matrix already uses for `Identity/rotate_key`.
Do not write the platform-exclusion story.

**Traps for whoever continues:**
- `check-sdk-coverage.py` scans `works/limn/scp/**` including the *generated*
  `internal/uniffi/` tree, but CI runs it on a fresh checkout with no
  generation. Move that tree aside before running it locally or results diverge.
- `scripts/generate-uniffi-kotlin.sh` hardcodes `$REPO_ROOT/target/debug`, so
  `CARGO_TARGET_DIR` must be `<worktree>/target`, not a custom dir.
- `crates/scp-testing/tests/integration/sdk_wrapper.rs` `include_str!`s five of
  the deleted Kotlin files, so the tree does not build until `kt_all()` is
  repointed. Its Kotlin corpus contained *only* scaffold files — never `Scp.kt`.
- 3 pre-existing `:scp-kt:test` failures at `925f18c6f` (2 `PersistenceTest`,
  1 `JoinFromWelcomeTest`), confirmed against a clean baseline worktree.

See [[feedback-worktree-absolute-path]].
