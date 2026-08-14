---
name: adr049-pr7-prepA-crypto-methods
description: ADR-049 PR-7 Prep A (d6ecc0c84) security review — MlsCryptoSnapshot pub(crate) widening + 15 moved PerContextState crypto methods. PASS, zero findings.
metadata:
  type: project
---

# ADR-049 PR-7 Prep A — crypto-method move (commit d6ecc0c84) — PASS, ZERO FINDINGS

Branch `feat/adr049-pr7-prepA-crypto-methods`. Additive prep: 15 per-context crypto
methods added to `PerContextState` (`scp-runtime/src/context/actor/state.rs`), bodies
moved VERBATIM from `MlsCryptoProvider`; provider unchanged except visibility widening.

## Key finding assessed: `MlsCryptoSnapshot` widened private -> `pub(crate)` (struct + all 13 fields)
- `crypto/mls/provider.rs:106-177`. Struct carries PRIVATE KEY MATERIAL (local_sender_key,
  signer_bytes MLS keypair, sender_key_entries, wrapping_secret_key).
- **ACCEPTABLE + BOUNDED.** No new exfil surface: `mls/mod.rs:41` re-exports only
  `MlsCryptoProvider`, never the snapshot; `pub(crate)` can't be named outside scp-runtime
  (FFI/SDK see only the facade). Widening is within the crate that already owns the material.
- `pub(crate)` IS the minimum: `export_crypto_state` builds the snapshot with a cross-module
  STRUCT LITERAL (state.rs:2379); literal construction needs all fields visible; nearest
  common ancestor of provider + actor modules is crate root, so `pub(in crate)` == `pub(crate)`.
- A builder/accessor would be WORSE: still takes every secret as a param (same value exposure)
  AND diverges the two bodies, defeating the byte-identical-move guarantee that makes the later
  atomic cutover (SCP-CRYPTOMOVE-001) a pure delete.
- Precedent (EpochState/TtlState/AccessControlState/GovernanceState elevations) apt for the
  MECHANISM only — those are NOT key material, so not a security-equivalence argument. This one
  stands on its own guardrails.
- ALL guardrails survive: Clone still NOT derived (provider.rs:180); manual redacting Debug intact
  (all secret fields -> [REDACTED]/counts, provider.rs:186-218); `zeroize_secrets()` now pub(crate)
  but unchanged (provider.rs:233); `Drop for MlsCryptoSnapshot` backstop intact (provider.rs:255).

## Key-material handling in moved methods: FAITHFUL
- `export_crypto_state` (state.rs:2325) matches provider (provider.rs:2303) field-for-field:
  Zeroizing on signer_bytes vs early-?, mem::take into snapshot, terminal snapshot.zeroize_secrets()
  + Drop backstop. Actor variant is MORE fail-closed: `crypto.sender_key.clone().ok_or_else` (Option)
  where provider had non-optional field.
- Node-resident wrapping secret passed by reference: `wrapping_secret_key: &[u8;32]` forwarded
  straight into hpke_open (process_incoming_sender_key, state.rs:2216); `&[u8]` only copied into the
  transient self-zeroizing snapshot in export. NO secret stashed on self or any struct field.
- seal/open/distribute/rotate handle keys by reference; added tracing logs only metadata (DIDs,
  "no wrapping key" msg) — no key bytes / plaintext / snapshot logged.

## No new Debug-on-secret / no-Zeroize
- `git diff` on state.rs adds ZERO new structs and ZERO new Debug derives/impls — only impl methods
  + #[cfg(test)]. No secret struct gained a naive Debug.

## Observation (non-blocking)
- `pub(crate)` now lets ANY scp-runtime code name snapshot.wrapping_secret_key etc. (was provider-only).
  Theoretical only — snapshot is never a field on a long-lived struct; instances are transient in
  export/restore and zeroized before drop. Should collapse when SCP-CRYPTOMOVE-001 deletes the provider
  twin. Track that the deletion lands so this doesn't ossify.

GOTCHA: Bash cwd resets between calls; worktree path is
`/Users/alec/Developer/limn/scp/.claude/worktrees/agent-ae83a40640c494a38`.
