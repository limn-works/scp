---
name: ADR-049 commit 12 (actor-per-context refactor) review
description: Security review of the manager/ deletion + Supervisor::with_providers + helper hoist commit at 7c3137565 on origin/refactor/actor-per-context
type: project
---

# ADR-049 commit 12 — security review (HEAD `7c3137565`)

## Architecture state (post-commit-12)
- `crates/scp-runtime/src/context/manager/` deleted; `Supervisor` is the single owner of providers + state.
- All helpers in `*_helpers.rs` and `*_logic.rs` take `&Supervisor` and are `pub` (not `pub(crate)`).
- Per-context state is `Arc<DashMap<String, Arc<Mutex<PerContextState>>>>` on the supervisor.
- Helper-side persistence + saga journal are wired via `Supervisor::with_providers(...)` from FFI.
- `OwnedIdentityDid` exists at `crates/scp-runtime/src/context/supervisor/identity_capability.rs` and is `pub(super)`. Production callers haven't been wired (issue_for_actor only used in tests). Sole-minter enforcement is compiler-only (type system + `deny(unsafe_code)` + `deny(non_local_definitions)`) — the source-text CI scanner that existed at commit 12 was later dropped (see CI gates section below).
- `ContextActor::run()` is still skeleton dispatch — production messaging/governance still flows through `Supervisor::dispatch_*` + helper functions, NOT through actor mailbox state ownership. Watchdog/panic recovery not yet in commit 12.

## Findings recorded

### P0
- None directly introduced by commit 12. Several P1 issues escalate close to P0 due to public surface area widening.

### P1 — public unchecked governance API
- `Supervisor::propose_governance_action` (pub, supervisor.rs:2431) and `Supervisor::vote_on_proposal` (pub, supervisor.rs:2484) call the unchecked-capability variants. Any holder of `Arc<Supervisor>` (FFI bridges, downstream crates) can propose/vote as any DID without the GovernancePropose / GovernanceVote capability check.
- `GovernanceCommand::ProposeGovernanceAction` (pub, actor/commands.rs:732) likewise dispatches the unchecked path through `dispatch_governance_command`. Documented as "the governance engine enforces eligibility internally" but the engine only checks signer-set/role membership, not ceiling-attenuated capability.
- Fix: gate the unchecked variants behind `pub(crate)` or rename them with `_unchecked` suffix and add deny-by-default lint; remove the unchecked `Supervisor::*` passthroughs entirely.

### P1 — saga journal posture broken from FFI
- All FFI bridges call `Supervisor::with_providers(...)` which always wires `NoOpSagaJournal` (supervisor.rs:449). FFI cannot configure a real journal.
- Cross-context sagas (migration, standing-pair, broadcast hosting handshake, cross-context tool invocation) lose all durable journal records. Crash recovery via `load_unresolved` is silently empty.
- Migration sagas are secret-bearing (handover envelope). With `NoOpSagaJournal`, the §9.4.3 "synchronously overwrite on-disk evidence" guarantee is moot — but if any production code path triggers `start_saga` from FFI today, in-flight sagas will not survive crash. Documented as "saga orchestration not yet active in FFI bridges (lands with watchdog migration in commit 12c.10)".
- Fix: extend `with_providers` with a `saga_journal: Option<Arc<dyn SagaJournal>>` parameter, default to a typed `Disabled` variant that returns `ContextError::NotInitialized` on `start_saga` instead of pretending to succeed. Or refuse `start_saga` entirely when `saga_journal.is::<NoOpSagaJournal>()`.

### P2 — saga FSM panic poisons concurrency guard
- `Supervisor::start_saga` (supervisor.rs:1569) sets `saga_pending_guard` to `true`, awaits `run_saga_fsm`, then stores `false`. No RAII; if `run_saga_fsm` panics, the store-false never runs and `saga_pending_guard` is permanently `true`. All future `start_saga` calls return `ActorBusy(SagaBusy)` until process restart.
- Fix: wrap `fsm_result` in a `scopeguard::defer!` (or a guard struct with `Drop`) so the AtomicBool resets on panic and ?-early-return both.

### P2 — saga journal does not require encrypted storage
- `SagaJournal` trait accepts any `scp_platform::Storage` backend. `JournalEntry.evidence: Zeroizing<Vec<u8>>` (msgpack-serialized) hits storage in plaintext between `append` and `mark_resolved(secret_bearing=true)`. If the storage backend is unencrypted (e.g. `InMemoryStorage`, plain `FileStorage`), the bearer envelope is recoverable from disk during the saga's lifetime.
- Spec §9.4.3 implies the journal's storage backend MUST satisfy at-rest encryption. The trait does not enforce this with a marker bound (`Storage: EncryptedStorage`).
- Fix: parameterize `ProtocolRepositorySagaJournal` over `S: EncryptedStorage` (the same sealed bound `ProtocolRepository::new` uses), or refuse construction at runtime when the backend is unencrypted.

### P2 — WrappingKeyPair derives Debug
- `WrappingKeyPair { public: [u8; 32], secret: Zeroizing<[u8; 32]> }` (actor/state.rs:885) has `#[derive(Debug)]`. The zeroize crate's `Zeroizing<Z>` derives `Debug` by delegating to inner `Z`, so `format!("{:?}", pair)` prints all 32 secret bytes.
- No production tracing/logging path currently formats `WrappingKeyPair` (verified via grep). Defense-in-depth issue: a future tracing line could leak.
- Fix: implement Debug manually with redacted output (analogous to `MlsCryptoProvider`'s `[N entries]` pattern); do not derive.

### P2 — `not_configured_key_resolver` silently disables governance signature verification
- All FFI bridges pass `not_configured_key_resolver()` to `with_providers` (commit 12 keeps the pre-existing pattern). Vote signatures are never verified at the helper layer.
- Pre-existing (called out in prior session memory as "key resolver not configured — governance vote signature verification is disabled").
- Fix: track whether a real resolver was wired, and reject vote dispatches when no resolver is set in production builds. Today the resolver is `None` and votes proceed.

### P3 — `wrapping_secret_key_for` returns owned secret copies
- `Supervisor::wrapping_secret_key_for` (supervisor.rs:698) returns `Arc<Zeroizing<Vec<u8>>>` allocated from `pair.secret.to_vec()`. Each call materialises a new heap copy. The Arc count tracks references but not aliases — multiple readers can hold copies of the same secret.
- `pub(crate)` and currently `#[allow(dead_code)]` (no production caller in commit 12).
- Fix: when wired in 12c.10, return a guard handle that forces single-reader semantics (e.g., `Arc<Zeroizing<...>>` is fine; just document call-site discipline).

### P3 — `KeyDestructionAttestation` unconditionally claims success
- `key_destruction.rs:111-112` sets `mls_group_destroyed: true` and `sender_keys_destroyed: true` always. The underlying `destroy_mls_group` / `destroy_sender_key` are infallible no-ops if the entry doesn't exist — so a duplicate close attests destruction without anything destroying.
- Not a security violation per se (nothing existed to destroy), but the attestation is misleading if relied on for audit.
- Fix: have the destroy methods return a "did anything exist" bool, propagate up to the attestation.

### Pre-existing issues kept by the refactor (not new, not fixed)
- Best-effort persistence: `persist_context_snapshot` swallows persistence write failures (manager_methods.rs:381). Forward-secrecy ops (`execute_revoke`, `execute_change_role`, `execute_remove_member`) mutate in-memory state before persisting; if persist fails the next process restart loses the revoke.
- `not_configured_key_resolver` (above).
- `DEFAULT_BRIDGE_INSTANCE` global singleton in PyO3/UniFFI/NAPI.

## CI gates (verified working)
- OwnedIdentityDid sole-minter enforcement: at commit 12 a `scripts/` Python source-text scanner enforced declaration location, `pub(super)` visibility, and forbidden derives. That scanner was later DROPPED entirely in favor of compiler enforcement — the type system (private field + `pub(super)` constructor), `#![deny(unsafe_code)]`, and `#![deny(non_local_definitions)]` (blocks a nested-impl second minter), plus review of the small frozen file. No bespoke CI gate remains.
- `disallowed-types` clippy.toml in scp-runtime forbidding `tokio::sync::RwLock` and `tokio::sync::Mutex` on read paths (Decision 12).
- `forbid(unsafe_code)` at scp-runtime/lib.rs.
- `clippy::expect_used` denied; verified all surviving `unwrap()/expect()` are in `#[cfg(test)]` blocks.

## Patterns to remember across the refactor
- "FFI bridge wires Some(empty) instead of None at boundary" recurs — see prior memory on UCAN ceiling. For `with_providers`, the `Option<Arc<dyn ContextPersistence>>` parameter is the new one to watch.
- Public passthrough on `Supervisor::*` of helper functions means any helper that has both `_inner(check, signing_key, ..., check_capability: bool)` and a "convenience" entry that passes `false` becomes a public capability-bypass surface.
- Saga journal is the right place for an `EncryptedStorage` sealed trait bound, mirroring `ProtocolRepository::new()`.
