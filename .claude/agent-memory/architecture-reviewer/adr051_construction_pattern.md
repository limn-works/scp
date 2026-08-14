---
name: adr051-construction-pattern
description: ADR-051 unified flat-config construction pattern — verified facts about EncryptedStorage seal, RPITIT object-safety, and precedent-claim inaccuracies
metadata:
  type: project
---

ADR-051 (phase-2.md) + `.docs/standards/construction.md` replace the `ApplicationNodeBuilder` typestate with one flat config-object pattern (`Thing::start(config)`) across all 5 SDK languages. PR #1805 (docs-only).

**Why:** SDK's primary author is an LLM; typestate phantom markers (`HasDomain`/`HasNoDomain`/`HasIdentity`) cause compile-retry loops and don't translate to Python/TS/Swift/Kotlin. Ratified as new CLAUDE.md "Agent-first API design" builder tenet.

**How to apply (verified code facts for any construction-pattern review):**
- `EncryptedStorage` seal: `crates/scp-platform/src/encrypted.rs` — sealed marker trait via `private::Sealed`; only `SqliteStorage`/`AppleStorage`/`Arc<T>` impl it. Production `ApplicationNodeBuilder::build()` is gated `where S: EncryptedStorage` (lib.rs:3142); `build_for_testing()` is separate, feature-gated. ADR's `start`/`start_for_testing` trait-bound split preserves this EXACTLY. Claim is ACCURATE.
- Object-safety wall is REAL: `KeyCustody`+`Storage` (`scp-platform/src/traits.rs`) and `DidMethod` (`scp-identity/src/lib.rs:366`) all use RPITIT (`impl Future<...> + Send`). `Arc<dyn Storage>` genuinely will not compile. Providers MUST stay typed enum-selectors. Claim is ACCURATE.

**Precedent-claim INACCURACIES found (artifacts mislead implementers):**
- `StorageConfig` has NO `Custom` variant anywhere — only `InMemory` + `Sqlite` (`scp-ffi/src/runtime.rs`). ADR/standard cite a "StorageConfig Custom(concrete) asymmetry precedent" that does not exist.
- `StorageConfig` is an FFI-layer enum DEFINED SEPARATELY in each bridge (`scp-ffi/src/`, `uniffi/src/`, `napi/src/`) — NOT one shared core type. Rust-core `NodeConfig.storage` cannot literally carry the FFI `StorageConfig` (core doesn't dep scp-ffi).
- Name collision: private `enum IdentitySource<K,D>` already exists at `scp-node/src/lib.rs:1580` (2 variants `Generate{key_custody,did_method}`/`Explicit`); ADR's public `IdentitySource` has 3 variants (`Generate|Persisted|Explicit`, field renamed `custody`). `Persisted` is new behavior.
- `DhtMode` lives only in `self_host.rs` today; `Reach` does NOT exist yet (closest: `PublicSurface`/`ReachabilityTier`). Both need homing/creating; reconcile with existing `skip_nat`.

Verdict was NEEDS REVISION (docs precision only; core decision sound, both preserved constraints accurately characterized).
