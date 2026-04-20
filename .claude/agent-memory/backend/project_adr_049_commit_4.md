---
name: ADR-049 commit 4 — new traits + production impls
description: Commit 4 of the actor-per-context refactor (ADR-049). Introduces MlsBackend, HpkeBackend, OpenMlsStorageAdapter, SagaJournal traits and production impls. Existing MlsCryptoProvider/ContextCryptoProvider untouched.
type: project
---

Active work on branch `refactor/actor-per-context` (base SHA d64708e8c).

**Why:** Commit 4 introduces new trait surfaces + production impls together, sharing the shared-storage validation gate before any later commit (5+) starts dissolving MlsCryptoProvider. The trait split replaces the 26-method ContextCryptoProvider with narrower: MlsBackend (~10), HpkeBackend (~3). StorageProvider is async now (`OpenMlsStorageAdapter`) with `spawn_blocking` hops. SagaJournal per spec §17.16 + §9.4.3.

**How to apply:**
- MlsBackend implementation MUST produce byte-identical output to existing `MlsCryptoProvider` MLS primitive calls — delegate to same OpenMLS configuration + same SCP_CIPHERSUITE.
- `ProductionHpkeBackend` is fresh: RFC 9180 Base mode (KEM X25519 0x0020, KDF HKDF-SHA256 0x0001, AEAD AES-128-GCM 0x0001). AAD pass-through (empty).
- `SpawnBlockingStorageAdapter` wraps `Arc<dyn Storage>` with `tokio::task::spawn_blocking` on every op. No `block_in_place`/`block_on` in new code.
- `ProtocolRepositorySagaJournal` writes to `ContextPersistence` under `saga_journal/` key prefix. Entry: length prefix + CRC32 checksum. Secret-bearing mark_resolved synchronously overwrites evidence before returning. Uses `scp-platform::PlatformError` via `Storage` trait.
- Existing files BYTE-IDENTICAL: `crates/scp-protocol/src/context/builder.rs`, `crates/scp-runtime/src/crypto/mls/provider.rs`, `crates/scp-runtime/src/crypto/mls/storage.rs`.
- ADR-049 Decisions 3 (saga), 6 (trait split), 7 (async providers + block_in_place removal).
- Spec §9.4.3 saga secret handling, §17.16 saga journal (3 operations, key namespace, crash recovery).
- Must NOT add `block_in_place` or `block_on` sites. `spawn_blocking` is OK.

**Shared-storage validation gate:** integration test `openmls_shared_storage_validation.rs` spawns N=4 tasks over shared `Arc<dyn OpenMlsStorageAdapter>`, each doing create_group, add_member, encrypt, decrypt, advance_epoch. 5 assertions — silent corruption on same-group_id races is the failure mode (STOP + escalate).

**Ratchet ban list (check-deleted-primitives.sh):** currently empty (activated in commit 12). No deletions expected in commit 4.
