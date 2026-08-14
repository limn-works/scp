# SCP-CAPINJECT-009 — Durable Credential Store (feat/adr062-slice9-credentials @ 619c50604)

Reviewed 2026-07-17. Verdict: PASS, fail-closed, no secret leakage. No CRITICAL/HIGH. Observations only.

## Architecture
- Deletes `impl Default for InMemoryCredentialStore`; gates whole `InMemoryCredentialStore` behind
  `#[cfg(any(test, feature="testing"))]` in scp-runtime/src/bridge/credentials.rs.
- New `DurableCredentialBackend` (object-safe `#[async_trait]`) + `ProtocolRepositoryCredentialStore<S: EncryptedStorage>`
  = real durable backend over ProtocolRepository/EncryptedStorage.
- New `FfiCredentialStore` enum in crates/scp-ffi/common/src/credentials.rs: `Durable(Arc<dyn DurableCredentialBackend>)`
  + `InMemory(...)` gated `#[cfg(feature="testing")]`. Redacting Debug (prints arm only).
- New store layer: crates/scp-runtime/src/store/credentials.rs. Keys:
  `bridge-credential/{sanitize(bridge_id)}/{sha256(Display(credential_type))}` and `bridge-credential-key/{sanitize(bridge_id)}`.

## Why it passes (fail-closed selection)
- PyO3 (asymmetric/lazy): `credential_store()` returns `Option<FfiCredentialStore>` built per-call from
  `storage_provider()?` (OnceLock<StorageProvider>). None → bridge_connector `credential_store_for` maps to typed
  CTX_2105 (SCP-CTX-2105) error. No in-memory fallback. Match over StorageProvider {InMemoryEncrypted, Sqlite} is
  exhaustive (2 variants). Both arms → `durable_from_handle`. Even dev in-memory selection = Durable over
  EncryptingAdapter<InMemoryStorage> (encrypted at rest), NOT the InMemory credential double.
- NAPI/UniFFI (eager): field is non-optional `FfiCredentialStore`; ALL constructors set
  `durable_from_handle(Arc::clone(&storage_handle))` — verified on branch blobs (working tree was on base HEAD, not branch — grep base is misleading; use `git show origin/branch:file`).
- InMemory arm `#[cfg(feature="testing")]`; `testing` never in a default feature list; `.in_memory()` only referenced in
  `#[cfg(all(test, feature="testing"))]`. Provably absent from shipped artifact.
- PyO3 lazy accessor race-free: stateless store over immutable OnceLock Arc snapshot; no partial-init/TOCTOU.

## Injection / secrets
- bridge_id → scp_platform sanitize_key_component (rejects `/ \ .. \0`). credential_type → SHA-256 hashed so
  Custom(arbitrary) can't break key grammar. Full type preserved verbatim in stored value.
- Root key: Zeroizing<[u8;32]>; store_value_zeroize scrubs serialized envelope; load path zeroizes intermediate Vec.
- CredentialError messages carry only bridge_id/credential_type/reason — never plaintext/key bytes. store_err lifts
  StoreError.to_string() (no secret bytes). FfiCredentialStore Debug redacts.

## Observations (not blocking)
- now_secs() unwrap_or_default → created_at=0 on clock failure (durability-only metadata; recurring repo pattern).
- provision/rotate/revoke are load-then-store, no CAS → last-write-wins under concurrency; documented, caller must
  quiesce. Acceptable durability-only admin path.
- Durable backend does NOT honor trait's "revoke MUST overwrite with zeros" / "reject when suspended" contract lines:
  crypto-shreds (deletes records + root-key custody copy, relies on EncryptedStorage at-rest) and has no suspend hook.
  suspend_bridge/BridgeSuspended is InMemory-inherent test-only, never wired in production — NOT a regression.
  (scp-node BridgeStatus::Suspended is a separate node auth gate, unrelated.)
- BridgeCredential derives Debug printing encrypted_data (ciphertext only, not plaintext) — mild, consider redact.
- sdk-capability-matrix + check-sdk-coverage.py changes are purely ADDITIVE (new `credential_backend_durable` row +
  alias to existing storage-selection symbols). No existing check weakened.
