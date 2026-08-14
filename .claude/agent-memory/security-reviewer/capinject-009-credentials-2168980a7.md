---
name: capinject-009-credentials-2168980a7
description: SCP-CAPINJECT-009 (ADR-062 §Decision 5) E2 bridge-credential durable-store selection — double-zero gating pass, ZERO findings
metadata:
  type: project
---

# SCP-CAPINJECT-009 E2 credentials — ZERO findings (branch feat/adr062-slice9-credentials, head 2168980a7, 2026-08-01)

Double-zero gating confirmation. Final state fails closed, no secret leakage. **Why:** removes the live SCP-CAPSEL-8000/8011 violation (in-memory credential store as a *default selection*). **How to apply:** this pattern (testing-gated enum arm + fail-closed lazy accessor) is the reference for future capability-injection fixes.

- **No silent in-memory store shipped.** `FfiCredentialStore` enum (crates/scp-ffi/common/src/credentials.rs): `Durable(Arc<dyn DurableCredentialBackend>)` always; `InMemory` arm + `in_memory()` ctor + all match arms are `#[cfg(feature="testing")]`. `InMemoryCredentialStore` itself `#[cfg(any(test,feature="testing"))]` in scp-runtime; its `Default` impl DELETED. `durable_from_handle<S: EncryptedStorage>` always returns `Durable`.
- **3 bridges select durable.** napi/uniffi eager at every ctor via `durable_from_handle(Arc::clone(&storage_handle))` before handle moved into durable providers. PyO3 lazy: `PyBridgeInstance::credential_store() -> Option<FfiCredentialStore>` matches both `StorageProvider` variants (InMemoryEncrypted/Sqlite, exhaustive no-wildcard) → durable; `None` only pre-storage-selection. `credential_store_for` (bridge_connector.rs) maps `None` → fail-closed `SCP-CTX-2105` (codes::CTX_2105) on ALL 8 ops. No in-memory fallback.
- **Path-injection defended.** bridge_id → `sanitize_key_component` in every key builder; credential_type → SHA-256(Display) hex (fixed-len, no `/`, safe for `Custom(arbitrary)`); full type preserved in value (list reads values, never parses keys). store/credentials.rs.
- **Secrets.** Root key `Zeroizing` end-to-end (generate/derive/store_value_zeroize/load-with-intermediate-zeroize). Hand-written redacting `Debug` on `FfiCredentialStore` (arm name only). No logging anywhere in credential files. Errors carry only bridge_id/type/byte-length/opaque crypto reason.
- **AAD path (new).** `credential_aad` = domain-tag `SCP-BRIDGE-CREDENTIAL-AAD-V1` || u64_le(len) || Display(type) || u64_le(created_at); authenticated-not-stored; injective + length-delimited. provision/rotate compute created_at BEFORE seal; retrieve builds AAD from the SLOT accessed + stored created_at → slot-swap fails GCM tag (no misattributed plaintext). AAD carries no secret. No leak.
- **pub→pub(crate).** encrypt_credential/decrypt_credential widened module-private→`pub(crate)`; credential_aad new `pub(crate)`. Does NOT cross crate boundary → not re-exportable public from scp-core → invisible to FFI/SDK. derive_credential_key/generate_bridge_credential_key stay `pub` (used by bridge_connector). Nothing security-relevant exposed/hidden.
- **Matrix/coverage additive.** sdk-capability-matrix.json +1 cell `credential_backend_durable` (4 langs true); check-sdk-coverage.py +1 ALIASES entry → existing storage-selection symbols. No existing entry weakened. Not an enforcement bypass.
- **Observation (NOT shipped, NOT a finding):** testing-gated `InMemoryCredentialStore` derives `Debug`; its `Zeroizing<[u8;32]>` root-key map would print raw bytes if `{:?}`-formatted (Zeroizing delegates Debug to inner). Test-only, never in shipped artifact.
