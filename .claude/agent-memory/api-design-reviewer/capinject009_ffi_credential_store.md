---
name: capinject009-ffi-credential-store
description: SCP-CAPINJECT-009 FfiCredentialStore enum seam review — verdict APPROVED; PyO3 lazy-accessor asymmetry judged justified (internal seam, not SDK surface)
metadata:
  type: project
---

# SCP-CAPINJECT-009 / ADR-062 Slice 9 — FfiCredentialStore enum seam (commit 619c50604, branch feat/adr062-slice9-credentials)

Reviewed the FFI credential-store selection seam. Verdict: **APPROVED**, minor observations only.

**Design shape:**
- `FfiCredentialStore` enum (crates/scp-ffi/common/src/credentials.rs): `Durable(Arc<dyn DurableCredentialBackend>)` + `#[cfg(feature="testing")] InMemory(...)`. Constructors `durable_from_handle<S>(Arc<S>)` (prod) and `#[cfg(testing)] in_memory()`. No `Default`, no zero-arg ctor — explicit arm selection forced at bridge construction boundary. Redacted Debug. This is exemplary misuse-resistance: selecting in-memory in prod is impossible by construction (cfg-gate), not by docs.
- Two parallel traits by design: `BridgeCredentialStore` (RPITIT, not dyn-safe, canonical contract, spec §12.11) + `DurableCredentialBackend` (#[async_trait], object-safe mirror of same 8 ops) purely for `Arc<dyn ...>` erasure. Same idiom as OpenMlsStorageAdapter. Drift is COMPILER-CAUGHT: adding a method to BridgeCredentialStore forces enum impl whose Durable arm calls through DurableCredentialBackend → compile error if mirror lacks it. Justified.

**The key asymmetry (concern raised):** PyO3 derives the store LAZILY in a per-call accessor `credential_store() -> Option<FfiCredentialStore>` over `OnceLock<StorageProvider>`; NAPI/UniFFI hold it as a `credential_store: FfiCredentialStore` field built at construction, accessor returns `&`. **Judged JUSTIFIED, not a tenet violation:**
- It's an internal FFI accessor, NOT the developer-facing SDK surface. The SDK-facing bridge_connector ops (provision/retrieve/rotate/revoke/list/keys) are identical across all three bridges. The "identical shape across bindings" tenet governs the SDK surface.
- Asymmetry is inherited from a pre-existing structural difference: PyO3 selects storage lazily via OnceLock (set post-construction by with_storage_py); NAPI/UniFFI select at construction. Credential store correctly tracks each bridge's existing pattern.
- Re-derivation is functionally equivalent: store is stateless over the shared Arc handle; `ProtocolRepository::new` is a zero-cost `const fn`; only cost is one Arc alloc per call. No state lost.
- Production behavior identical; the only divergence (PyO3 None → fail-closed CTX_2105) is unreachable in correct prod usage.

**Minor observations flagged:** (1) genuine internal-seam shape divergence: Option-by-value vs &-ref return + PyO3-only CTX_2105 defensive path — acceptable defense-in-depth. (2) Doc-accuracy nit: runtime.rs credential_store() doc says None maps to "SCP-CAPSEL-8001" but emitted runtime code is `codes::CTX_2105`; SCP-CAPSEL-8001 is a requirement/enforcement ID not the error code — align the doc. (3) `in_memory()` ctor (test RAM double) vs `InMemoryEncrypted` storage variant (still routes durable) are adjacent names, documented, different namespaces.
