# FFI Platform Adapter Must Be Retained on the Handle Struct

**Rule**: When an FFI bridge function creates a platform adapter (e.g., `KeyCustodyProviderAdapter`) to
perform a one-shot operation (DID creation, key generation), that adapter must be stored on the opaque
handle struct — not dropped at scope exit — if any subsequent operation on that handle needs the same
provider.

**Context (SCP-214 review, 2026-03-01)**: `identity_create_platform` in
`crates/scp-ffi/uniffi/src/bridge.rs` creates a `KeyCustodyProviderAdapter` wrapping the injected
`KeyCustodyProvider` callback, calls `dht.create(&adapter)` to create the DID, then returns an
`Identity` struct with `in_memory_custody: None`. The adapter is dropped at the end of the function.

Consequence: every subsequent operation that requires the platform custody provider — `context_create`
(routing ID derivation), message signing (`create_inner_envelope`), key rotation (`DidMethod::rotate`),
UCAN minting — has no reference to the provider. The UniFFI and NAPI `context_create` functions both
gate routing ID derivation on `in_memory_custody.is_some()`, which is always `false` for platform
identities. Platform custody identities silently get `routing_id: None` for every context they create.

**Pattern that passes review**:

```rust
pub struct Identity {
    pub(crate) did: String,
    pub(crate) custody_type: CustodyMethod,
    pub(crate) core_id: Option<ScpIdentity>,
    pub(crate) in_memory_custody: Option<Arc<OpaqueInMemoryKeyCustody>>,
    // NEW: retain the platform adapter for the lifetime of the handle
    pub(crate) platform_custody: Option<Arc<dyn KeyCustody + Send + Sync>>,
}
```

In `identity_create_platform`:

```rust
let adapter = Arc::new(KeyCustodyProviderAdapter::new(provider));
let (identity, _document) = dht.create(adapter.as_ref()).await.map_err(ScpError::from)?;
let handle = Arc::new(Identity {
    did: identity.did.clone(),
    custody_type: CustodyMethod::Platform,
    core_id: Some(identity),
    in_memory_custody: None,
    platform_custody: Some(adapter),  // retained
});
```

Then in `context_create`, check both custody fields:

```rust
let routing_id = if let (Some(custody), Some(core_id)) =
    (identity.in_memory_custody.as_ref(), identity.core_id.as_ref())
{
    Some(custody.0.derive_pseudonym(...).await?)
} else if let (Some(custody), Some(core_id)) =
    (identity.platform_custody.as_ref(), identity.core_id.as_ref())
{
    Some(custody.derive_pseudonym(...).await?)
} else {
    None
};
```

**Corollary**: The same pattern applies to any opaque handle that wraps a provider injected at
construction time (storage providers, push providers, attestation providers). If the provider is used
beyond the constructor, it must live on the struct.

**Detection**: When reviewing FFI bridge identity/context functions, check:
1. Does the function create a platform adapter?
2. Is that adapter stored on the returned handle struct?
3. Does any subsequent bridge function on the same handle require the same adapter?

If the answer to (1) and (3) is yes and (2) is no, the adapter is incorrectly dropped.

**Related lessons**: `ffi-identity-load-does-not-restore-crypto-state.md` (same root: crypto state not
persisted across function boundaries).
