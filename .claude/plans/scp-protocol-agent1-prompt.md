# Agent 1 Prompt: Create scp-protocol + scp-runtime + scp-core facade

## Task

Three-crate extraction from the current scp-core monolith:
1. Create `scp-protocol` — pure sync protocol types (~82K lines)
2. Rename current `scp-core` to `scp-runtime` — keeps async orchestration
3. Create NEW `scp-core` — facade with explicit wrapper modules merging both crates

Do NOT attempt to compile — Agent 2 handles compilation fixes.

**Execute phases in strict order: A → B → C → D → E → F → G → H → I.**
Phase B must complete before Phase C (the `git mv` frees the `crates/scp-core` path for the new facade).

## Branch: `refactor/scp-protocol-extraction`

Create from latest main.

---

## Phase A: Create scp-protocol crate

1. Add `"crates/scp-protocol"` to workspace `Cargo.toml` members list

2. Create `crates/scp-protocol/Cargo.toml`:

```toml
[package]
name = "scp-protocol"
version = "0.1.0-beta.1"
description = "Pure sync protocol types and logic for SCP"
edition.workspace = true
repository.workspace = true
license.workspace = true
homepage.workspace = true

[dependencies]
scp-primitives = { path = "../scp-primitives", version = "=0.1.0-beta.1" }
scp-event-log = { path = "../scp-event-log", version = "=0.1.0-beta.1" }
serde = { workspace = true }
serde_json = { workspace = true }
serde_json_canonicalizer = { workspace = true }
serde_bytes = { workspace = true }
rmp-serde = { workspace = true }
rmpv = { workspace = true }
thiserror = { workspace = true }
sha2 = { workspace = true }
ed25519-dalek = { workspace = true }
x25519-dalek = { workspace = true }
hkdf = { workspace = true }
aes = { workspace = true }
aes-gcm = { workspace = true }
rand = { workspace = true }
hex = { workspace = true }
base64 = { workspace = true }
bs58 = { workspace = true }
uuid = { workspace = true }
zeroize = { workspace = true }
subtle = { workspace = true }
tracing = { workspace = true }
percent-encoding = { workspace = true }
unicode-normalization = { workspace = true }
jsonschema = { version = "0.28", default-features = false }
metrics = { workspace = true }
lru = { workspace = true }

[dev-dependencies]
serde_json = { workspace = true }
rmp-serde = { workspace = true }
proptest = "1"
# dev-only: some #[cfg(test)] blocks extracted from scp-core use async test infrastructure.
# These do NOT affect the production crate — scp-protocol has zero async in production code.
tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }
scp-primitives = { path = "../scp-primitives" }
scp-platform = { path = "../scp-platform", features = ["testing"] }
scp-event-log = { path = "../scp-event-log", features = ["testing"] }

[lints]
workspace = true
```

---

## Phase B: Rename scp-core to scp-runtime

1. In `crates/scp-core/Cargo.toml`, change `name = "scp-core"` to `name = "scp-runtime"`
2. In workspace `Cargo.toml`, change `"crates/scp-core"` member to `"crates/scp-runtime"`
3. `git mv crates/scp-core crates/scp-runtime`
4. Add `scp-protocol` dependency to `crates/scp-runtime/Cargo.toml`:
   ```toml
   scp-protocol = { path = "../scp-protocol", version = "=0.1.0-beta.1" }
   ```

---

## Phase C: Create new scp-core facade

1. Add `"crates/scp-core"` back to workspace `Cargo.toml` members
2. Create `crates/scp-core/Cargo.toml`:

```toml
[package]
name = "scp-core"
version = "0.1.0-beta.1"
description = "SCP protocol + runtime — unified API surface"
edition.workspace = true
repository.workspace = true
license.workspace = true
homepage.workspace = true

[dependencies]
scp-protocol = { path = "../scp-protocol", version = "=0.1.0-beta.1" }
scp-runtime = { path = "../scp-runtime", version = "=0.1.0-beta.1" }

[features]
testing = ["scp-runtime/testing"]
allow_unencrypted_storage = ["scp-runtime/allow_unencrypted_storage"]
allow_in_memory_custody = ["scp-runtime/allow_in_memory_custody"]

[dev-dependencies]
serde_json = { workspace = true }

[lints]
workspace = true
```

3. Create `crates/scp-core/src/lib.rs` with **explicit wrapper modules**.

The facade merges sub-modules from both crates by name. Within each wrapper, re-export
sub-modules EXPLICITLY (not `pub use *`) to avoid hidden name conflicts:

```rust
//! SCP protocol + runtime — unified API surface.
//!
//! Merges [`scp_protocol`] (pure sync types) and [`scp_runtime`] (async
//! orchestration) into a single namespace. Downstream crates depend on
//! `scp-core` alone.
//!
//! MAINTENANCE: When adding a public module to scp-protocol or scp-runtime,
//! add the corresponding re-export here. The CI check and structural test
//! in tests/facade_completeness.rs will catch omissions.

// --- Modules that exist ONLY in scp-protocol (no conflict) ---
pub use scp_protocol::jcs;
pub use scp_protocol::serde_util;
pub use scp_protocol::time;
pub use scp_protocol::uri;

// --- Modules that exist ONLY in scp-runtime (no conflict) ---
pub use scp_runtime::store;
pub use scp_runtime::event_log;
pub use scp_runtime::metrics;
pub use scp_runtime::well_known;

// --- Modules split across both crates (explicit sub-module merging) ---

pub mod crypto {
    // From scp-protocol (pure):
    pub use scp_protocol::crypto::canonical;
    pub use scp_protocol::crypto::ed25519;
    pub use scp_protocol::crypto::tofu;
    pub use scp_protocol::crypto::key_continuity;
    pub use scp_protocol::crypto::envelope_seal;
    // From scp-runtime (async):
    pub use scp_runtime::crypto::mls;
    // Split sub-modules (disjoint children merged):
    pub mod sender_keys {
        // Protocol: SenderKey types, encrypt, key_protocol_verify, broadcast
        pub use scp_protocol::crypto::sender_keys::*;
        // Runtime: key_protocol (async signing)
        pub use scp_runtime::crypto::sender_keys::key_protocol;
    }
    pub mod access_keys {
        // Protocol: AccessKey types, wrapping
        pub use scp_protocol::crypto::access_keys::*;
        // Runtime: lifecycle, wire (async)
        pub use scp_runtime::crypto::access_keys::lifecycle;
        pub use scp_runtime::crypto::access_keys::wire;
    }
    pub mod ucan {
        // Protocol: UcanError/Token types, validate, capability, nonce, revoke, spending
        pub use scp_protocol::crypto::ucan::*;
        // Runtime: mint (async signing)
        pub use scp_runtime::crypto::ucan::mint;
    }
}

pub mod context {
    // Protocol: ContextState, ContextError, context_id_bytes, params, roles, etc.
    pub use scp_protocol::context::*;
    // Runtime: ContextHandle, manager, builder, providers, ttl, etc.
    pub use scp_runtime::context::manager;
    pub use scp_runtime::context::builder;
    pub use scp_runtime::context::providers;
    pub use scp_runtime::context::ttl;
    pub use scp_runtime::context::export_import;
    pub use scp_runtime::context::standing;
    pub use scp_runtime::context::app_sandbox;
    pub use scp_runtime::context::policy;
    // Split sub-modules:
    pub mod governance {
        pub use scp_protocol::context::governance::*;
        pub use scp_runtime::context::governance::timeout;
    }
    pub mod tools {
        pub use scp_protocol::context::tools::*;
        pub use scp_runtime::context::tools::invoke;
        pub use scp_runtime::context::tools::session;
    }
}

pub mod trust {
    pub use scp_protocol::trust::*;
    // Runtime: only ProtocolRepositoryTrustBridge (NOT glob — avoid duplicate re-exports)
    pub use scp_runtime::trust::ProtocolRepositoryTrustBridge;
}

pub mod identity {
    pub use scp_protocol::identity::*;
    // Runtime: blocking, recovery, custody_migration, scpid
    pub use scp_runtime::identity::blocking;
    pub use scp_runtime::identity::recovery;
    pub use scp_runtime::identity::custody_migration;
    pub use scp_runtime::identity::scpid;
}

pub mod economy {
    pub use scp_protocol::economy::*;
    // Runtime: credentials, integration, adapter, receipt
    pub use scp_runtime::economy::credentials;
    pub use scp_runtime::economy::integration;
    pub use scp_runtime::economy::adapter;
    pub use scp_runtime::economy::receipt;
}

pub mod discovery {
    pub use scp_protocol::discovery::*;
    // Runtime: addressing, search, did_capabilities, bootstrap, dht_context
    pub use scp_runtime::discovery::addressing;
    pub use scp_runtime::discovery::search;
    pub use scp_runtime::discovery::did_capabilities;
    pub use scp_runtime::discovery::bootstrap;
    pub use scp_runtime::discovery::dht_context;
}

pub mod envelope {
    pub use scp_protocol::envelope::*;
    // Runtime: pseudonym (async)
    pub use scp_runtime::envelope::pseudonym;
    // Split sub-modules:
    pub mod inner {
        pub use scp_protocol::envelope::inner::*;
        pub use scp_runtime::envelope::inner::sign;
    }
    pub mod outer {
        pub use scp_protocol::envelope::outer::*;
        pub use scp_runtime::envelope::outer::ops;
    }
}

pub mod sync {
    pub use scp_protocol::sync::*;
    // Runtime: days_offline, hours_offline, weeks_offline
    pub use scp_runtime::sync::days_offline;
    pub use scp_runtime::sync::hours_offline;
    pub use scp_runtime::sync::weeks_offline;
}

pub mod bridge {
    pub use scp_protocol::bridge::*;
    // Runtime: oauth, credentials
    pub use scp_runtime::bridge::oauth;
    pub use scp_runtime::bridge::credentials;
}

pub mod provenance {
    pub use scp_protocol::provenance::*;
}
```

NOTE: Protocol side uses `pub use *` within wrappers (safe — scp-protocol exports only pure
sub-modules with no name conflicts). Runtime side uses EXPLICIT sub-module names (safe —
we know exactly what stays). If a protocol-side `pub use *` ever conflicts with a runtime
sub-module name, the compiler will catch it immediately.

---

## Phase D: Move files from scp-runtime to scp-protocol

All source paths are now under `crates/scp-runtime/src/`.

Create destination directories:
```bash
mkdir -p crates/scp-protocol/src/{crypto/{sender_keys,access_keys,ucan},context/{governance,tools},trust,identity,economy,discovery,envelope/{inner,outer},sync,bridge,provenance}
```

### File moves:

**Leaf utilities:**
```bash
git mv crates/scp-runtime/src/jcs.rs crates/scp-protocol/src/jcs.rs
git mv crates/scp-runtime/src/serde_util.rs crates/scp-protocol/src/serde_util.rs
git mv crates/scp-runtime/src/time.rs crates/scp-protocol/src/time.rs
git mv crates/scp-runtime/src/uri.rs crates/scp-protocol/src/uri.rs
```

**Crypto primitives:**
```bash
git mv crates/scp-runtime/src/crypto/canonical.rs crates/scp-protocol/src/crypto/canonical.rs
git mv crates/scp-runtime/src/crypto/ed25519.rs crates/scp-protocol/src/crypto/ed25519.rs
git mv crates/scp-runtime/src/crypto/tofu.rs crates/scp-protocol/src/crypto/tofu.rs
git mv crates/scp-runtime/src/crypto/key_continuity.rs crates/scp-protocol/src/crypto/key_continuity.rs
git mv crates/scp-runtime/src/crypto/bip39_wordlist.rs crates/scp-protocol/src/crypto/bip39_wordlist.rs
git mv crates/scp-runtime/src/crypto/envelope_seal.rs crates/scp-protocol/src/crypto/envelope_seal.rs
```

**Sender keys (pure parts):**
```bash
git mv crates/scp-runtime/src/crypto/sender_keys/encrypt.rs crates/scp-protocol/src/crypto/sender_keys/encrypt.rs
git mv crates/scp-runtime/src/crypto/sender_keys/key_protocol_verify.rs crates/scp-protocol/src/crypto/sender_keys/key_protocol_verify.rs
git mv crates/scp-runtime/src/crypto/sender_keys/broadcast.rs crates/scp-protocol/src/crypto/sender_keys/broadcast.rs
```

**Access keys (pure parts):**
```bash
git mv crates/scp-runtime/src/crypto/access_keys/wrapping.rs crates/scp-protocol/src/crypto/access_keys/wrapping.rs
```

**UCAN (pure parts — NOT mint.rs):**
```bash
git mv crates/scp-runtime/src/crypto/ucan/capability.rs crates/scp-protocol/src/crypto/ucan/capability.rs
git mv crates/scp-runtime/src/crypto/ucan/nonce.rs crates/scp-protocol/src/crypto/ucan/nonce.rs
git mv crates/scp-runtime/src/crypto/ucan/revoke.rs crates/scp-protocol/src/crypto/ucan/revoke.rs
git mv crates/scp-runtime/src/crypto/ucan/spending.rs crates/scp-protocol/src/crypto/ucan/spending.rs
git mv crates/scp-runtime/src/crypto/ucan/validate.rs crates/scp-protocol/src/crypto/ucan/validate.rs
```

**Trust (all files):**
```bash
git mv crates/scp-runtime/src/trust/custody_violation.rs crates/scp-protocol/src/trust/custody_violation.rs
git mv crates/scp-runtime/src/trust/admission.rs crates/scp-protocol/src/trust/admission.rs
git mv crates/scp-runtime/src/trust/aggregate.rs crates/scp-protocol/src/trust/aggregate.rs
git mv crates/scp-runtime/src/trust/attestation.rs crates/scp-protocol/src/trust/attestation.rs
git mv crates/scp-runtime/src/trust/capability_registry.rs crates/scp-protocol/src/trust/capability_registry.rs
git mv crates/scp-runtime/src/trust/capability_uri.rs crates/scp-protocol/src/trust/capability_uri.rs
git mv crates/scp-runtime/src/trust/challenge.rs crates/scp-protocol/src/trust/challenge.rs
git mv crates/scp-runtime/src/trust/consequence.rs crates/scp-protocol/src/trust/consequence.rs
git mv crates/scp-runtime/src/trust/participation.rs crates/scp-protocol/src/trust/participation.rs
git mv crates/scp-runtime/src/trust/renewal.rs crates/scp-protocol/src/trust/renewal.rs
git mv crates/scp-runtime/src/trust/sybil.rs crates/scp-protocol/src/trust/sybil.rs
```

**Context types (NOT policy.rs — async):**
```bash
git mv crates/scp-runtime/src/context/params.rs crates/scp-protocol/src/context/params.rs
git mv crates/scp-runtime/src/context/state_machine.rs crates/scp-protocol/src/context/state_machine.rs
git mv crates/scp-runtime/src/context/roles.rs crates/scp-protocol/src/context/roles.rs
git mv crates/scp-runtime/src/context/membership.rs crates/scp-protocol/src/context/membership.rs
git mv crates/scp-runtime/src/context/memory_scope.rs crates/scp-protocol/src/context/memory_scope.rs
git mv crates/scp-runtime/src/context/metadata.rs crates/scp-protocol/src/context/metadata.rs
git mv crates/scp-runtime/src/context/templates.rs crates/scp-protocol/src/context/templates.rs
git mv crates/scp-runtime/src/context/close.rs crates/scp-protocol/src/context/close.rs
git mv crates/scp-runtime/src/context/nesting.rs crates/scp-protocol/src/context/nesting.rs
git mv crates/scp-runtime/src/context/invitation.rs crates/scp-protocol/src/context/invitation.rs
git mv crates/scp-runtime/src/context/promotion.rs crates/scp-protocol/src/context/promotion.rs
git mv crates/scp-runtime/src/context/broadcast.rs crates/scp-protocol/src/context/broadcast.rs
git mv crates/scp-runtime/src/context/broadcast_content.rs crates/scp-protocol/src/context/broadcast_content.rs
```

**Identity pure parts:**
```bash
git mv crates/scp-runtime/src/identity/block_list.rs crates/scp-protocol/src/identity/block_list.rs
git mv crates/scp-runtime/src/identity/private_state.rs crates/scp-protocol/src/identity/private_state.rs
git mv crates/scp-runtime/src/identity/private_state_events.rs crates/scp-protocol/src/identity/private_state_events.rs
git mv crates/scp-runtime/src/identity/attestation.rs crates/scp-protocol/src/identity/attestation.rs
```

**Governance (pure parts — NOT timeout.rs):**
```bash
git mv crates/scp-runtime/src/context/governance/majority.rs crates/scp-protocol/src/context/governance/majority.rs
git mv crates/scp-runtime/src/context/governance/multisig.rs crates/scp-protocol/src/context/governance/multisig.rs
git mv crates/scp-runtime/src/context/governance/unanimity.rs crates/scp-protocol/src/context/governance/unanimity.rs
git mv crates/scp-runtime/src/context/governance/mls_integration.rs crates/scp-protocol/src/context/governance/mls_integration.rs
```

**Context tools (pure parts — NOT invoke.rs, session.rs. YES interface.rs — it IS pure):**
```bash
git mv crates/scp-runtime/src/context/tools/integrity.rs crates/scp-protocol/src/context/tools/integrity.rs
git mv crates/scp-runtime/src/context/tools/lifecycle.rs crates/scp-protocol/src/context/tools/lifecycle.rs
git mv crates/scp-runtime/src/context/tools/registry.rs crates/scp-protocol/src/context/tools/registry.rs
git mv crates/scp-runtime/src/context/tools/schema.rs crates/scp-protocol/src/context/tools/schema.rs
git mv crates/scp-runtime/src/context/tools/summary.rs crates/scp-protocol/src/context/tools/summary.rs
git mv crates/scp-runtime/src/context/tools/interface.rs crates/scp-protocol/src/context/tools/interface.rs
```

**Economy (pure parts — NOT credentials.rs, integration.rs, adapter.rs, receipt.rs):**
```bash
git mv crates/scp-runtime/src/economy/types.rs crates/scp-protocol/src/economy/types.rs
git mv crates/scp-runtime/src/economy/policy.rs crates/scp-protocol/src/economy/policy.rs
git mv crates/scp-runtime/src/economy/budget.rs crates/scp-protocol/src/economy/budget.rs
git mv crates/scp-runtime/src/economy/pricing.rs crates/scp-protocol/src/economy/pricing.rs
git mv crates/scp-runtime/src/economy/estimate.rs crates/scp-protocol/src/economy/estimate.rs
git mv crates/scp-runtime/src/economy/antispam.rs crates/scp-protocol/src/economy/antispam.rs
```

**Discovery (pure parts only):**
```bash
git mv crates/scp-runtime/src/discovery/handles.rs crates/scp-protocol/src/discovery/handles.rs
git mv crates/scp-runtime/src/discovery/petnames.rs crates/scp-protocol/src/discovery/petnames.rs
git mv crates/scp-runtime/src/discovery/scope.rs crates/scp-protocol/src/discovery/scope.rs
git mv crates/scp-runtime/src/discovery/context.rs crates/scp-protocol/src/discovery/context.rs
git mv crates/scp-runtime/src/discovery/push.rs crates/scp-protocol/src/discovery/push.rs
```

**Envelope (pure parts — NOT pseudonym.rs, NOT sign.rs, NOT ops.rs):**
```bash
git mv crates/scp-runtime/src/envelope/inner/mod.rs crates/scp-protocol/src/envelope/inner/mod.rs
git mv crates/scp-runtime/src/envelope/outer/mod.rs crates/scp-protocol/src/envelope/outer/mod.rs
git mv crates/scp-runtime/src/envelope/chunk.rs crates/scp-protocol/src/envelope/chunk.rs
git mv crates/scp-runtime/src/envelope/padding.rs crates/scp-protocol/src/envelope/padding.rs
git mv crates/scp-runtime/src/envelope/validation.rs crates/scp-protocol/src/envelope/validation.rs
```

**Sync (pure parts):**
```bash
git mv crates/scp-runtime/src/sync/alerts.rs crates/scp-protocol/src/sync/alerts.rs
git mv crates/scp-runtime/src/sync/conflict_resolution.rs crates/scp-protocol/src/sync/conflict_resolution.rs
```

**Bridge types (NOT oauth.rs, NOT credentials.rs):**
```bash
git mv crates/scp-runtime/src/bridge/claiming.rs crates/scp-protocol/src/bridge/claiming.rs
git mv crates/scp-runtime/src/bridge/envelope.rs crates/scp-protocol/src/bridge/envelope.rs
git mv crates/scp-runtime/src/bridge/provenance.rs crates/scp-protocol/src/bridge/provenance.rs
git mv crates/scp-runtime/src/bridge/registration.rs crates/scp-protocol/src/bridge/registration.rs
git mv crates/scp-runtime/src/bridge/shadow.rs crates/scp-protocol/src/bridge/shadow.rs
```

**Provenance:**
```bash
git mv crates/scp-runtime/src/provenance/attach.rs crates/scp-protocol/src/provenance/attach.rs
git mv crates/scp-runtime/src/provenance/evaluate.rs crates/scp-protocol/src/provenance/evaluate.rs
```

---

## Phase E: Create scp-protocol module tree + split mod.rs files

For each module, READ the scp-runtime mod.rs IN FULL, then:
1. CREATE scp-protocol mod.rs with pure types + pure submodule declarations
2. EDIT scp-runtime mod.rs to REMOVE moved types, keep ONLY async submodule declarations

**SCOPING RULE for scp-protocol mod.rs files:**
Declare sub-modules as `pub mod X;` (keeping items scoped to `module::X::Item`).
Do NOT flatten with `pub use self::X::*;`. Flattening would cause name collisions in the
facade's `pub use scp_protocol::context::*` when scp-runtime adds explicit sub-modules.

**RE-EXPORT RULE for scp-runtime mod.rs files:**
scp-runtime mod.rs files must NOT re-export scp-protocol types (no `pub use scp_protocol::*;`).
Only declare their own async sub-modules. The scp-core facade handles merging — if scp-runtime
also re-exports, types appear via two paths, which is fragile and confusing.
Exception: envelope inner/outer mod.rs stubs (below) re-export for sign.rs/ops.rs internal use.

**CRITICAL for moved inner/mod.rs and outer/mod.rs:**
After moving these files, REMOVE `pub mod sign;` from the moved `inner/mod.rs` and `pub mod ops;` from the moved `outer/mod.rs` (those files stay in scp-runtime). Then create NEW mod.rs stubs in scp-runtime:

`crates/scp-runtime/src/envelope/inner/mod.rs`:
```rust
pub use scp_protocol::envelope::inner::*;
pub mod sign;
```

`crates/scp-runtime/src/envelope/outer/mod.rs`:
```rust
pub use scp_protocol::envelope::outer::*;
pub mod ops;
```

### The 15 mod.rs files to split:

1. `context/mod.rs` — Pure: ContextState, ContextError, context_id_bytes(). Stays: ContextHandle (tokio::RwLock), builder, manager, providers, ttl, export_import, standing, app_sandbox, policy.
   **NOTE:** ContextError::IntegrationFailed embeds IntegrationError from economy/integration.rs (stays). Agent 2 must handle this — either move IntegrationError or restructure.
2. `trust/mod.rs` — Pure: all trust types. Stays: `pub use crate::store::trust::ProtocolRepositoryTrustBridge;`
   **NOTE:** `participation` module is `pub(crate)` — promote to `pub` in scp-protocol.
3. `crypto/mod.rs` — Pure: re-exports of pure crypto modules. Stays: `pub mod mls;`, agent_binding_tests.
4. `crypto/ucan/mod.rs` — Pure: UcanError, UcanToken, UcanHeader, UcanPayload, Attenuation types. Stays: `pub mod mint;`
5. `crypto/sender_keys/mod.rs` — Pure: SenderKey, SenderKeyStore, SenderKeyError, generate_sender_key. Stays: `pub mod key_protocol;`
6. `crypto/access_keys/mod.rs` — Pure: AccessKey, AccessKeyError, ContentEncryptionKey types. Stays: `pub mod lifecycle;`, `pub mod wire;`
7. `envelope/mod.rs` — Pure: SCP_PROTOCOL_VERSION, EnvelopeError, VersionCompatibility. Stays: pseudonym.rs, inner/sign.rs, outer/ops.rs.
8. `economy/mod.rs` — Pure: module declarations for types, policy, budget, pricing, estimate, antispam. Stays: `pub mod credentials;`, `pub mod integration;`, `pub mod adapter;`, `pub mod receipt;`
9. `discovery/mod.rs` — Pure: DiscoveryError. Stays: addressing, search, did_capabilities, bootstrap, dht_context.
10. `bridge/mod.rs` — Pure: BridgeMode, BridgeConnector, ShadowIdentity types. Stays: `pub mod oauth;`, `pub mod credentials;`
11. `sync/mod.rs` — Pure: SyncEvent, SyncError. Stays: days_offline, hours_offline, weeks_offline.
    **NOTE:** SyncEvent::QueueOverflow references store::queue::QueueOverflowInfo — Agent 2 must move QueueOverflowInfo to scp-protocol.
12. `identity/mod.rs` — Pure: re-exports of pure parts. Stays: blocking, recovery, custody_migration, scpid.
13. `provenance/mod.rs` — Pure: DataProvenance, CounterpartyPolicy types.
14. `context/governance/mod.rs` — Pure: GovernanceAction, GovernanceEngine trait, compute_proposal_id (promote to `pub`). Stays: `pub mod timeout;`
15. `context/tools/mod.rs` — Pure: ToolSchema, ToolError. Stays: `pub mod invoke;`, `pub mod session;`

---

## Phase F: Known issues for Agent 2

### Harness artifacts with hardcoded paths (MUST update after rename)

These files use `include_str!()` or grep patterns with hardcoded `crates/scp-core/` paths that break after the rename to `crates/scp-runtime/`:

1. `crates/scp-testing/tests/integration/pipeline_wiring.rs` — two `include_str!` paths:
   - `include_str!("../../../../crates/scp-core/src/context/manager.rs")` → change to `crates/scp-runtime/src/context/manager.rs`
   - `include_str!("../../../../crates/scp-core/src/crypto/mls/provider.rs")` → change to `crates/scp-runtime/src/crypto/mls/provider.rs`
   - Also has a meta-test checking CLAUDE.md enforcement sections — verify it still passes.

2. `scripts/check-cross-layer.sh` — grep patterns reference `crates/scp-core/src/`:
   - Update to `crates/scp-runtime/src/`

3. `crates/scp-testing/tests/integration/ffi_conformance.rs` — points to `scp-ffi/` paths (unchanged by rename, but verify).

4. `scripts/check-sdk-coverage.py` — tree-sitter AST parsing. Check if it references `scp-core` anywhere.

### Why most `crate::` paths DON'T need changing

Moved files use `crate::trust::TrustError`, `crate::crypto::ucan::UcanError`, etc. After the
move, `crate::` refers to scp-protocol instead of scp-core. But because the module tree within
scp-protocol mirrors the original structure, these paths STILL RESOLVE. The analysis confirmed
311 internal references that work automatically. Only 4 outbound references need fixing.

### scp-identity imports

5 test files import `scp_identity::cache::TestClock`. Change to `scp_primitives::TestClock`:
- `trust/renewal.rs:191`
- `trust/aggregate.rs:456`
- `trust/challenge.rs:762`
- `trust/attestation.rs:1284`
- `crypto/ucan/nonce.rs:373`

No production code imports from scp-identity. scp-protocol does NOT depend on scp-identity.

### Cross-crate type issues

1. `ContextError::IntegrationFailed` embeds `IntegrationError` from economy/integration.rs (stays). Either move IntegrationError type to scp-protocol or restructure ContextError.
2. `SyncEvent::QueueOverflow` references `store::queue::QueueOverflowInfo` (stays). Move QueueOverflowInfo (pure data type) to scp-protocol.
3. `trust/mod.rs` re-exports `ProtocolRepositoryTrustBridge` from store — stays in scp-runtime's trust module only.

### Path and visibility fixes

4. `compute_proposal_id` — promote from `pub(crate)` to `pub`.
5. `trust/participation` — promote from `pub(crate)` to `pub`.
6. `jcs` and `serde_util` — moved to scp-protocol but referenced by staying files (sign.rs, app_sandbox.rs). scp-runtime imports from `scp_protocol::jcs` / `scp_protocol::serde_util`.
7. Moved `inner/mod.rs` must have `pub mod sign;` line REMOVED (sign.rs stays in scp-runtime).
8. Moved `outer/mod.rs` must have `pub mod ops;` line REMOVED (ops.rs stays in scp-runtime).

### Test extraction

9. 26 `#[cfg(test)]` blocks in moved files reference async modules (mint.rs, builder, etc.) that stay in scp-runtime. These tests cannot compile in scp-protocol because scp-protocol cannot depend on scp-runtime (circular). Options:
   a. Extract the test functions to scp-runtime integration tests (preferred)
   b. Delete the tests from scp-protocol and rely on scp-runtime's integration test coverage

   The 26 tests are in: validate.rs (12), close.rs (3), memory_scope.rs (3), standing.rs (3), majority.rs (3), multisig.rs (3), unanimity.rs (3), governance/mod.rs (1), wrapping.rs (1), encrypt.rs (1), envelope/validation.rs (1).

---

## Phase G: Facade completeness enforcement

### CI script: `scripts/check-facade-completeness.sh`

```bash
#!/usr/bin/env bash
# Verify scp-core facade re-exports all public items from scp-protocol and scp-runtime.
# Fails if any public module in either crate is not accessible through scp-core.
set -euo pipefail

# Get public modules from scp-protocol
protocol_mods=$(cargo doc --package scp-protocol --no-deps 2>/dev/null && \
  find target/doc/scp_protocol -maxdepth 1 -name "*.html" -exec basename {} .html \; | sort)

# Get public modules from scp-runtime
runtime_mods=$(cargo doc --package scp-runtime --no-deps 2>/dev/null && \
  find target/doc/scp_runtime -maxdepth 1 -name "*.html" -exec basename {} .html \; | sort)

# Get public modules from scp-core
core_mods=$(cargo doc --package scp-core --no-deps 2>/dev/null && \
  find target/doc/scp_core -maxdepth 1 -name "*.html" -exec basename {} .html \; | sort)

# Check that every protocol/runtime module appears in core
missing=0
for mod in $protocol_mods $runtime_mods; do
  if ! echo "$core_mods" | grep -q "^${mod}$"; then
    echo "MISSING from scp-core facade: $mod"
    missing=$((missing + 1))
  fi
done

if [ "$missing" -gt 0 ]; then
  echo "ERROR: $missing modules not re-exported through scp-core facade"
  exit 1
fi
echo "Facade completeness check passed."
```

### Structural test: `crates/scp-core/tests/facade_completeness.rs`

```rust
//! Verifies the scp-core facade correctly re-exports key types from both
//! scp-protocol and scp-runtime. If a type is added to either crate but
//! not wired through the facade, this test fails to compile.

// Protocol types (from scp-protocol)
use scp_core::trust::TrustError;
use scp_core::crypto::ucan::UcanError;
use scp_core::crypto::sender_keys::SenderKey;
use scp_core::context::ContextState;
use scp_core::envelope::EnvelopeError;
use scp_core::bridge::BridgeMode;
use scp_core::economy::EconomicPolicy;
use scp_core::provenance::DataProvenance;

// Runtime types (from scp-runtime)
use scp_core::crypto::mls::MlsCryptoProvider;
use scp_core::crypto::ucan::mint::mint_ucan;
use scp_core::store::ProtocolRepository;

#[test]
fn facade_exposes_protocol_types() {
    // These just need to compile — the use statements above verify the facade.
    let _ = std::any::type_name::<TrustError>();
    let _ = std::any::type_name::<UcanError>();
    let _ = std::any::type_name::<SenderKey>();
    let _ = std::any::type_name::<ContextState>();
    let _ = std::any::type_name::<EnvelopeError>();
    let _ = std::any::type_name::<BridgeMode>();
    // Verify runtime types are also accessible
    let _ = std::any::type_name::<MlsCryptoProvider>();
}
```

This test is a compile-time check — if any re-export path breaks, the test fails to compile, not at runtime. Add types as they're created.

---

## Phase H: Commit

```
git add -A
git commit -m "refactor: extract scp-protocol + rename scp-core to scp-runtime + create facade

Three-crate split: scp-protocol (pure sync ~82K lines), scp-runtime
(async orchestration, renamed from scp-core), scp-core (facade with
explicit wrapper modules merging both). Zero downstream API changes.

Does not compile yet — compilation fixes in next commit.

Partial implementation of #1446."
```

Push: `-u origin refactor/scp-protocol-extraction`

---

## Phase I: Update artifacts (Agent 2 scope, after compilation works)

- `.docs/architecture.md` §2.1 — add scp-protocol, update scp-core description
- `.docs/architecture.md` §2.2 — update dependency graph
- `CLAUDE.md` project map — update crate descriptions

---

## What NOT to move

- `crypto/mls/` — OpenMLS runtime
- `crypto/ucan/mint.rs` — async KeyCustody
- `crypto/sender_keys/key_protocol.rs` — async KeyCustody
- `crypto/access_keys/wire.rs`, `lifecycle.rs` — async
- `crypto/agent_binding_tests.rs` — test infrastructure
- `context/manager.rs`, `builder.rs`, `ttl.rs`, `export_import.rs`, `standing.rs`, `app_sandbox.rs`, `policy.rs`
- `context/providers/` — async persistence
- `context/governance/timeout.rs` — tokio
- `context/tools/invoke.rs`, `session.rs` — async
- `economy/credentials.rs`, `integration.rs`, `adapter.rs`, `receipt.rs` — async (RPITIT)
- `discovery/addressing.rs`, `search.rs`, `did_capabilities.rs`, `bootstrap.rs`, `dht_context.rs` — async
- `envelope/inner/sign.rs`, `envelope/outer/ops.rs`, `envelope/pseudonym.rs` — async
- `sync/days_offline.rs`, `hours_offline.rs`, `weeks_offline.rs` — async
- `bridge/oauth.rs`, `bridge/credentials.rs` — async
- `store/` — async persistence
- `identity/blocking.rs`, `recovery.rs`, `custody_migration.rs`, `scpid.rs` — async
- `event_log/` (scp-runtime internal) — async
- `metrics.rs`, `well_known.rs` — runtime
- `crates/scp-ffi/wasm/` — separate crate, don't touch
