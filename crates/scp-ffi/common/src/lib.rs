//! Shared types for SCP FFI bridges.
//!
//! Three module groups:
//!
//! - **`validate`** — Input validation (always available, no external deps).
//!   Used by all FFI bridges (`PyO3`, napi-rs, `UniFFI`).
//!
//! - **`petname_helpers`** (behind `resolvers` feature) — Shared petname/handle/
//!   address-resolution helpers: JSON serialization, `HandleTarget` parsing,
//!   `HandleEntry` conversion, `HandleQuerier` impl, global singletons.
//!
//! - **Resolver adapters** (behind `resolvers` feature) — Bridge `scp-core`'s
//!   validation traits to the FFI runtime. Requires scp-core, scp-identity,
//!   tokio.
//!
//! See §3.10.10, §9.5, §7.4.1, §22.3.1, §22.4, §22.8 in `.docs/specs/`.

pub mod bridge_state;
pub mod error_codes;
pub mod outlet_id;
pub mod ucan_errors;
pub mod validate;

mod bridge_id;
pub use bridge_id::generate_bridge_id;

// Canonical §18.4.1 context-ID generator — shared across all FFI
// bridges so `Scp::context_create` cannot regress to non-hex shapes
// (see ADR-048 §7a for the UniFFI regression that motivated the
// extraction).
mod context_id;
pub use context_id::generate_context_id;

// Canonical handleless transport-status triple — shared across all
// FFI bridges so the no-handle-supplied `transport_status()` probe
// cannot diverge across `PyO3`, napi-rs, and `UniFFI`
// (see ADR-048 §7a).
mod transport_status;
pub use transport_status::handleless_transport_status;

// ---------------------------------------------------------------------------
// HTML escaping for event output (XSS prevention)
// ---------------------------------------------------------------------------

/// Escapes HTML-special characters in event output strings.
///
/// Prevents XSS when event output (which may contain attacker-controlled
/// strings from consequence rules, capability names, or member DIDs) is
/// inserted into DOM via `innerHTML` or similar mechanisms.
///
/// Replaces:
/// - `&` → `&amp;`
/// - `<` → `&lt;`
/// - `>` → `&gt;`
/// - `"` → `&quot;`
/// - `'` → `&#x27;`
///
/// This function is used by all FFI bridges (`PyO3`, napi-rs, `UniFFI`)
/// to sanitize event strings before returning them to callers.
#[inline]
#[must_use]
pub fn html_escape_event_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#x27;"),
            _ => result.push(ch),
        }
    }
    result
}

// Shared callback-custody byte/string parsing helpers (behind the `custody`
// feature). Requires scp-platform for the typed return values. Used by the
// PyO3, napi-rs, and UniFFI CallbackKeyCustody adapters; NOT folded into
// `resolvers` because these are pure byte/string ops far lighter than the
// resolver stack. See ADR-006.
#[cfg(feature = "custody")]
pub mod custody_parse;

// Shared attestation construction pipeline for all FFI bridges.
// Requires scp-core + scp-identity (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod attestation;

// Self-contained bridge instance replacing process-global OnceLock singletons.
// Requires scp-core (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod bridge_instance;

// Re-export the public bridge-instance surface so callers do not need to
// `use scp_ffi_common::bridge_instance::CoreFields`.
#[cfg(feature = "resolvers")]
pub use bridge_instance::{
    AllowlistGuardError, BridgeInstanceCore, CoreFields, HandleAffinityError, LifecycleError,
    ShutdownError, ShutdownOutcome, TransportLockError, UNSET_INSTANCE_ID,
};

// Shared runtime helpers (key resolver, event log provider backed by the
// durability-only `scp_platform::in_memory::InMemoryStorage`, ADR-062 §0).
// Requires scp-core + scp-platform (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod bridge_runtime;

// Bridge credential-store selection seam shared by all three FFI bridges
// (ADR-062 §Decision 5, SCP-CAPINJECT-009). The `FfiCredentialStore` enum
// dispatches between the real durable backend and a testing-only in-memory
// double. Requires scp-core (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod credentials;

// Crash-safe per-stream `monotonic_seq` grant counter (SCP-OUT-034 AC31) shared
// by all three bridges. Persists the cursor to durable `Storage` so an SDK
// restart never regresses the §5.4.5 credit-grant sequence. Requires
// scp-platform (behind `resolvers`, which always pulls it in).
#[cfg(feature = "resolvers")]
pub mod outlet_stream_credit;

// Bridge-agnostic pieces of the §5.4.5 cross-context streaming-saga FFI surface
// (SCP-OUT-047): the per-instance registry value, the chunk serialize/terminal
// step, and the ADR-056-chokepoint key-bearing truncated-close recovery driver.
// Shared so the three bridges' streaming-saga poll/recover wiring cannot drift.
// Requires scp-core (behind `resolvers`, which always pulls it in).
#[cfg(feature = "resolvers")]
pub mod streaming_saga;

// Shared context-parameter builder for all FFI bridges.
// Requires scp-core (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod context_params;

// Canonical event-log filter shared across PyO3, napi-rs, and UniFFI.
// Pins `after_sequence` / `before_sequence` / `event_type` / `actor_did` /
// `limit` semantics so the three bridges cannot drift. Requires scp-core
// for `scp_event_log::Event` (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod event_log;

// Trust store shared across PyO3, napi-rs, and UniFFI bridges.
// Requires scp-core (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod trust_store;

// Canonical §6.2.4 SagaError decomposition shared across PyO3, napi-rs, and
// UniFFI. Pins the `RateLimited → Option<u64>` read, the `None`-never-`0` rule,
// and the `SCP-SAGA-{code}` formatting in ONE place so the three bridges'
// `map_saga_error` cannot drift. Requires scp-core for
// `scp_core::context::supervisor::SagaError`, so it sits behind the `resolvers`
// feature alongside the other scp-core-dependent adapters.
#[cfg(feature = "resolvers")]
pub mod saga_errors;

// Shared broadcast key-distribution value-shape helpers (§5.14.2). The
// Grant→sealed-JSON and sealed-JSON→raw-key seams are identical across PyO3,
// napi-rs, and UniFFI; extracted here so the hand-populated author_did/context_id
// echo cannot drift. Requires scp-core (behind `resolvers`).
#[cfg(feature = "resolvers")]
pub mod broadcast;

// Shared signed-context-export verifying-key resolver (§23.16.8, ADR-050).
// Local-custody-first then DID-resolver (#active/#agent) fallback. Closure-based
// so each bridge keeps its own custody accessor and error type. Requires
// scp-core + ed25519-dalek (behind `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod export_verify;

// Shared message-send persona-source seam (ADR-039 Enforcement-Stack Layer 2).
// The `PersonaSource` callable + `ResolvedMessageSigner` atomic (key, persona)
// pair, injected per bridge instance and consulted at each native bridge's
// send site. Requires scp-core (MessageSigner) + ed25519-dalek (behind
// `resolvers`). There is no `scp-ffi` WASM bridge (`crates/scp-ffi/wasm` does
// not exist); the separate browser WASM client (`scp-client` / `scp-client-wasm`)
// provisions no agent key and does not route sends through scp-core's
// `MessageSigner`/`CoreFields`, so this seam is inapplicable there until
// `scp-client` gains agent-key custody (a real gap to revisit under RFC #2242).
#[cfg(feature = "resolvers")]
pub mod persona;

// All resolver types below require the `resolvers` feature (scp-core, scp-identity, tokio).
#[cfg(feature = "resolvers")]
mod resolvers;

#[cfg(feature = "resolvers")]
pub use resolvers::*;

// Discovery result mapping (ContextDiscoverySource → trust/resolution metadata).
// Requires scp-core types.
#[cfg(feature = "resolvers")]
pub mod discovery;

// Relay-backed reconnection driver (ADR-029 reconnection-driver
// addendum). Implements SyncPhaseDriver (Tier 1) / SnapshotTransport
// (Tier 2) / ResetTransport (Tier 3) over a TransportManager (relay-client
// retrieval) + Supervisor (actor-owned reconnection state). The driver
// lives at the FFI/SDK layer because the actor's ContextTransportProvider
// is send-only; buffered-message retrieval is owned by TransportManager.
// Requires scp-core + scp-transport (behind `resolvers`).
#[cfg(feature = "resolvers")]
pub mod reconnect;

// Shared periodic suppression-detection heartbeat scheduler (§9.9.2). Spawned
// alongside the relay subscribe loop at the FFI/SDK boundary, where the signing
// key lives; routes sends through Supervisor::send_heartbeat. Same layer and
// rationale as the reconnection driver. Requires scp-core + scp-transport +
// ed25519-dalek (behind `resolvers`).
#[cfg(feature = "resolvers")]
pub mod heartbeat_scheduler;

// Shared petname/handle/address-resolution helpers (behind the `resolvers` feature).
#[cfg(feature = "resolvers")]
pub mod petname_helpers;

// Shared test helpers for FFI bridge tests (behind the `testing` feature).
#[cfg(feature = "testing")]
pub mod test_helpers;

// Shared relay/node startup code for FFI bridges that need to spawn servers.
// Requires scp-transport, scp-node, scp-platform, tokio.
#[cfg(feature = "server")]
pub mod server;

// Shared DHT client for all FFI bridges (ADR-062 §Decision 1). `scp-dht` is a
// non-optional dependency compiled with `production-dht`, so the real
// `PkarrDhtClient` — and therefore `FfiDhtClient` — is always available; the
// in-memory nullifier arm is `testing`-gated. Unconditional so every bridge
// shares one DHT type regardless of which feature set it enables.
pub mod dht;
