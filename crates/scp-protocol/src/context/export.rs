//! Shared constants for the signed context-export preimage (§23.16.8, ADR-050).
//!
//! These live in `scp-protocol` (the pure, `wasm32`-compatible crate that holds
//! protocol constants independent of the async runtime) so that every consumer
//! of the signed context-export preimage binds the **same** scope discriminant
//! byte into the signed digest. The native runtime (`scp-runtime`) owns the
//! `ExportScope` enum and the `ContextExport` envelope and references these
//! constants here. Without a single source of truth, independent producers could
//! disagree on the byte value and produce mutually-unverifiable signatures.

/// Scope discriminant byte for a **full** context export, folded into the
/// signed snapshot preimage (§23.16.8, ADR-050).
///
/// The signed digest is
/// `SHA-256(CONTEXT_EXPORT_DOMAIN_SEPARATOR || [scope_tag] || JCS(snapshot))`,
/// where `scope_tag` is this byte for an `ExportScope::Full` export. Binding the
/// scope into the preimage means an attacker who flips a validly-signed
/// `Public` export's envelope scope to `Full` (or vice versa) causes the
/// verifier to recompute a different digest than the creator signed, so the
/// signature fails by construction — the invariant no longer rests on the
/// hollow-context argument.
///
/// **Stable wire value — MUST NEVER change once shipped.** It is part of the
/// signed preimage; changing it would silently invalidate every previously
/// produced export signature. New scopes take new, never-reused byte values.
pub const EXPORT_SCOPE_TAG_FULL: u8 = 0x00;

/// Scope discriminant byte for a **public** context export, folded into the
/// signed snapshot preimage (§23.16.8, ADR-050).
///
/// See [`EXPORT_SCOPE_TAG_FULL`] for the construction and the stability
/// guarantee. This byte tags an `ExportScope::Public` export.
///
/// **Stable wire value — MUST NEVER change once shipped.**
pub const EXPORT_SCOPE_TAG_PUBLIC: u8 = 0x01;
