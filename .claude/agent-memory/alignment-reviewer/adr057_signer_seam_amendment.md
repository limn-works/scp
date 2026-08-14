---
name: adr057-signer-seam-amendment
description: ALIGNED review of ADR-057 CRYPTO-22 signer-threading seam amendment (2026-08-03), branch adr-057-signer-seam
metadata:
  type: project
---

# ADR-057 Amendment "CRYPTO-22 identity-key signer-threading seam" (2026-08-03) — ALIGNED

Branch `adr-057-signer-seam` vs `origin/main` (merge-base `093c5afca`). Docs-only: +76 lines, ONE file (`.docs/adrs/ADR-057-in-browser-client-over-shared-mls.md`). New "## Amendment (2026-08-03)" appended after the merged 2026-08-01 attestation-model amendment.

**Why:** seam mechanization for CRYPTO-22 slices S3/S5 (how the identity signature reaches openmls's single leaf self-sign + a freshness-carrying resolver seam). Status: Proposed.
**How to apply:** if re-reviewing, this was a clean ALIGNED (0 blocking/material findings). Re-verify only if the amendment text changed.

Verified against origin/main (all TRUE):
- Docs-only, artifact-flow clean; frames itself as amending ADR-057, downstream of merged §9.5.2/§9.7.1 model — NOT a new parent decision. Does not reshape spec.
- Persona reconciliation FIXED: `signing_key_id` threaded as injected `SigningKeyId` (default `#active`) from the SAME send-path seam (`MessageSigner` enum supervisor.rs:1288 fuses key+persona so they can't disagree; UCAN analog `MintParams.signing_key_id` mint.rs:411). S5 threads param + deletes the `key_package_actor.rs:785` `SigningKeyId::Active` hardcode (confirmed exact line). Does NOT build a determiner / second `#agent` mint path → deferred to RFC #2242 (cited 4x). NO residual "no parameter threading now" contradiction.
- No overclaim: framed as signer-threading mechanism; explicitly does NOT claim agent accountability/enforcement (that's the merged parent + RFC #2242).
- Scope claim HOLDS: `#agent` at MLS/credential layer is cfg(test)-only. credential.rs Agent uses all inside `#[cfg(test)] mod tests` (line 177+) + 1 doc comment; `crates/scp-runtime/src/crypto/mls/` has ZERO Agent occurrences. Only two non-test `ScpCredential::new(...Active)` sites: `key_package_actor.rs:785` + `crypto/mls/provider.rs:615` make_credential — all other ScpCredential::new sites confirmed cfg(test).
- Supporting citations true: KeyCustody RPITIT `sign` (traits.rs:344, not dyn-safe → Arc<dyn> claim correct); `dispatch_broadcast_command_with_custody<C>` supervisor.rs:5858; `ScpMlsProvider` `type CryptoProvider = RustCrypto`; openmls 0.8.1 pinned in Cargo.lock; ScpIdentity `active_signing_key`/`agent_signing_key: Option<KeyHandle>`; DidCache `Staleness`/`DidResolutionResult`.
- GOTCHA (self-corrected during review): `MAX_ATTESTATION_KEY_RESOLUTION_STALENESS` (300s/5min), §9.7.1 checks 1-2, last-known-good Update grace — ALL already in merged spec (09-security-model.md:632-657). Amendment's "does not exist yet" = the CODE constant, not the spec value. Grep with a source-path filter misses spec presence; check `.docs/specs` separately.
