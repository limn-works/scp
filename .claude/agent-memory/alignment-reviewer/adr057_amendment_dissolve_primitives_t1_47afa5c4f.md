---
name: adr057-amendment-dissolve-primitives-t1-47afa5c4f
description: ADR-057 Amendment T1 (dissolve scp-primitives, extract scp-did) final gate @ 47afa5c4f — ALIGNED, 0 findings
metadata:
  type: project
---

# ADR-057 Amendment "Dissolve scp-primitives; extract scp-did" (T1) @ `47afa5c4f` (2026-07-02) — ALIGNED

Branch `refactor/dissolve-primitives-split-identity`, base `86519aa6f`, HEAD `47afa5c4f` (13-commit range, 373 files +3239/-2512). READ-ONLY code↔ADR fidelity review. **0 findings.**

**Why:** Retry after transient provider rate-limit; assess whole-document ADR-057 fidelity + ADR-055 consistency + artifact fidelity + anchors.

**How to apply:** If re-reviewing this branch, incremental diffs only. This was the full-range gate; all T1 claims verified true.

## What T1 did (all verified against code)
- Dissolved `scp-primitives` → `scp-clock` (0 deps, leaf) / `scp-crypto` (ed25519-dalek only) / `scp-did` (ed25519-dalek DIRECT + serde crates, NO scp-crypto edge — validates via `VerifyingKey::from_bytes`). scp-primitives dir GONE.
- Moved DID model out of BOTH scp-primitives AND scp-protocol (Slice-1a strays: identity/document.rs, did_attestation.rs) into scp-did. `DidDocumentError`→`DidError` (0 residual refs).
- Deleted `scp-runtime/src/crypto/mls/mod.rs` `pub use scp_mls` shim; no forbidden shims survive outside owner crates + scp-core facade.
- New gate `scripts/check-no-shim-reexports.sh`: closed crate set `{scp_clock,scp_crypto,scp_did,scp_mls}`, scp-core facade exempt, matches whole-crate/`::Item`/`as`-rename spellings.

## Declared behavior changes (T1 carve-out) — each matched EXACTLY
1. z-base-32 canonicality ported into `scp_did::extract_public_key_from_did` (lib.rs:120-149) — byte-exact re-encode+compare, mirrors native `scp_identity::dht::extract_public_key` (dht.rs:2722-2749). Pinned by cross-parser test `native_and_scp_did_parsers_agree_on_canonicality` (dht.rs:3394). Wasm reaches ONLY scp-did parser (event-log tree.rs:320, protocol claiming.rs:210/223).
2. THREE native did:dht decoders onto same guard, each the exact KIND ADR states:
   - `BridgeDidResolver` (resolvers.rs:80-87): delegates to scp_did parser — fail-CLOSED strictness.
   - `DidDht::verify` (dht.rs:2124-2134): delegates to same-file native extract_public_key — fail-CLOSED strictness.
   - `app_sandbox` (app_sandbox.rs:903-912): delegates to scp_did parser — fail-**OPEN** prefix-bug repair (old code stripped "did:dht:" not the 'z' → 33 bytes → rejected EVERY valid DID).
3. Local did:key gate in BridgeDidResolver (`#[cfg(not(any(test, feature="testing")))]`) — stops scp-did/testing riding in transitively via custody opt-ins (allow_in_memory_custody). Behavior-PRESERVING (shipped default-feature artifacts already accept only did:dht).
4. Python UCAN classifier repair (trust.py:103-118): prefixes now match actual scp-did format strings ("hex decode error"/"unsupported DID format"/"...not canonical"); old "hex decode failed"/"unsupported DID method" no longer matched = real repair. Conformance guard test added.
5. Issue-URL refs scrubbed from scp-did (github.com hits = IdentityLinkPlatform enum, legit).

## Structural/artifact fidelity
- Release = 16 publishable crates (release.yml:863); scp-client-wasm EXCLUDED (publish=false, commit 5b35cb9aa).
- ADR anchor `#amendment-2026-06-30-dissolve-scp-primitives-extract-scp-did` resolves. Prereq-3 struck+SUPERSEDED; Costs/risks, Prereq-2, crate graph all coherent.
- ADR-055 lives in phase-4.md (§ADR-055 heading), already "Amended by ADR-057" at :1472 — no contradiction.
- architecture.md (tree+layer diagram+completed-extractions prose), check-protocol-deps.sh (scp-primitives→scp-clock), worktree CLAUDE.md (3 FFI targets, new crate map) all updated.

## Immaterial observations (NOT findings)
- T1 bullet says deleted shim `pub use scp_mls::*` vs enforcement-map `pub use scp_mls::{…}` — same shim, cosmetic.
- Prereq-5 "covering the prereq-3 move" survives though Prereq-3 struck — coherent (move still happened, to scp-did).
- Crate-table scp-did "Owns" omits decode_multibase_key (real export, resolvers.rs:21 imports) — non-exhaustive list.

**T1c** (extract scp-dht transport layer) and **T2** (scp-client Storage wiring) are forward-only follow-ons; semantic blockers (error-taxonomy String vs IdentityError::ZBase32DecodeError; did:key test-scope) accurately enumerated in ADR.
