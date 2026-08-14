---
name: adr057-t1-primitives-dissolve
description: ADR-057 T1 scp-primitives dissolve / scp-did extraction — security review, FINAL state cc23e51f6 (canonicality hardening; zero findings)
metadata:
  type: project
---

# ADR-057 T1 — dissolve scp-primitives; extract wasm-safe scp-did

## HEAD cc23e51f6 — uniform z-base-32 canonicality hardening (re-reviewed clean) 2026-07-03
Delta since 280983dd7 = 3 commits (5b35cb9aa, c1ef1394d, cc23e51f6). ZERO CRITICAL/HIGH/MEDIUM.
- c1ef1394d: scp-did `extract_public_key_from_did` gains z-base-32 canonicality round-trip
  (re-encode `zbase32::encode(bytes)` + byte-exact compare vs input suffix; lowercase, no case fold).
  Closes trailing-bit-padding non-injectivity (16 alt encodings/key → petname-squat / log-spoof).
  Fail-closed (Err, no panic). Mirrors native scp_identity::dht::extract_public_key verbatim.
- cc23e51f6: 3 native decoders delegated onto the single hardened parser — ALL strictly STRONGER, no weakening:
  1. BridgeDidResolver::resolve_public_key (UCAN path) → scp_did::extract_public_key_from_did,
     err→CoreUcanError::MalformedToken. Old hand-roll had NO canonicality (bug); now rejects non-canonical.
  2. DidDht::verify (self-cert) → extract_public_key free fn (same file). Input-class table old-vs-new:
     wrong-prefix/non-zbase32/canonical-match/canonical-mismatch = SAME; non-canonical-of-matching-key
     = old TRUE(bug)→new FALSE; len!=32 = old maybe-true→new FALSE (correct, 32-byte ed25519 only). No weakening.
  3. app_sandbox::extract_ed25519_pubkey_from_did: REAL bug fix — old stripped only "did:dht:" (kept 'z')
     →33 bytes→rejected EVERY valid did:dht (masked, tests only did:key/web). Now delegates → works + canonical.
- (c) app_sandbox: extraction feeds VerifyingKey::from_bytes → verify(&canonical,&sig) at verify() (lib ~295).
  Extraction alone grants NOTHING; ed25519 sig verify still required. DID self-certifying → sound.
- (b) did:key hex UNREACHABLE in shipped artifacts CONFIRMED. scp-ffi-common `testing=["resolvers","scp-did/testing"]`
  gates did:key. All 3 bridges' `[dependencies]` use scp-ffi-common features=["custody"](+default resolvers), NO testing;
  the `["testing","custody"]` line is `[dev-dependencies]` only (pyo3:71, napi:62, uniffi:71+). Bridge own `testing`
  =scp-core/testing (transitively →scp-did/testing) but not in default (=server). resolver=2 → dev-dep features not
  unified into normal graph. scp-did default=[]. No `default` anywhere enables testing. Shipped .so/.dylib/.node = did:key compiled out → falls to "unsupported DID format" Err.
- Parity complete: ALL non-test production `zbase32::decode` sites (scp-did:123, dht.rs:2732) enforce canonicality.
  BridgeDidResolver by_kid uses trait-default→resolve_public_key→hardened. DispatchDidResolver both arms covered.
- 5b35cb9aa: release.yml drops publish=false scp-client-wasm from publish list+dry-run (correctness; cargo publish on
  publish=false=hard error). check-no-shim gate `//*) [[ *'*/'* ]] || continue` STRENGTHENS (fewer skips, over-report-safe).
- verify_ed25519_signature single home scp-crypto/src/lib.rs:34 (unchanged). No new unwrap/expect in non-test code.
- OBSERVATION (cosmetic): resolvers.rs:623 doc "Fallback resolver: z-base-32 decode only, no document validation"
  now stale — Bridge variant enforces canonicality. Not a security issue.

Branch `refactor/dissolve-primitives-split-identity`. FINAL review at HEAD **280983dd7**
(full range `86519aa6f..HEAD`, 8 commits). Behavior-preserving crate-topology refactor.
**ZERO security findings (CRITICAL/HIGH/MEDIUM).** Supersedes the earlier 81ef76c56 / 033a12d4c reviews.

## Final-polish commit 280983dd7 (re-verified clean)
- Comment-filter added to check-no-shim-reexports.sh: strips `file:lineno:` prefix, trims leading
  ASCII whitespace, skips lines whose trimmed content starts with `//`. SOUND — any `//`-prefixed
  line genuinely does NOT compile as a re-export in Rust (line comments win to EOL). Block comments,
  unicode leading whitespace (U+00A0 etc., not in POSIX `[:space:]`), and code-before-comment all fail
  in the OVER-REPORT (safe) direction — none can HIDE a real `pub use scp_x`. Only residual evasion =
  multi-line-split `pub use\n  scp_x` (grep is line-based) — DOCUMENTED in-script + backstopped by
  rustfmt normalization + rustc acyclicity. Gate runs green on tree.
- Template dep hygiene: cross-context-bridge dropped scp-identity + scp-platform/testing + scp-event-log/testing
  (3 dead lines, all unreferenced in src — grep clean), added scp-did. Net REMOVES two testing-feature edges.
  personal-relay scp-core→scp-clock (SystemClock only; scp_core unref after). rust-client dropped
  scp-event-log/testing, added scp-did. All `publish=false` examples.
- Cargo.lock: NO external pkg add/remove/version-change — only intra-workspace dependency-edge reassignment
  (hex/base64/bs58/serde_json/serde_bytes/thiserror/z-base-32 moved from scp-protocol/primitives stanza to
  scp-did stanza). scp-crypto tightened to ed25519-dalek only; scp-clock zero deps.
- did:key testing gate re-confirmed: ALL `features=["testing"]` scp-did edges under `[dev-dependencies]`
  (resolver=2 → not in normal build graph). No `default` enables testing. scp_event_log::DID public re-export
  became private `use` — no external consumer (grep NONE). Non-issue.

## Topology
- scp-primitives DISSOLVED (dir + name gone from workspace/lock/code — grep clean).
  - `src/crypto.rs` → **scp-crypto/src/lib.rs** (byte-identical modulo 4-line crate header).
  - `src/time.rs` → **scp-clock/src/lib.rs** (byte-identical modulo header).
  - `src/identity.rs` → **scp-did/src/lib.rs** (code body byte-identical modulo header + new `pub mod`/re-export).
- scp-protocol `identity/document.rs` + `identity/did_attestation.rs` → **scp-did/src/{document,attestation}.rs**
  as a PURE `DidDocumentError`→`DidError` rename + import-path fixups. No logic change.

## Security-critical, verified
- (a) `verify_ed25519_signature`: single canonical home = scp-crypto/src/lib.rs:34, body unchanged.
  (Other same-named fns in scp-runtime wire.rs / scp-protocol sender_keys / scp-testing are PRE-EXISTING
  independent local helpers, untouched.)
- (b) `extract_public_key_from_did` single home scp-did/src/lib.rs:120; z-base-32/32-byte/format-reject unchanged.
  `decode_multibase_key` (document.rs) z-prefix + base58btc + 32-byte checks byte-identical.
  did:key:{hex} branch still gated `#[cfg(any(test, feature = "testing"))]` (lib.rs:134).
- (c) serde stability intact: DidError is a thiserror type (never serialized); no `#[serde]` attr changed;
  document.rs hex custom ser/de + attestation to/from_service_entry unchanged.

## did:key testing gate — UNREACHABLE IN PRODUCTION (independently re-walked)
- scp-did `default = []`; NO default feature anywhere enables `testing`.
- Every always-on `scp-did = {features=["testing"]}` is under `[dev-dependencies]`
  (scp-client-wasm, scp-client, scp-protocol, scp-mls). Real `[dependencies]` never enable testing.
- `testing` forwards (scp-protocol/mls/event-log/core) are opt-in feature defs only.
- scp-client-wasm (browser prod surface): `[dependencies]` scp-did has NO testing → wasm build rejects did:key.
- Scaffolds/templates enable scp-event-log/testing → scp-did/testing (thus did:key). This is
  **pre-existing + behavior-preserving** — OLD scaffold reached it identically via
  scp-event-log/testing → scp-primitives/testing. Both are `publish = false` examples, not prod artifacts.
- NEW: ci.yml wasm-check now compiles scp-did (+clock/crypto/mls/client-wasm) on wasm32 default-features →
  mechanically backstops the wasm-safe / did:key-excluded claim. Positive pattern.

## Gate script check-no-shim-reexports.sh — CLEAN
- Closed 4-crate set (scp_clock/crypto/did/mls), no user input → no injection; `set -euo pipefail`;
  fails-closed (any match → exit 1); `|| true` correctly prevents set-e false-kill on no-match grep.
- Both prior low-sev observations FIXED: nested `src/` now covered via `find crates -type d -name src`
  (catches scp-ffi/{common,napi,uniffi}); word-boundary regex `(::)?scp_x\b` catches whole-crate/as-rename/path forms.
- Exotic laundering (pub type / package= / multi-hop) explicitly out-of-scope with SOUND rationale
  (acyclicity=rustc, wasm-fence=compile job, dep rules=check-protocol-deps.sh). Well-reasoned, not non-convergent.

## Manifests/lock/enforcement/(e)/(f)
- Cargo.lock: only local crates added (scp-clock/crypto/did) + scp-primitives removed. NO new external dep.
- fuzz/Cargo.lock new externals (arc-swap, parking_lot, instant, fluvio-wasm-timer, etc.) ALL already in
  base main lock — transitive deps of newly-added fuzz deps scp-mls/scp-platform. No new supply-chain surface.
- hex promoted optional→normal dep in scp-did: CORRECT (document.rs uses hex unconditionally in serde);
  did:key hex::decode still cfg-gated. Benign.
- No feature-default flip; no pin widening.
- Enforcement touches: check-no-mutable-globals.sh + check-protocol-deps.sh + .clippy.toml = comment-only
  (scp_primitives→scp_clock). ci.yml/docs.yml path filters additive. ci.yml registers the new gate + strengthens
  wasm-check. CLAUDE.md adds check-no-shim-reexports.sh to enforcement list (sanctioned "new coverage").
- release.yml publish order dependency-correct (clock/crypto/did leaves → platform → event-log → protocol →
  identity → mls → client → client-wasm → runtime). `--allow-dirty` pre-existing.
