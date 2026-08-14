---
name: adr057-t1cb-parser-consolidation
description: ADR-057 T1c-b did:dht parser consolidation onto scp-did authority; ZERO FINDINGS at ebda42b1f
metadata:
  type: project
---

# ADR-057 T1c-b did:dht parser consolidation (branch feat/adr057-t1cb-parser-consolidation, HEAD ebda42b1f atop 0d4db22b5) -- 2026-07-03 -- ZERO FINDINGS

Range 0d4db22b5..HEAD = 3 files (dht.rs, lib.rs, ADR doc). `scp_identity::dht::extract_public_key` rewritten as thin wrapper: UNCONDITIONAL positive did:dht:z prefix gate (`strip_prefix("did:dht:").is_some_and(|s| s.starts_with('z'))`, NO cfg anywhere) then delegate to `scp_did::extract_public_key_from_did` (crates/scp-did/src/lib.rs:120) with `.map_err(IdentityError::InvalidDidFormat)`.

- (a) GATE LOAD-BEARING VERIFIED EMPIRICALLY: `cargo test -p scp-identity -p scp-mls --features scp-mls/testing extract_public_key_rejects_did_key_in_every_build` PASSES — co-selecting scp-mls/testing unifies scp-did/testing ON (scp-did/testing enabled by scp-client/scp-event-log/scp-mls/scp-protocol; scp-core/testing→scp-protocol/testing pulls it in CI all-features), so the linked scp-did ACCEPTS did:key:{hex}, and the wrapper's unconditional gate is the SOLE rejecter. scp-identity/testing is NOT even in the CI feature list (=["scp-platform/testing"], no scp-did) — a `cfg(feature="testing")` gate would be OFF in exactly the custody builds that need protection. Unconditional gate is the correct design, not over-engineering: it enforces a DIFFERENT property (did:dht-only) the authority deliberately does not, so NOT redundant re-check. Both untrusted callers fail-closed via `?`: relay_resolve (resolution.rs:167, FFI identity_resolve path) and DualLayerResolver::resolve (resolver.rs:473, UCAN issuer).
- (b) ACCEPTANCE SURFACE BYTE-IDENTICAL: old `encoded`=after "did:dht:z", new scp-did `suffix`=after "did:dht:z" — same decode/32-byte/re-encode-compare. Edge spellings all match old: `did:dht:` alone→reject, `did:dht:z` alone→InvalidDidFormat(0 bytes), uppercase `Z`→reject (starts_with('z') case-sensitive), NUL/unicode after z→decode-fail→InvalidDidFormat. Prefix-error message text IDENTICAL to old.
- (c) CANONICALITY gates every did:dht Ok path in scp-did (re-encode byte-exact vs suffix, lines 141-146); wrapper only forwards, cannot bypass. `verify` (dht.rs:2106) reaches it via is_ok_and (non-canonical→false).
- (d) ERROR-TAXONOMY FOLD SAFE: `IdentityError::ZBase32DecodeError` DELETED (lib.rs); zero residual Rust refs repo-wide (only ADR prose). All 3 FFI `From<IdentityError>` impls (pyo3 error.rs:390 IDENT_1001 catch-all, napi:189, uniffi:1085) bucketed both ZBase32DecodeError AND InvalidDidFormat into the same catch-all — no code change. Only message TEXT changes on decode/length/canonicality; sole surviving assertion `msg.contains("not canonical")` satisfied by scp-did wording.
- (e) DELETED private `DidDht::extract_public_key`: all 9 callers retargeted to free fn (identical gate+delegate), no prod validation lost. 5 extract_public_key tests pass; did:key-reject + decode-fail-maps-to-InvalidDidFormat + re-fork-guard added.
