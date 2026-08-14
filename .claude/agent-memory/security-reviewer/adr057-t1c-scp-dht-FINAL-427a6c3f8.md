---
name: adr057-t1c-scp-dht-FINAL-427a6c3f8
description: ADR-057 T1c extract scp-dht transport crate + review-fix commit — FINAL state review, ZERO findings
metadata:
  type: project
---

# ADR-057 T1c scp-dht extraction FINAL (branch feat/adr057-t1c-scp-dht, HEAD 427a6c3f8 atop 6932d2fbf, base c102f8222) -- 2026-07-03 -- ZERO FINDINGS

Range c102f8222..427a6c3f8. Behavior-preserving transport extraction into new native leaf crate scp-dht (BEP44 DHT transport) + review-fix batch. 58 files, +457/-211.

**(a) verify_bep44_signature at new home (scp-dht/src/lib.rs:77):** BYTE-IDENTICAL to origin (scp-identity/src/dht.rs) — same verify_strict, same preimage `bep44_signable` (3:seqi<seq>e1:v<len>:<val>), only IdentityError→DhtError variant rename. Inherent method DidDht::verify_bep44_signature now delegates to scp_dht::verify_bep44_signature + `.map_err(IdentityError::from)`. **Fix-commit deleted DidDht::bep44_signable inherent wrapper** — it was ONLY a signable-payload constructor (not a verifier); sole caller (publish_document) now calls scp_dht::bep44_signable directly; NO production caller lost verification. All 3 attacker-facing read-path callers fail-closed: pkarr gateway resolve (pkarr_client.rs `crate::verify_bep44_signature(public_key,...)` verifies against REQUESTED key before trusting gateway, unskippable — faithful move, only `crate::dht::`→`crate::`), resolution.rs verify_and_deserialize, resolver.rs validate_dht_result (receives `dht_result.map_err(IdentityError::from)` BEFORE validation). mod.rs + pkarr_client.rs diffed vs origin = byte-identical except IdentityError→DhtError.

**(b) From<DhtError> (scp-identity/src/lib.rs):** 1:1 message-preserving, all 3 variants identically-named (DhtPublishFailed/DhtResolveFailed/Bep44SignatureInvalid), msg carried verbatim.

**(c) scp-dht Cargo surface:** NO new external dep (Cargo.lock adds only scp-dht package; mainline/reqwest/z-base-32/tracing/ed25519-dalek/thiserror/tokio all pre-existing, moved from scp-identity). default=[]. production-dht = [dep:mainline, dep:reqwest, dep:z-base-32, dep:tracing] = exactly the pkarr stack. reqwest default-features=false features=[rustls-tls] preserved. bep44_signable/verify_bep44_signature in lib.rs are NON-gated (only ed25519-dalek). scp-identity production-dht forwards to scp-dht/production-dht. scp-node + uniffi enable scp-dht production-dht (prod). Consumers import scp_dht:: directly (no shim re-exports; deleted scp-identity re-exports orphan nothing).

**(d) release.yml:** scp-dht added to version-verify list + publish sequence, positioned after scp-did BEFORE scp-identity (leaf crate, correct dep order — no publishable dependent published before it). Not publish=false. Dry-run summary now 17 crates. No publishable dep missing.

**(e) enforcement additive-only:** check-no-shim-reexports.sh adds scp_dht to closed set (crates array + owning_dir + docs) = EXPANDS coverage, weakens nothing. ci.yml/docs.yml add scp-dht path filters (additive). CLAUDE.md = doc-only project-map edit.

**Observation (non-finding, PRE-EXISTING, carried verbatim):** pkarr_client.rs build() sets reqwest `user_agent("scp-identity/0.1.0")` — now stale crate name (lives in scp-dht) + hardcoded 0.1.0 vs actual 0.1.0-beta.2. Benign outbound fingerprint string, not introduced by this diff (unchanged from origin). No security impact.
