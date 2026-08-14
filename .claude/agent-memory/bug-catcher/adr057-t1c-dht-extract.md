---
name: adr057-t1c-dht-extract
description: CLEAN double-zero of ADR-057 T1c-a DHT-transport extraction into scp-dht crate (branch feat/adr057-t1c-scp-dht @908daf5ce)
metadata:
  type: project
---

# ADR-057 T1c-a — DHT transport → scp-dht crate (CLEAN)

Range c102f8222..908daf5ce (3 commits: 6932d2fbf extract, 427a6c3f8 review-batch, 908daf5ce hygiene). Prior pass @427 CLEAN. Re-review scoped to top hygiene commit's one real code change.

**Change:** deleted private `DidDht::verify_bep44_signature` wrapper (scp-identity/src/dht.rs) + inlined sole caller to `scp_dht::verify_bep44_signature(&public_key, &record.signature, &record.value, record.seq)?;` (dht.rs:959). Also deleted duplicate test `bep44_signable_format_is_correct` + user-agent `scp-identity/0.1.0`→`concat!("scp-dht/",env!("CARGO_PKG_VERSION"))`.

**Verified CLEAN (no defects):**
- (a) inlined args EXACTLY match wrapper's (order+types): `&[u8;32],&[u8;64],&[u8](Vec deref),u64`. extract_public_key→[u8;32], DhtRecord.signature=[u8;64], .value=Vec<u8>, .seq=u64.
- (b) `?` fail-closed preserved: scp_dht returns Result<(),DhtError>; `From<scp_dht::DhtError> for IdentityError` (lib.rs:295) maps `Bep44SignatureInvalid(msg)→Self::Bep44SignatureInvalid(msg)` — IDENTICAL to old wrapper's `.map_err(IdentityError::from)`.
- (c) wrapper had EXACTLY one caller (dht.rs:973 `Self::` form @427). resolution.rs:188 + resolver.rs:224 ALREADY call scp_dht::verify_bep44_signature DIRECTLY — inline makes dht.rs consistent w/ siblings.
- (d) deleted test is dup: scp-dht/src/lib.rs:101 has bep44_signable_format_is_correct + 3 more verify tests (roundtrips/tampered_value/tampered_seq). scp-dht coverage SUPERSET of what identity had.
- (e) `cargo test -p scp-dht` 9/9 green; `-p scp-identity` 199/199 green; clippy -D warnings both crates clean.

No regression in range. GATES PASS.
