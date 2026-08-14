---
name: adr057-t1c-scp-dht-extraction-6932d2fbf
description: ADR-057 T1c DHT transport extraction into scp-dht + DhtError refactor (feat/adr057-t1c-scp-dht, HEAD 6932d2fbf) -- ZERO FINDINGS
metadata:
  type: project
---

# ADR-057 T1c: extract scp-dht + DhtError error-channel (6932d2fbf on c102f8222) -- 2026-07-03 -- ZERO FINDINGS

Behavior-preserving transport-extraction refactor. Range c102f8222..6932d2fbf. Reviewed all 6 checklist items CLEAN.

- **verify_bep44_signature byte-equivalent**: new home crates/scp-dht/src/lib.rs:79 identical to origin (c102f8222 dht.rs:2669) — same `VerifyingKey::from_bytes` / `Signature::from_bytes` / `verify_strict` / exact `bep44_signable` format (`"3:seqi"+seq+"e1:v"+len+":"+val`). Only error type IdentityError→DhtError. DidDht::verify_bep44_signature (dht.rs:817) rewraps via `.map_err(IdentityError::from)`. All 3 prod read-path callers fail-closed: resolution.rs:187 (`if let Err ... continue` — rejects relay record), resolver.rs:224 (`?`), dht.rs:981 (`?`).
- **pkarr gateway RESOLVE validation preserved + unskippable**: crates/scp-dht/src/dht_client/pkarr_client.rs resolve_via_gateway still verifies sig against the REQUESTED public_key before `Ok(Some(DhtRecord))`, `continue`s on Err. Only change `crate::dht::verify_bep44_signature`→`crate::verify_bep44_signature` (same fn, now crate root). Attacker gateway can't forge (no valid Ed25519 sig for key it doesn't control). seq i64→u64 unwrap_or(0)-then-verify unchanged.
- **From<DhtError> for IdentityError** (scp-identity/src/lib.rs:293): 1:1 identically-named — DhtPublishFailed→DhtPublishFailed, DhtResolveFailed→DhtResolveFailed, Bep44SignatureInvalid→Bep44SignatureInvalid. No variant collapse, no classification drift. Original dht_client produced exactly these 3 IdentityError variants directly. MigrationPublishFailed boxes `source` verbatim (no inner-variant match; phase set by control-flow not error).
- **Cargo surface**: scp-dht deps = tokio/thiserror/ed25519-dalek/z-base-32/tracing (always) + mainline/reqwest (optional, production-dht). reqwest default-features=false rustls-tls. default=[]. Cargo.lock adds ONLY scp-dht (no new external pkg). production-dht forwards: scp-identity/production-dht=["scp-dht/production-dht"]; scp-node + scp-ffi/uniffi enable scp-dht/production-dht directly → gateway sig-verify path IS compiled into prod.
- **Deleted scp-identity re-exports** (verify_bep44_signature/DhtClient/InMemoryDhtClient/PkarrDhtClient): nothing security-relevant orphaned; every consumer (scp-runtime/scp-node/scp-testing/scp-ffi all bridges) now imports `scp_dht::` directly. No broken `scp_identity::verify_bep44_signature` caller.
- **check-no-shim-reexports.sh**: additive only — adds `scp_dht` to closed crate set + owning_dir mapping crates/scp-dht/src/; doc/echo strings updated 4→5 crates. No weakening.
