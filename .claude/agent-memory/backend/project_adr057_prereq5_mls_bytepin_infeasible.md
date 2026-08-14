---
name: adr057-prereq5-mls-bytepin-infeasible
description: ADR-057 Prereq-5 MLS Commit/Welcome byte-equality KAT is mechanically infeasible with openmls_rust_crypto 0.5.1; KeyPackage byte-pin IS feasible but needs invasive scp-mls provider injection
metadata:
  type: project
---

ADR-057 Prereq-5 (line 48) mandates a native-vs-wasm32 byte-equality KAT over "(i) a sample MLS commit/welcome wire blob" + "(iii) a credential/KeyPackage from the same DID". The `feat/adr057-test-stack` plan proposed a seeded `OpenMlsProvider` (fixed-seed `OpenMlsRand`) to make Commit/Welcome byte-deterministic. **That premise is FALSE — empirically proven.**

**Root cause (openmls_rust_crypto 0.5.1 + hpke-rs 0.6.0, the versions scp-mls resolves):**
- KeyPackage/leaf keygen (openmls-0.8.1 `key_packages/mod.rs:298`, `treesync/node/encryption_keys.rs:214`) draws `ikm = Secret::random(cs, provider.rand())` then `crypto.derive_hpke_keypair(cs, ikm)`. `derive_hpke_keypair` is a **pure KDF** (`openmls_rust_crypto-0.5.1/src/provider.rs:405`, no RNG). So KeyPackage bytes ARE deterministic given a seeded `rand()` + fixed SCP signature key. **KeyPackage byte-pin = feasible.**
- Commit (update_path) and Welcome encryption call `crypto().hpke_seal(...)` → `provider.rs:424 hpke_from_config()` builds a FRESH `Hpke::<HpkeRustCrypto>::new()` per call → `hpke-rs-0.6.0/src/kem.rs:30 kem::encaps` calls `hpke.random(len)` = **HpkeRustCrypto's OWN internal RNG, NOT `OpenMlsProvider::rand()`**. The `OpenMlsCrypto::hpke_seal` API takes no randomness param → **no seam** to inject a seed. **Commit/Welcome byte-pin = mechanically infeasible** without forking openmls_rust_crypto or hpke-rs (DOA-scale). Proven: two `hpke_seal` calls with identical inputs yield different `kem_output`.

**Also:** scp-mls `create_group`/`generate_key_package` (`crates/scp-mls/src/group.rs:426,924`) construct `InMemoryMlsProvider::default()` INTERNALLY (= `openmls_rust_crypto::OpenMlsRustCrypto`, `lib.rs:106`); `ScpMlsGroup` owns a concrete `provider` field. There is NO provider-injection seam — even the feasible KeyPackage byte-pin needs invasive generic-over-`P: OpenMlsProvider` (or a `testing`-gated seeded constructor) threaded through the fence-guarded shared crate.

**Consequence:** the stale KAT's structural-only treatment of Commit/Welcome ([[project-adr057-3-client-wasm]] worktree, `test/adr057-kat-and-adversarial`) was CORRECT about Commit/Welcome (they are genuinely non-deterministic); its only miss was leaving KeyPackage as structural when a seeded rand could byte-pin it. Prereq-5's "commit/welcome wire blob byte-equality" clause needs an ADR amendment (KeyPackage byte-pin + Commit/Welcome structural-convergence). Parts 1 (wasm-pack CI job / #1981), 3.1-3.4 (event-log root+leaves, AAD, credential, AEAD-roundtrip KATs), and 4 (+10 driver-adversarial tests) are independent of this and fully feasible. Env: wasm-pack + node 25.7.0 present, `wasm-pack test --node crates/scp-client-wasm` runnable locally.
