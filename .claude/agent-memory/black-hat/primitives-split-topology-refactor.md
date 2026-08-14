---
name: primitives-split-topology-refactor
description: Findings from reviewing refactor/dissolve-primitives-split-identity (scp-primitives dissolved into scp-clock/scp-crypto; DID model to new wasm-safe scp-did). Range 86519aa6f..d12691ef6.
metadata:
  type: project
---

# Dissolve-primitives / split-identity crate-topology refactor (ADR-057 T1)

Branch refactor/dissolve-primitives-split-identity, HEAD d12691ef6.
scp-primitives DELETED → dissolved into scp-clock (Clock trait, byte-identical to old primitives/time.rs) + scp-crypto (ed25519 anchor). DID data model extracted to new wasm-safe scp-did (deps: scp-crypto only). scp-protocol now → scp-clock + scp-crypto + scp-did + scp-event-log.

## HIGH — fuzz/ crate NOT retargeted, points at deleted scp-primitives (build break / dead safety-net)
- `fuzz/Cargo.toml:32` still `scp-primitives = { path = "../crates/scp-primitives" }` → deleted dir.
- `fuzz/src/lib.rs:16` still `use scp_primitives::Clock;` (Clock now in scp-clock).
- fuzz/ is standalone (NOT workspace member per CLAUDE.md) so `cargo build --workspace` never catches it. Only the nightly `fuzz-build` CI job (`cargo +nightly check --manifest-path fuzz/Cargo.toml`) catches it.
- fuzz-build gate DOES trigger here (fuzz path-filter includes scp-protocol/scp-clock/scp-crypto/scp-did/scp-event-log — all touched) → CI FAILS, blocking. But if fuzz job is dismissed/flaked-non-blocking, 26-target fuzzing safety-net silently dies. Refactor's "CI retargeted" claim is incomplete.

## Areas verified CLEAN
- (a) check-protocol-deps.sh: logic byte-identical (comment-only change primitives→scp-clock). `cargo tree -p scp-protocol` is TRANSITIVE so banned tokio|scp-platform|openmls riding through scp-did/scp-crypto/scp-clock ARE caught.
- (b) ci.yml filters: `rust` filter is `crates/**` wildcard (covers all new crates incl scp-mls/client/client-wasm). `fuzz` filter correctly remapped scp-primitives→3 successor crates. check-protocol-deps.sh, check-protocol-sync.py, AND the WASM/protocol wasm-check job are all `needs: check-draft` (unconditional, NOT path-gated) — not skippable.
- (c) ADR-057 fence (scp-mls/scp-client/scp-client-wasm must not reach scp-runtime/scp-identity/tokio): enforced MECHANICALLY by the unconditional wasm-check `cargo check -p scp-mls -p scp-client-wasm --target wasm32` (+ scp-did directly). scp-client covered transitively via scp-client-wasm→scp-client. A native dep addition → wasm32 compile FAILS (tokio-multithread/runtime/identity don't build on wasm32). Real failing gate, not just prose. NOTE: no explicit cargo-tree grep gate for the fenced crates (unlike scp-protocol) — relies purely on wasm32 compile; adequate for the stated invariant.
- (d) Clock/SystemTime privatization: scp-clock byte-identical to old primitives/time.rs; now_secs/now_millis are private `fn`, ClockError pub(crate). Guarantee is Rust module privacy (same as before) — there was NEVER a mechanical grep gate for SystemTime (known documented limitation). No new bypass.

## MEDIUM (pre-existing, carried forward unchanged) — release.yml publish-order inversion
- scp-identity has REAL non-dev dep `scp-protocol = "=0.1.0-beta.2"` but is published 5th (line 396) BEFORE scp-protocol 7th (line 412). `cargo publish -p scp-identity` (verify build) resolves scp-protocol from crates.io before that version exists → fail/stale. Present at base 86519aa6f; old order had same inversion (identity 3rd before protocol 5th). NOT introduced by this refactor but real latent supply-chain bug. All NEWLY-inserted crates (clock/crypto/did/mls/client/client-wasm) ARE dependency-correctly ordered.

## LOW — stale scp-primitives doc drift (phantom provenance, no mechanical impact)
- release.yml:872 human summary still lists scp-primitives + omits 6 new crates.
- Comments in scp-mls/src/{lib,credential}.rs, scp-identity/src/cache.rs, scp-event-log/src/{lib,crypto}.rs, scp-protocol/src/trust/attestation.rs, .clippy.toml:17, check-no-mutable-globals.sh:129 all still name scp-primitives.
