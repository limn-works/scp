---
name: adr057-t1-dissolve-primitives-review
description: CLEAN review of ADR-057 T1 topology refactor (dissolve scp-primitives → scp-clock/scp-crypto/scp-did) on branch refactor/dissolve-primitives-split-identity @b85daa755
metadata:
  type: project
---

# ADR-057 T1 — dissolve scp-primitives / extract scp-did (b85daa755) — CLEAN

Behavior-preserving topology refactor. Reviewed range 86519aa6f..b85daa755. NO defects found.

**Why:** Topology cleanup — scp-primitives "junk drawer" dissolved into capability leaves; DID model given one wasm-safe home (scp-did, DidDocumentError→DidError). Enforced by new gate script + acyclicity/wasm-fence CI.

**How to apply:** If re-reviewing or extending, these facts are verified:
- scp-clock/src/lib.rs & scp-crypto/src/lib.rs = BYTE-IDENTICAL moves of scp-primitives time.rs/crypto.rs (only added `#![warn(missing_docs)]`/`#![forbid(unsafe_code)]`).
- scp-did/src/lib.rs = byte-identical move of primitives/identity.rs + additive `pub mod`/`pub use`. document.rs & did_attestation.rs→attestation.rs = pure DidDocumentError→DidError rename + import-path updates. Zero logic drift. No lingering DidDocumentError.
- Single owning def of each moved type (one verify_ed25519_signature in scp-crypto, one DID, one DidError) — no aliasing ambiguity. Old scp-protocol/src/crypto/ed25519.rs and scp-event-log crypto.rs/time.rs were pure `pub use` shims, deleted; no external consumers.
- scp-identity dropped scp-protocol dep: ZERO scp_protocol refs in its src/tests; uses only scp_clock+scp_did (both declared). Removed its DID re-exports; no stale `scp_identity::DID/DidDocument/...` consumers.
- Testing feature (did:key gating) maps 1:1 scp-primitives/testing → scp-did/testing across client/client-wasm/event-log/mls/protocol. scp-clock has NO testing feature (correctly purged).
- Full `cargo check --workspace --all-targets` + CI feature set = CLEAN. Wasm fence: scp-clock/crypto/did/protocol compile to wasm32.
- release.yml publish order topologically valid for all NORMAL deps (clock,crypto,did,platform,event-log,protocol,identity,mls,client,client-wasm,runtime,...). scp-media edge in scp-runtime is DEV-only (pre-existing, doesn't block publish verify).

**Gate script scripts/check-no-shim-reexports.sh (NEW, wired ci.yml):** SOUND. Closed set {scp_clock,scp_crypto,scp_did,scp_mls}. Regex `pub[[:space:]]+use[[:space:]]+(::)?${mod}\b` — `\b` works under BSD grep (bash 3.2 verified); correctly excludes scp_didxyz & plain `use`. Exclusion allows owning crate + scp-core facade only. Mode 0755, exit codes correct under set -euo pipefail, runs clean. The one legit remaining `pub use scp_mls` is scp-core/src/lib.rs (facade, allowed). scp-runtime/src/crypto/mls/mod.rs shim correctly deleted.
