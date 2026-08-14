---
name: adr057-t1-primitives-dissolve-FINAL-5b35cb9aa
description: ADR-057 T1 final-state security review (HEAD 5b35cb9aa, range 86519aa6f..HEAD) — scp-primitives dissolve into scp-clock/scp-crypto/scp-did; ZERO findings
metadata:
  type: project
---

# ADR-057 T1 scp-primitives dissolve — FINAL review @5b35cb9aa (2026-07-03)

Branch refactor/dissolve-primitives-split-identity. Range 86519aa6f..HEAD (10 commits).
Supersedes my 033a12d4c review (adr057-t1-primitives-dissolve.md). **ZERO findings.** Behavior-preserving topology refactor confirmed at final state.

Checklist verdicts (all CLEAN):
- (a) verify_ed25519_signature: scp-crypto/src/lib.rs byte-identical to old scp-primitives/src/crypto.rs except +4 crate attrs (doc/warn missing_docs/forbid unsafe). scp-clock same. The protocol sender_keys (key_protocol_verify.rs:1049) + runtime access_keys (wire.rs:528) LOCAL verify fns are pre-existing separate impls, only import-repointed to scp_crypto (byte-identical fn).
- (b) extract_public_key_from_did: scp-did/src/lib.rs code body byte-identical (diff EXIT 0). Testing gate `#[cfg(any(test, feature="testing"))]` intact on did:key hex branch. REACHABILITY CLEAN: ALL `scp-did/testing` + `features=["testing"]` edges are in [dev-dependencies] or opt-in cargo `testing` features. Prod [dependencies] edges all plain versioned. scp-client-wasm default=[] (testing opt-in) → WASM release artifact (wasm-pack default features) cannot reach did:key.
- (c) serde stability: document.rs (from scp-protocol/src/identity/document.rs, R096) + attestation.rs (from scp-protocol/src/identity/did_attestation.rs) are PURE DidDocumentError→DidError rename + import-path + fmt reflow. No serde attr/field/rename/tag change. DidError is a thiserror enum (not serialized).
- (d) shim gate scripts/check-no-shim-reexports.sh: SOUND. `*/`-guard verified in isolation (scratch harness): genuine `//` comment SKIPs; `// */ pub use ...` (block-close leaving live code) FLAGs; live code FLAGs. A `//`-trimmed line can only host live `pub use` if a `*/` closes a prior block on that line — guard catches exactly that. Worst case = over-flag dead block-commented code (false positive, safe). Multi-line `pub use`/`pub<comment>use` evasion documented in-script, depends on rustfmt CI (acknowledged coupling). grep `pub\s+use\s+(::)?scp_{clock,crypto,did,mls}\b` catches whole-crate/`as`-rename/path forms — my two prior 033a12d4c observations (nested-src glob miss; `as`-rename evasion) are now BOTH FIXED (find -type d -name src; `\b`). Gate passes clean; registered CLAUDE.md:112 + ci.yml:187.
- (e) manifests/lock: Cargo.lock ZERO new/removed external packages (only scp-* stanzas). All added deps in new crate manifests are `workspace=true` (no pin-widening). No feature-flip on existing external deps.
- (f) enforcement touches all legit: check-no-mutable-globals.sh/check-protocol-deps.sh/.clippy.toml = comment-only primitives→scp-clock rename (no allowlist/banned-set weakening; banned still tokio|scp-platform|openmls). CLAUDE.md ADDS check-no-shim-reexports.sh to list (sanctioned coverage expansion) + project-map doc.
- (g) release.yml: exactly 16 publish steps = exactly the 16 publish!=false crates (scp-clock,crypto,did,platform,event-log,protocol,identity,mls,client,runtime,core,transport,mcp,media,node,relay). scp-client-wasm/scp-testing/scp-ffi* (publish=false) excluded. Dep-order valid: protocol(6) deps ∈{clock1,crypto2,did3,eventlog5}, wasm fence intact (protocol has NO identity/mls/client edge); identity(7) deps ∈{clock1,did3,platform4}. TAGS block matches.

scp-primitives crate FULLY DELETED (git ls-tree + fs both empty). 4 deleted files (protocol/crypto/ed25519.rs, event-log/crypto.rs, event-log+protocol/time.rs) were all pure `pub use scp_primitives::…` shims. Zero dangling scp_primitives refs tree-wide.

PRE-EXISTING (NOT this diff, byte-identical @86519aa6f): scp-identity [dependencies] scp-platform features=["testing"] (in-memory custody feature in a prod dep edge; comment says scp-node enables it non-optionally). Out of scope; flagged only as carry-over observation.
