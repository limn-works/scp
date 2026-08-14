---
name: project-adr057-t1-crate-split
description: ADR-057 T1 crate-topology split (dissolve scp-primitives → scp-clock/scp-crypto/scp-did; scp-identity keeps native DHT) — worktree state + verification plan
metadata:
  type: project
---

ADR-057 slice T1 = behavior-preserving crate-topology split. Worktree `/Users/alec/Developer/limn/scp/.claude/worktrees/split-primitives`, branch `refactor/dissolve-primitives-split-identity`, base `d1193202e` (ADR amend) on `86519aa6f`.

Final topology (NO scp-dht — DHT not separable, ADR rejected-alt 5): scp-clock (leaf, ex time.rs), scp-crypto (leaf, ex crypto.rs), scp-did (wasm-safe, ex scp-primitives/identity.rs + scp-protocol/identity/document.rs + did_attestation.rs; DidDocumentError→DidError). scp-identity STAYS native (DHT/DidMethod/DidDht/ScpIdentity/IdentityError/resolver/cache/republish/config) — only imports repointed. scp-primitives DELETED.

**Why:** interim Slice-1a parked DID types in scp-protocol + scp-primitives junk-drawer w/ re-export shims — the smell it was meant to fix. T1 gives DID model one honest wasm-safe home.

**How to apply:** When resuming, DON'T blind-re-execute — the working tree already contains staged renames (5 files) + ~250 unstaged import rewrites + 3 untracked new-crate Cargo.toml/README. Treat as in-progress work to VERIFY+FINISH+COMMIT, not redo. Invariant: scp-clock/crypto/did/event-log/protocol/mls/client/client-wasm must NOT gain tokio/scp-platform/scp-identity deps. Verify gates: build, clippy (all features), fmt, wasm32 check (clock/crypto/did/protocol/mls/client-wasm), check-protocol-deps.sh, nextest, grep scp_primitives=0, grep pub-use-scp_mls in runtime=0, grep scp_protocol::identity::document/did_attestation/DidDocumentError=0. Commit atomic, do NOT push/PR.
