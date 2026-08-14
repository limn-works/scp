---
name: project-adr057-t1-dht-split-cycle-stop
description: ADR-057 T1 crate-topology split STOPPED at the scp-identity DHT split — irreducible scp-identity ⇄ scp-dht type cycle; needs an upstream ADR amendment before T1 can proceed
metadata:
  type: project
---

ADR-057 slice **T1** (dissolve `scp-primitives` → scp-clock/scp-crypto; move DID model → scp-did; split scp-identity → scp-did/scp-dht/scp-identity; delete shims). Branch `refactor/dissolve-primitives-split-identity`, worktree `.claude/worktrees/split-primitives`, base `49c4aef84`.

**STOPPED before making any edits.** The `scp-dht` extraction (move `scp-identity/src/dht.rs` [7403 lines] + `dht_client/` into a new `scp-dht` crate, `DidDht`+`MigrationPartialState`+`DhtError`) creates an **irreducible bidirectional type cycle** `scp-identity ⇄ scp-dht` that cannot be broken by import rewrites alone (T1 is mandated behavior-preserving, ZERO logic changes).

**Why:** the ADR-057 table keeps the identity *verbs/domain* in scp-identity: `ScpIdentity`, `IdentityError`, `DidMethod` (all in `scp-identity/src/lib.rs`) and `DidCache`/`DidResolutionResult`/`Staleness` (`cache.rs`). But `dht.rs` (which must move to scp-dht):
- `impl<D,C> DidMethod for DidDht<D,C>` (dht.rs:2023) — implements the STAYS trait
- constructs `ScpIdentity { .. }` (dht.rs:1070/1186/1609/2111) and returns `IdentityError` 148× in real code
- `MigrationPartialState` (dht.rs:545) **embeds `ScpIdentity`** as fields `new_identity`/`old_identity` (dht.rs:551/567) → a scp-dht type structurally contains a scp-identity type ⇒ **scp-dht → scp-identity**
- meanwhile `config.rs` (STAYS) uses `crate::DidDht` 11× ⇒ **scp-identity → scp-dht** (the edge the task expected)
- and the task's own intended shape — `IdentityError::MigrationPublishFailed { partial: Box<scp_dht::MigrationPartialState> }` — closes the loop.

Cannot resolve by moving imports. Resolving requires one of: (a) also move `ScpIdentity`/`IdentityError`/`DidMethod` into scp-dht (contradicts ADR table — these are the verbs that stay); (b) a new shared lower crate (topology change not in the plan); (c) restructure migration error/state ownership (logic/design change). All are upstream-artifact decisions, forbidden to T1's mechanical scope.

**Per artifact-flow invariant + the task's explicit "STOP if genuinely circular" clause: escalated to a human. Needs an ADR-057 amendment resolving the scp-identity↔scp-dht boundary before T1 can run.** The other three crates (scp-clock, scp-crypto, scp-did) are NOT blocked by this cycle — only the scp-dht cut is. See [[feedback-worktree-absolute-path]].
