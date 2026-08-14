# ADR-057 T-1 §9.10.4 pseudonym-logic extraction — CLEAN (refactor/adr057-pseudonym-extract @1baeec93c)

**Verdict: byte-and-trace-IDENTICAL, 0 defects.** Behavior-preserving move of §9.10.4 pseudonym
logic native `scp-runtime/messaging_helpers.rs` → `scp-protocol::context::pseudonym` (wasm-safe),
native `ingest_pseudonym_announcement` collapsed onto shared `classify_pseudonym_announcement`.

Verified vs `git show origin/main:...messaging_helpers.rs` (old ingest @613):
- Metric `record_pseudonym_announcement_rejected()` fires EXACTLY once per reject, on the same 4
  branches (mismatch/reserved/broadcast/collision), NOT on NotAnnouncement/Recorded. New: single
  call at top of Rejected arm.
- All 4 `tracing::warn!` reproduced verbatim (fields + message + order). Sender-mismatch keeps
  `claimed_did = %claimed_did` where claimed_did:DID — DID Display is `f.write_str(&self.0)`
  (scp-did/lib.rs:62), renders identical bytes to old `%announcement.member_did` (String).
- 4 REJECT_* &'static consts == old literal strings exactly (feed PermissionDenied(reason.to_owned())
  at direct site msg_helpers:3252 + §25.19 KAT goldens). Buffered site drops Rejected→None (unchanged).
- Accept path: re-borrow `peer_registry_mut()` insert(member_did,pseudonym) + emit PseudonymAnnounced —
  identical data/order. `if let Some` total (classify already proved Some; no mutation between read+insert,
  single-thread &mut, no TOCTOU).
- peer_registry() (immut, used by classify) vs peer_registry_mut() (old): BOTH Some iff Pseudonymous,
  None iff Broadcast (state.rs:667/679) — broadcast-None branch determination identical.
- Moved struct serde preserved: derive(Serialize,Deserialize)+deny_unknown_fields+serde_bytes on
  pseudonym. Visibility pub(crate)→pub only (no wire effect). No state:: refs remain, no pub-use shim.
- #[allow(clippy::implicit_hasher)] on 2 pub fns justified: peer_registry is always default-hasher
  HashMap; generic BuildHasher would add unused param vs "one canonical shape". Not a bug.

Tests: scp-protocol pseudonym unit 12/12, runtime pseudonym_routing_tests 13/13, cross-target KAT 1/1
(scp-client-wasm), native build + wasm32 check both clean.

**ENV HAZARD:** `/Users/alec/.cargo/shared-target` is shared across worktrees. Other agents' cargo
(cargo-nextest etc.) rebuilding scp-protocol from a different branch into shared-target produced a
transient stale rlib → spurious E0432 "could not find pseudonym in context" + SIGTERM-killed tests.
Use `CARGO_TARGET_DIR=<iso>` to get a definitive build when other agents are active. NOT a code defect.
