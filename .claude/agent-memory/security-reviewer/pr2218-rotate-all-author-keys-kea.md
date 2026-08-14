# PR #2218 rotate_all_author_keys -> KeyEpochAdvance emission (#1847) -- 2026-08-02 -- CLEAN, 0 BLOCKER/HIGH/MEDIUM

Branch fix/rotate-all-author-keys-epoch-advance (84be6115b). Diff = 3 files: broadcast/mod.rs
(rotate_all_author_keys sig () -> (timestamp_ms: u64) returning Vec<BroadcastKeyEpochAdvance>),
governance_helpers.rs (execute_rotate_content_keys + execute_revoke emit KEA leaves), tests.

- BroadcastKeyEpochAdvance (crypto/sender_keys/broadcast.rs:129) carries ONLY {author_did:String,
  new_epoch:u64, timestamp:u64} -- NO key material. Rotated key stays in author.broadcast_key
  (Class-S state), never in the advance struct threaded into log payloads.
- KEA leaf author_did = author.author_did.clone() from bc.authors trusted internal registry, NOT
  caller-controlled / not from envelope. Actor iterates only its own registered authors => a
  non-author cannot mint a KEA for another DID. Leaf is node-local Merkle append (audit anchor,
  not per-leaf author-signed). Consistent w/ pre-existing execute_revoke KEA pattern.
- timestamp_secs from CommitMeta built by governance auto-execute dispatcher from deps.clock.now_secs()
  (trusted clock, not caller). New .saturating_mul(1_000) panic-safe. ms advance.timestamp is DEAD
  DATA in governance path (leaf uses timestamp_secs directly) -- documented in code.
- GovernanceDeadlockRecovery NOT in this PR's diff (grep=0); pre-existing execute_reconfigure_governance.
  unavailable_dids/missed_windows are DID newtypes (d.0.clone) => type-constrained, validated non-empty.
- KEA emit loops bounded by Vec::with_capacity(authors.len()); warn-and-continue, no retry/no infinite loop.
- execute_revoke: MemberBan capability check is INSIDE commit_class_s_keep closure (atomic, no TOCTOU),
  KEA path only reached after fail-closed persist Ok => unauthorized caller rejected before any emit.
- Determinism sort (advances.sort_unstable_by author_did) is a real security property: prevents HashMap
  iteration-order Merkle-root divergence across replicas (feeds checkpoint root comparison).
- Fixed BLOCKER (checkpoint counter) verified correct: both paths += 1 + kea_success_count, only durable
  leaves counted (else-arm increments on Ok) => no §9.9.3 checkpoint-position drift.
- Best-effort KEA is safe direction: key rotation fail-closed persists BEFORE best-effort leaves;
  missing leaf degrades observability not access control (encryption-as-access-control enforces).
