---
name: ttl-convergent-deadline-adr049-pr3
description: ADR-049 PR-3 TTL redesign — event log is single authoritative TTL deadline source; BLACK-P3-003 closure + residual attack surface
metadata:
  type: project
---

# TTL convergent deadline redesign (branch feat/adr049-pr3-live-timers, commit a847842a1)

Invariant: event log is the single authoritative TTL-deadline source. One derivation
`convergent_ttl_deadline(&[Event], creation_ts, params_ttl)` at
`crates/scp-runtime/src/context/ttl_close_helpers.rs:569`. Rule: max(creation+params_ttl base,
highest TtlExtended.new_deadline_unix); ANY ContextPromoted after last ContextCreated (by
sequence) => None (immortal).

## BLACK-P3-003 = CLOSED
- reset_ttl_timer (ttl_close_helpers.rs:351) now emits a TtlExtended leaf (deterministic
  payload: old_dl=recorded convergent deadline, new_dl=old_dl+dur, proposal_id=SHA-256 content
  address). handle_ttl_expiry (ttl_close_helpers.rs:~145) derives ContextExpired leaf timestamp
  from convergent_ttl_deadline(LOG) not the cleared scalar or retry clock -> stable across
  retries, convergent across members.

## Key architectural fact (defuses most attacks)
- Runtime event log (providers/event_log.rs) is LOCAL per-node, empty-signature leaves,
  convergence BY CONSTRUCTION (each honest member deterministically appends identical leaves).
  NO peer/relay leaf-ingestion path. Only untrusted ingestion = creator-signed import
  (import_event_log_data, gated by validate_export_for_import export_import.rs:544, Merkle root
  bound to creator Ed25519 sig). So a relay/peer CANNOT inject ContextPromoted/TtlExtended into
  a victim's live log. convergent_ttl_deadline does ZERO per-leaf auth but is safe because the
  log's provenance is controlled (own appends or creator-signed import).

## Residuals worth flagging (all within creator-trust boundary; none remotely exploitable)
1. Best-effort reset append: NOT relay-exploitable (append is to local provider, not a relay
   round-trip). Only trigger = local disk fault. In-memory scalar still moves -> resident actor
   stays convergent; divergence only post-restore, fail-safe-shorter, equivocation-detectable.
   Minor asymmetry: execute_extend_ttl surfaces append err via .await? (governance_helpers.rs:1962),
   reset swallows it.
2. M3 residual / legibility gap: redesign REMOVED the import-time clamp. Derived deadline can
   EXCEED or contradict legible params.ttl (smuggled TtlExtended -> longer; smuggled
   ContextPromoted -> infinite). Joiner consenting on params.ttl=1h can import a context whose
   real lifetime is years/forever. Recommend legibility surface show convergent_ttl_deadline(log),
   not params.ttl.
3. Double-ContextCreated ordering: last_created=max(seq of ContextCreated); a 2nd forged
   ContextCreated with seq > a ContextPromoted FLIPS promotion off (re-arms TTL on a permanent
   context). Import-only (creator controls seq within Merkle chain). Recommend reject logs with
   >1 ContextCreated.
4. "Kill TTL early via ContextPromoted" is IMPOSSIBLE: promotion => None => immortal (opposite);
   max() means no leaf can shorten below base. No early-expiry DoS via crafted leaves.
5. finalize_close (ttl_close_helpers.rs ~648) still reads in-memory scalar for ContextClosed leaf
   timestamp (clock fallback), NOT convergent_ttl_deadline(log) -> letter-of-invariant gap on the
   cooperative-close path (not the TTL-expiry path). Low sev; recommend parity.
