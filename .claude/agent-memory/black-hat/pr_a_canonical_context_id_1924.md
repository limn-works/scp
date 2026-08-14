# PR-A Canonical Context ID = Digest (#1924, ADR-056) — black-hat findings

HEAD ea592648f. `state::context_id_to_bytes(id)` = decode-if-64-lowercase-hex else SHA-256.
Single chokepoint; runtime keying (builder/ttl/messaging/lifecycle/governance_logic/key_destruction/mls-provider) routes through it. key_destruction fail-open FIXED.

## CRITICAL: 4 FFI event-log read stragglers key under SHA-256(id), not the digest
- The event log is INIT under the digest (builder create_context inits under context_id_to_bytes).
- These 4 PRODUCTION FFI read paths still call `scp_core::context::context_id_bytes(id)` = SHA-256(hex(digest)):
  - `crates/scp-ffi/src/event_log.rs:228` (pyo3 query_manager_entries → event_log_query)
  - `crates/scp-ffi/napi/src/event_log.rs:114` (napi event_log_query_on)
  - `crates/scp-ffi/napi/src/event_log.rs:238` (napi prove_inclusion/absence sync)
  - `crates/scp-ffi/uniffi/src/bridge.rs:12779` (uniffi event_log_query)
- Real ids are 64-hex (generate_context_id), so FFI keys WRONG → supervisor.event_log_entries returns
  None/empty → silently falls back to the empty UCAN-state tree. Event-log queries + Merkle
  inclusion/absence proofs over the manager log return nothing for real contexts. Fail-open-ish
  (silent empty). Gate MISSES these: it only scans crates/scp-runtime/src.
- Fix: route these through a resolver (scp_core needs to re-export context_id_to_bytes, or FFI
  computes via the chokepoint). And extend the gate scan to scp-ffi.

## CRITICAL: gate check-context-id-keying.sh is bypassable (3 shapes, proven by mutation)
- Aliased import: `use scp_protocol::context::context_id_bytes as cib;` then `cib(id)` → gate PASSES.
- Re-export path: `scp_core::context::context_id_bytes(id)` → gate PASSES (only matches scp_protocol::).
  NB: the FFI stragglers above already use exactly scp_core:: path — a runtime site could too.
- Multiline qualified: `scp_protocol::context::\n  context_id_bytes(id)` → gate PASSES (awk line-by-line).
- Not a closed allowlist of permitted SHAPES — it's a denylist of two literal call spellings.
  Self-test covers none of these. The proper enforcement is the type system / a newtype, or making
  context_id_bytes pub(crate)-restricted + a single facade. Per CLAUDE.md simplifier guidance this
  gate is non-convergent denylist.

## SOUND (verified)
- Decode is a bijection on 64-hex; no NEW collision/hijack vs pre-ADR-056 (registry first-writer-wins
  keyed by STRING; MLS keys gate access; attacker importing hex(victim_digest) gains keying-address
  collision only, same as old SHA-256(id) collision — no secret access).
- §6.2.4 saga: target_context_id (raw digest on wire) → lookup by hex(digest) = canonical id string;
  state.context_id = decode(id) = digest → match holds. Fix is load-bearing + correct.
- Two-name collapse (supervisor register-under-string): registry value-agnostic, keys by string in all
  cases; no new fail-open. hex(state.context_id) sites in mls/provider are log/error display only.
- Uppercase/63/65-len guard correct; synthetic (identity-private-state) + standing- prefix hash unchanged.
