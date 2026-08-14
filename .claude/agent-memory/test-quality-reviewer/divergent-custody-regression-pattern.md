---
name: divergent-custody-regression-pattern
description: Good test pattern — force a normally-masked source-of-X regression to surface by constructing two divergent instances
metadata:
  type: project
---

## Divergent-instance regression guard (FFI persona custody sourcing)

Files: `crates/scp-ffi/napi/src/context.rs`, `crates/scp-ffi/uniffi/src/bridge.rs`
Test: `agent_persona_uses_identity_custody_not_handle_custody` (each bridge).

**The pattern.** The `#agent` message-send resolver must source the agent
signing key from the SENDER IDENTITY's own custody, not the context handle's
custody. In normal use those two custodies are the SAME object (creator sends in
own context), so a revert to handle-custody sourcing is invisible. The test
DELIBERATELY DIVERGES them: identity registered/built with `custody_a` (holds
the agent key); handle carries a fresh EMPTY `custody_b`. Correct code exports
from custody_a → returns agent key; a revert exports from empty custody_b →
`KeyNotFound` → `.expect()` panics. This is the canonical way to make a
"which source did we read from" regression deterministically catchable.

**Why it's non-vacuous:** asserts the exact agent-key bytes (distinct from the
active key, which create_with_agent_key generates separately), not just "some
key" or "Ok". Fully deterministic — InMemory custody + InMemoryDhtClient, no
net/time/fs, uuid context_id, fresh bridge instance per test, no global state.

**Symmetry note:** the two bridges source identity custody differently, and the
tests correctly adapt: NAPI exercises the DashMap registry lookup
(`register_identity` + `with_identity`); UniFFI passes the `Identity` struct
directly. Both guard the same property. Persona-stamp assertion is intentionally
omitted from the regression test (covered by sibling
`resolve_message_signer_binds_stamp_and_key_atomically` in both bridges).

**Reusable heuristic:** when a property is "read X from source A not source B,"
a passing test that uses A==B proves nothing. Make A and B differ and starve B.
