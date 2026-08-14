---
name: test-isolate-bridge-gate-from-producer-gate
description: A negative test asserting only a shared error CODE cannot prove the BRIDGE gate fired when the producer has a redundant gate emitting the same code — it passes even if the bridge check is deleted. Assert the layer-unique message substring to isolate.
metadata:
  type: feedback
---

When the FFI bridge enforces a security check that the producer ALSO enforces (defense-in-depth, same error code), a negative test that asserts only the shared `code` does NOT prove the *bridge's* check fired — deleting the bridge check leaves the test green because the producer's redundant gate emits the identical code.

**Concrete case (FFI #116 Slice C):** the UniFFI caller-principal binding (`enforce_caller_principal_binding`) and the supervisor's own gate-1 (`supervisor.rs:5504`) BOTH emit `SCP-SAGA-13050` for a non-member caller. The negative tests asserting `code == SAGA_13050` would pass even if the bridge binding were removed — the bridge's load-bearing axis (a) (hosted-vs-unhosted, which the producer never checks) was untested. Caught by test-quality + bug-catcher independently.

**Why it matters:** This is the "gaming enforcement tests / passes for the wrong reason" failure mode CLAUDE.md warns about. A green test that can't distinguish the layer under test from a redundant downstream layer gives false mutation-resistance.

**How to apply:** Assert the LAYER-UNIQUE message substring in addition to the code. The bridge messages ("is not an identity hosted by this bridge instance" / "is hosted by this bridge but is not a member of") are distinct from the supervisor gate-1 message ("is not a member of caller context '…' — not authorized to initiate over it"), so the substring pins the assertion to the bridge. Capture `msg` in the match arm (don't discard via `..`). Generally: when two layers can produce the same observable code, find a discriminator only the layer-under-test produces, and assert it. Also choose negative-test inputs so only the intended gate can trip (clear all EARLIER validation gates), then pin the LATER redundant gate with the message discriminator.
