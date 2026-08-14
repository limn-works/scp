---
name: standing-context-ok-contract-and-example-parity
description: When a normative Ok-return/contract clause carves out a happy-path caveat (e.g. send-gating on Welcome-join), the WORKED EXAMPLE that consumers/LLMs copy must be checked for the same caveat — contract honesty does not propagate to examples automatically.
metadata:
  type: feedback
---

When reviewing an API whose contract clause adds a happy-path carve-out, also audit the worked example a consumer copies — example parity is a separate check from contract honesty.

**Why:** §5.15.8 `standing_context` (spec/05-contexts.md) round-5 fixed an Ok-return over-promise: a Welcome-joined `Ok` is now honestly disclosed as "decryptable but interim send-gated until Phase-2E." But the §5.12.5 architecture example (lines 951-952) still showed the unconditional `standing_context(bob) -> channel.send(...)` happy path with no joiner caveat. The contract was honest; the *example a consumer/LLM pattern-matches* re-introduced the exact over-promise. This matters specifically because of the CLAUDE.md line-42 "Agent-first API design" tenet: the SDK's primary author is an LLM, and the bar is "writes correct code from the type signature PLUS ONE EXAMPLE." An honest contract buried in prose plus a misleading example = the LLM copies the example.

**How to apply:** For any spec/API where a contract clause says "Ok means X but NOT Y" or "this path is gated," grep the same doc for the worked example / pseudocode call-site (`grep -n "\.send(\|sdk\.<entrypoint>"`) and verify the example annotates the caveat. Related: when a handle's `Ok` exists but an affordance (send) is conditionally unavailable, push for the failure to be a TYPED value (`SendNotYetAvailable`) not prose — implicit-state-not-in-the-type-system is the line-42 anti-pattern. See [[classs_cell_field_granular_views]] if present.
