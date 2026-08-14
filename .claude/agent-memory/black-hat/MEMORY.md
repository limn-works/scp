# Black Hat Agent Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

Index only — one line per entry. Detail lives in the linked topic file. Keep this under 140 lines.

## Design / ADR attacks
- [ADR-063 provenance-bearing projection](adr063-provenance-bearing-projection.md) — V2 ciphertext binding is sound; the HTTP guarantee is not. `#active` rotation deletes the whole archive; attestation doc omits `provenance_hash` so verification is not executable; serving `provenance` breaks §24.3.5.
- [ADR-039 persona attribution](adr039-persona-attribution.md) — binding is cryptographically sound, but every production key resolver returns `None`, so the `#active`/`#agent` guarantee ships unwired.
- [Refactor plan adversarial analysis](refactor-plan-adversarial-analysis.md) — BLACK-301..311 facade divergence, Phase B TOCTOU, BridgeInstance split-brain.

## Protocol / crypto
- [PR #2234 broadcast KEA fail-closed](pr2234-kea-failclosed-audit.md) — `execute_governance_action` rolls back the `executed_proposals` replay marker on dispatch error, making an applied governance action re-executable. No atomic multi-leaf append. `testing`-gated author seed = authority escalation.
- [Event-log substrate swap phase 2](eventlog_substrate_swap_phase2.md) — export forgery closed; equivocation detector false-positives under dormant replication; in-memory dedup wiped on respawn.
- [PR #2141 R25 batch 3](pr2141-r25-batch3.md)

## Relay / DID slot exclusivity (SCP-RELAYRES-003)
- [DID slot-exclusivity](relayres003-did-slot-exclusivity.md) — WS validating relay closes all four §3.10.8 flood variants, but co-deployed QUIC/UDP share the store and bypass `DidSlotRegistry` on publish and query/subscribe. `did_slot_registry()` wired nowhere. HIGH.
- [DELETE gate cold-index bypass](relayres003-delete-gate-cold-index.md) — `is_current_slot_blob` is in-memory-index-only; empty after restart or on a store-sharing peer → DELETE of the genuine slot blob → DID-doc rollback. HIGH.
- [Slot exclusivity round 1](relayres003-slot-exclusivity.md) — QUIC/UDP bypass fixed in 7cdd735d6; residual unauth DELETE revert (MEDIUM), WebTransport latent asymmetry, cold-establish global-lock DoS (LOW).

## SDK / bridges
- [TS SDK fail-closed + parity](ts-sdk-failclosed-parity.md) — test seam genuinely tree-shaken from the bundle; but `check-sdk-coverage.py` accepts a TYPE name as proof of a runtime capability (2/184 TS ops).
- [PR #1628 BridgeInstance extraction](pr1628-bridge-instance.md) — post-shutdown ghost ops, placeholder-DID confusion, rate-limiter ephemeral bypass, economy unbounded growth.

## Historical PR/spec audits (verify against current code before acting)
- [Archive: PR #76, spec 22, PR #127, HTTP #195, transport expansion, PR #1606, 2026-04-01 branch review](archive-pr-audits.md)
