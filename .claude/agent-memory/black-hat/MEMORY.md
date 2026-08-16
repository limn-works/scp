# Black Hat Agent Memory

Index only. One line per entry; detail lives in the linked topic file.

Notes:
- Agent threads reset cwd between bash calls, so use absolute file paths.
- In the final response, share relevant file names and code snippets. Every path returned MUST be absolute.
- Avoid emojis.
- Do not use a colon before tool calls. Write "Let me read the file." with a period.

## Reviews by branch / PR

- [Track F remaining fail-opens](pr-trackf-remaining-fail-opens.md) — relay blob selection, FileKeyCustody v2 passphrase verifier, cfg-gated in-memory stores, required custody argument, governance fail-closed: what is sound and what is residual.
- [Track F round two](pr-trackf-round2-file-custody.md) — the v2 key-file HMAC runs only at `open_existing`, and every write path re-seals unverified disk bytes; plus five smaller fail-opens and the list of what resisted attack.
- [FFI bridge audit](ffi-bridge-audit.md) — cross-bridge parity gaps in the PyO3 / NAPI / UniFFI surface.
- [PR #1628 BridgeInstance extraction](pr1628-bridge-instance.md) — BLACK-301 post-shutdown ghost ops, BLACK-303 placeholder DID confusion, BLACK-308 rate-limiter ephemeral bypass, BLACK-309 economy unbounded growth.
- [PR #2141 R25 batch 3](pr2141-r25-batch3.md) — findings from that batch.
- [Refactoring plan adversarial analysis (2026-03-21)](refactor-plan-adversarial-analysis.md) — BLACK-301..311: facade divergence, Phase B TOCTOU, asymmetric wiring, BridgeInstance split-brain; mitigations are a generation counter, atomic send+receive wiring, a CI mod/re-export check.
- Event-log substrate swap phase 2 (RFC 6962): export forgery closed; the equivocation detector false-positives under dormant cross-member replication; in-memory dedup is wiped on respawn.
- [Historical audits](historical-audits.md) — PR #76, spec 22 human-readable addressing, PR #127 UCAN bridges, PR #195 HTTP features, transport expansion, PR #1606 sender-key AAD, the 2026-04-01 consequence/economy/FFI branch review, ADR-039 persona attribution, and the TS SDK fail-closed/parity review, including what each pass confirmed working.

## Standing SCP-specific attack patterns

- Confused deputy via context recreation: standing contexts use deterministic IDs, so any Phase 3 lock reacquire without a generation check is exploitable.
- Lock ordering: the three lock types (DashMap shards, per-context Mutex, standing_contexts Mutex) admit an ordering inversion. `ContextHandle`'s `Arc<ArcSwap<ContextState>>` is lock-free per ADR-049 §Decision 12 and never joins the ordering graph; the risk there is transition atomicity, not deadlock.
- DashMap shard starvation: `contexts.iter()` holds shard locks, so combining it with a per-context Mutex await yields convoys or deadlock. Check every iteration path.
- Capability TOCTOU: check capability, drop the lock, act under a new lock. Watch GovernancePropose, GovernanceVote, ContextClose.
- Background task stale state: TTL timers and governance timeout tasks hold Arc references and operate on orphaned state after a context is recreated unless they verify a generation.
