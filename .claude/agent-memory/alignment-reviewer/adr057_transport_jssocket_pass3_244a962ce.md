---
name: adr057-transport-jssocket-pass3-244a962ce
description: ADR-057 browser relay transport PASS-3 convergence review — parity-scope + mesh-residual + native-parity #2179 cleanup, ALIGNED
metadata:
  type: project
---

# ADR-057 In-Browser Relay Transport — PASS 3 (convergence) @ `244a962ce` (2026-07-19) — ALIGNED

Branch `feat/adr057-transport-jssocket`. Reviewed docs-cleanup delta `4c8afb284..244a962ce` (8 commits) after PASS-2 found the D2 byte-parity fix incomplete at ADR-057:200. **0 blocking, 0 major.** All 5 items correct + honest:

- **M-D :200 parity scope** — FIXED. Removed unscoped "(identical pseudonyms native vs. browser)" parenthetical; added "Scope this precisely" clause: KAT pins **cross-target ALGORITHM determinism** (same recipe→same bytes for SAME input key), NOT same-human equality (fails pre-#1980 — browser keys on per-context MLS key, native on identity key). Now coherent with Option-A Decision (:231) + A1 as-built note (:239). Targeted self-contradiction gone.
- **M-B mesh residuals** — FIXED + honest. "relay-semantics-agnostic / no-backfill" positive framing dropped, explicitly recharacterized "**This is a limitation, not a virtue**". New "Residuals" block: (1) epoch/sender-key ordering residual, (2) offline/restore residual — both cross-ref T4 accurately. **Verified T4 (:122) genuinely defers the `SenderKeyRequest`/`SenderKeyResponse` §9.16.2 pull path gated on #1980** — cross-ref is real, not phantom. Ordering premise stated.
- **D4 active-signal** — disclosed in spec §9.10.4.1 as browser-transport residual **4** ("ACTIVE per-join O(N)-publish signal"); correctly distinguished from passive residuals 1–2; numbering coherent.
- **Native-parity #2179 flag** — LEGIT external-constraint deferral, NOT scar-tissue. **#2179 is a real OPEN issue** titled "Native reciprocal-announce parity for §9.10.4 pseudonym mesh" (matches ADR). Genuine constraint: native has no live relay-receive pump → reciprocal untestable e2e. `#[ignore]`d scaffold test `native_reciprocal_announce_on_new_peer_is_a_follow_up` (messaging_helpers.rs) is REAL (records first-time new peer, then `panic!`s that reciprocal unimplemented) — pins contract, NOT a `let _=` dead-ref sham. Artifact-flow intact (ADR governs, code references down).
- **Packaging-deferral (resubscribeAll onopen)** — honest, not phantom. wasm export `resubscribeAll` (lib.rs:514, never-throws) + native driver test `resubscribe_all_restores_delivery_after_entry_time_subscribes_were_dropped` (transport_regression.rs) both real. TS `onopen` wiring correctly deferred: `@limn-works/scp-ts-wasm` package genuinely doesn't exist yet.

**Nits (non-blocking):** (a) `#2179` raw GitHub issue-ref in source (test ignore-reason + panic) — FIRST such usage in codebase (grep=0 precedent); project leans SCP-NNN PRD IDs; no mechanical ban; idiomatic in `#[ignore]`. (b) new :200 ":224/:232" line pointers imprecise — A1 note is at :239 not ~:224 (fragile prose cross-ref). (c) MINOR pre-existing staleness: :200 T-1 para still says browser call site "NOT YET BUILT" (07-16 text, untouched) while A1 (:239, 07-17) records it as-built — mild same-paragraph tense tension surfaced by the new forward-ref clause; not introduced by this delta, not phantom.

## GOTCHA — worktree HEAD moved mid-review
Prompt said HEAD=`244a962ce` branch `feat/adr057-transport-jssocket`. First `git log` confirmed. But between commands the worktree was checked out to `1620de983` (unrelated ceiling/saga branch) — ADR-057 file vanished from filesystem, `4c8afb284` no longer an ancestor of HEAD. Fix: review by **explicit SHA** (`git show 244a962ce:path`, `git diff 4c8afb284..244a962ce`) — commits persist as objects regardless of checkout. Don't trust `HEAD`/filesystem when a prompt pins a SHA.
