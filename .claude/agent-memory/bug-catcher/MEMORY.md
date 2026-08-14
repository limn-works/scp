# Bug Catcher Memory

Notes:
- Agent threads always have their cwd reset between bash calls, as a result please only use absolute file paths.
- In your final response always share relevant file names and code snippets. Any file paths you return in your response MUST be absolute. Do NOT use relative paths.
- For clear communication with the user the assistant MUST avoid using emojis.
- Do not use a colon before tool calls. Text like "Let me read the file:" followed by a read tool call should just be "Let me read the file." with a period.

## Start here

- [Historical bug patterns (Feb–Aug 2026)](historical-bug-patterns.md) — ARCHIVE + the recurring-pattern taxonomy (TOCTOU across async locks; bulk-replacement missed call sites; FFI `None`-passing; guard across `.await`; types without call-site wiring; WASM drift). Read the taxonomy before any review.

## Per-review notes

- [SCP-RELAYRES-004 relay WRITE path](relayres004-write-path-5b89baada.md) — 5b89baada: tokio `abort()` is NOT synchronous for a *running* task → republish arms can leak past `stop()`; failed tier-change re-publish advertises a dead relay URL; PRD still cites the deleted `bound_relay_count`. Large verified-CLEAN list inside.
- [check-error-codes.sh Phase 4 brace-counting unsound](gate-brace-counting-unsound.md) — SCP-OUT-030 awk brace-counter: false-neg (unallocated code after an unbalanced `cfg(test)`) + false-pos (block/trailing comments, `cfg(all(test))`). AC2 holey; AC1/3-7 met.
- [UniFFI Swift checksum staleness](uniffi_checksum_staleness.md) — CRITICAL recurring: hand-edited throwing sig + stale checksum int → Swift SDK `fatalError` on init. Detect by regen+diff. Found in 8bcd520c2 (#1543).
- [PR #2234 broadcast KEA / checkpoint counter](pr2234-broadcast-kea-counter.md) — PROVEN by mutation: 6 new "counter" tests have ZERO power (deleting all 36 counter bumps keeps 69/69 green). Counter is cadence-only.
- [SCP-OUT-031 PR-2b bridge render](outlet031-pr2b-bridge-render.md) — e1ce84f48 3-bridge OutletErrorSurface. Swift bindings VERIFIED byte-identical (regen recipe inside). 7 defects incl. fail-closed collapse leaking via raw-envelope Display + stale `_scp_core.pyi`.
- [PR #2235 app_bind audit](pr2235-app-bind-audit.md) — §8.4 bind/unbind: UniFFI reads stale/empty `handle.ceiling_strings` (all binds fail on the default ceiling); vacuous "absence" pipeline assertion inflating a ratchet; non-atomic log-then-registry; NAPI JSON casing change broke TS `DeclarationValidationResult`.
- [ADR-062 E4 RelayPublisher severance](adr062-e4-relaypublisher-severance.md) — 7f658c8fb CLEAN. `RepublishManager` default-typaram removal + test-double cfg-gating; notes the pre-existing "no prod RelayPublisher impl" (#482).
- [ADR-057 node-vs-browser twin audit (d1ebc5ab9)](adr057-node-browser-twin-divergences.md) — ZERO native↔browser interop test exists (the cross-target KAT only pins shared-primitive byte determinism). Browser omits `0xFF02` context-params (⇒ can never join a node context, `valn0502`), omits `InnerEnvelope`+§9.17 access-key layer entirely (⇒ no §9.8.1 signature verify), and `add_member` skips the governance gate. Large verified-CLEAN list + a near-miss false positive (HPKE ctx binding) inside.
- [Bridge-triple twin divergences (d1ebc5ab9)](bridge-triple-twin-divergences.md) — UniFFI SYNTHESIZES a default `ContextRoleState` (creator auto-admin ⇒ tautological gate) for outlet_register/interface_expose/accept; PyO3 has NO context-Active gate on any bridge-local outlet op (its own outlet_stream.rs twin does the live read); NAPI+UniFFI drop the ADR-010 dual role-state check on cross-context + session invoke. Big CLEAN list + 4 verified false-positive traps inside.
- [SDK-quad twin divergence (d1ebc5ab9)](sdk-quad-twin-divergence-d1ebc5ab9.md) — TWO public TS `evaluateTrust`; the `trust.ts` twin still calls nonce-CONSUMING `ucanValidate` + prose classification + zeroed Layer 2. Plus TS missing chainDepth/ttl guards its own saga twins have, proven-vacuous TS tests (guard lives in the mock), VALID-7002 purpose drift. Big verified-CLEAN outlets list inside.

- [PR #2155 dev-profile merge (8b7cbe7f8)](pr2155-dev-profile-merge-8b7cbe7f8.md) — unreviewed merge, retro-verified CLEAN. ADR-057 release block byte-identical; squash lost nothing; `debug-assertions=false` proven a true no-op vs cargo default. One doc defect: **`bench` inherits `release`, NOT `dev`** (Cargo.toml:156 says otherwise). Empirical flag-dump recipes inside.

## Clean-review notes worth not re-deriving

- **SCP-AB-021 KeyResolver VM-widening (ba06a8e0+7d4cdcf0) — CLEAN.** `Fn(&DID)->Opt<VK>` →
  `Fn(&DID,SigningKeyId)->Opt<VK>` threaded end-to-end (Supervisor::send_message →
  SendMessagePayload.signing_key_id → … → build_encrypted_envelope); `verify_and_unwrap` reads the
  wire value. ~30 resolver sites are pure signature widenings. All FFI bridges + self_host pass
  `SigningKeyId::Active` — preserves prior behavior, no regression. `from_fragment` is the sole
  canonical decoder.
  **Pre-existing (NOT that diff):** every production resolver (bridge_instance, self_host,
  bridge_runtime not_configured) returns `None` regardless of args — real DID-doc VM resolution is
  unwired, so encrypted-context receive verification fails closed in real deployments.

## Key files

- `/Users/alec/Developer/limn/scp/.docs/specs/` — full protocol specs.
- `/Users/alec/Developer/limn/scp/.docs/specs/00-open-questions.md` — open + resolved design decisions.
- `/Users/alec/Developer/limn/scp/.docs/architecture.md` — build document.
- `/Users/alec/Developer/limn/scp/.docs/sketch.md` — API surfaces.
- `/Users/alec/Developer/limn/scp/.docs/adrs/phase-2.md` — Phase 2 ADRs (context, roles, tools, events, transport).
