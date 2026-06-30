# ADR-057: In-Browser SCP Clients Over a Shared `scp-mls` Crate (Keys On-Device)

**Status:** Accepted (2026-06-30). Feasibility proven by a wasm32 compile spike; implementation staged across slices (see below).

**Amends:** ADR-055 (Remove the WASM Bridge; Browser Clients Are Remote Thin Clients) — specifically its *browser-deployment conclusion*. ADR-055's removal of the WASM **bridge** stands unchanged; this ADR revises only its claim that a browser must therefore be a *remote thin client with no in-browser protocol execution*.

## Context

ADR-055 removed the WASM FFI bridge because it was a parallel **re-implementation** of the protocol that had to stay byte-identical to native for §9.9.3 Merkle convergence — a perpetual maintenance tax and a proven security-bug source. That removal was and remains correct.

ADR-055 then concluded that browser clients must be **remote thin clients** to a server-side `scp-node`, with "no in-browser client-side MLS or protocol execution." That conclusion rested on an unstated premise: that running the protocol in a browser necessarily means *re-implementing* it (the tax) or *delegating* it to a server (custodial). A feasibility audit and a wasm32 compile spike (2026-06-30) disproved that premise:

- The blocker that killed the WASM bridge is **`scp-runtime`'s orchestration** — multi-thread `tokio` + the ADR-049 actor/supervisor model — which cannot compile to `wasm32-unknown-unknown`. It is *not* the cryptography and *not* the keys.
- The MLS group state machine (`crates/scp-runtime/src/crypto/mls/{group,encrypt,ratchet,credential,key_package}.rs`, ~3,057 lines) is **fully synchronous** and depends only on `openmls` (RustCrypto backend) plus an in-memory provider. It is *liftable*, not trapped.
- The participant hot path — §9.16 double-encryption seal/open, MLS epoch advance, event-log leaf + inclusion/absence proofs — is entirely synchronous, and the runtime provider traits it needs (`transport`, `event_log`, `persistence`) are **sync `dyn` traits a browser implements directly**. The actor/supervisor is native-concurrency machinery *wrapping* these sync calls; it is not a participant requirement.
- A wasm32 `cargo check` of the lifted MLS machine **succeeded (exit 0)**.

Therefore a browser can run the protocol in-tab over **shared code compiled to wasm32** — the same `scp-protocol`/`scp-mls` the native runtime uses — with the DID signing key and MLS group secrets held **on-device**. This is categorically different from the deleted bridge: it shares one codebase compiled to two targets, so the parity tax does not return.

Confidentiality and accountability are preserved by construction: the browser decrypts locally, the server never sees plaintext and never holds keys, and every operation traces to the on-device human DID. This satisfies the protocol tenets (encryption-as-access-control, relays-are-untrusted, every-agent-traces-to-a-human-DID) that a custodial remote-thin-client would violate.

## Decision

**Browser SCP clients run the protocol in-tab over a shared `scp-mls` crate, with keys on-device. The server is untrusted and never holds key material or plaintext.**

Components:

1. **`scp-mls` crate** — lift the synchronous MLS state machine out of `scp-runtime` into a `wasm32`-safe crate consumed by **both** `scp-runtime` (native node) and the browser client. One MLS implementation, two compile targets — no re-implementation, no byte-match maintenance. Liftable unit = the 9 sync files (`group`, `encrypt`, `ratchet`, `credential`, `key_package`, `error`, `wrapping_extension`, `epoch_grace`, and the `InMemoryMlsProvider = openmls_rust_crypto::OpenMlsRustCrypto` alias).
2. **Single-threaded browser driver** (~1.5–2.5K lines) over `scp-mls` + `scp-protocol`, implementing the participant operations (create/join/send/receive-decrypt/process-commit/close/leave, event-log leaves + proofs). It restores the deleted bridge's proven **shape** — a single global manager accessed via closure, with a pull-based `drain_events` model — but its bodies call shared `scp-protocol`/`scp-mls` types rather than re-deriving them.
3. **Browser platform infra**, restored/adapted from the deleted bridge: JS-callback key custody (the key stays in JS/WebCrypto and never enters wasm memory), IndexedDB-backed storage (the in-memory MLS provider snapshots out-of-band, reusing the existing `snapshot`/`restore` path), the relay transport (the surviving `webtransport-wasm`/WebSocket pipe), and the hardened time source (mitigating attacker-overridable `Date.now()` → UCAN-expiry bypass).
4. **The node continues to run `scp-runtime`'s orchestration unchanged** (actors, sagas, recovery, durable async storage). The browser is a participant, not a node.

The deleted bridge is recoverable at commit `1a3b41a5e^` (pinned in ADR-055) and is used as a restoration source for the infra and the driver shape — **not** for its re-implemented protocol bodies, which shared `scp-protocol`/`scp-mls` now obsolete.

### Prerequisites (from the spike)

1. `openmls` must carry its **`js` feature** (KeyPackage `Lifetime`s need wall-clock time on wasm) plus the `getrandom` `wasm_js` backend.
2. `epoch_grace.rs` hard-wires `tokio::time::Instant`/`SystemClock` and sits on the ratchet path (`process_commit` takes `&mut EpochGraceStore`); it must take an injected `scp_primitives::Clock` with a wasm backend so it ships with the machine.
3. The three synchronous, tokio-free `scp-identity` types `credential.rs` needs (`DidDocument`, `SigningKeyId`, `decode_multibase_key`) must move into a tokio-free crate (a new leaf crate or `scp-protocol`).
4. Caveat (not a blocker): the `std::panic::catch_unwind` DoS-guard in `encrypt.rs` is inert under the wasm `panic=abort` default — the browser build either uses `panic=unwind` or accepts the guard is a no-op in-tab.

### Scope fence (mandatory)

The browser driver covers the **participant** path only. Economy/payment validation, governance coordination, broadcast hosting, cross-context saga **coordination**, and always-on presence stay in `scp-runtime` or are node-delegated. The browser *participates* (signs its own steps) but does not *coordinate* — coordination requires always-on hosts. These were ~13K of the deleted bridge's 15.5K `manager.rs`; fencing them is what keeps the driver at ~2K and the parity-tax argument intact.

### Liveness / presence

MLS membership is an active relationship that **decays** when a member is absent — missed §9.9.2 heartbeats (peers cannot distinguish absence from relay suppression), lapsed PCS Update commits, exhausted KeyPackage pre-keys. These obligations are periodic **and** key-touching. The v1 model is **cold presence**: the browser participates while open and catches up / re-proves liveness when it returns, the same way the group already tolerates any frequently-offline member. **Always-on presence** (something keeping a member alive while the tab is closed) would require an **attenuated keep-alive delegate** that can *only* heartbeat / Update / replenish pre-keys and *cannot* read plaintext or send as the member. Whether MLS+SCP can express a delegation that narrow is an **open cryptographic question** (a delegate able to send a heartbeat — an MLS application message — can generally also decrypt), deferred to its own ADR + cryptographer analysis. **Confidentiality never requires custody** under any presence model; only always-on availability does.

## Consequences

**Positive:**
- True self-sovereign in-browser SCP clients (keys on-device, server sees only ciphertext) — high product value.
- One MLS state machine shared by node and browser; ADR-055's parity-tax avoidance is preserved because the browser runs shared code, not a re-implementation.
- Unblocks #1951 (browser examples) with a real foundation.

**Costs / risks:**
- A new `scp-mls` crate, a browser driver, and restored browser infra to build and maintain (bounded by the scope fence).
- The three prerequisite factorings (openmls `js`, `epoch_grace` `Clock` injection, `scp-identity` leaf types) touch core crates and must keep the native runtime working.
- Browser members are frequently offline → liveness degradation is expected; the protocol's offline-member handling must tolerate it.
- Forward secrecy means a fresh tab without local state cannot decrypt history it was absent for (lose-device-lose-history). Acceptable for a self-sovereign client; the custodial alternative trades it for plaintext-at-the-server.
- A single-tab driver needs its own crash/consistency story to replace the actor's bounded-crash-persist + per-context send serialization (snapshot cadence to IndexedDB; the §9.9.3 checkpoint compare is sync-available).

## Alternatives Considered

1. **Remote thin client with node-held keys (ADR-055's stated direction).** Rejected as the *primary* model: the node holds the user's keys and group secrets, sees plaintext, and can impersonate — custodial, violating encryption-as-access-control / relays-are-untrusted / human-accountability. It remains a valid *secondary, opt-in* option for users who explicitly choose convenience over self-sovereignty (a documented custodial mode), but it is not the default and not what "browser client" means.
2. **Re-implement the protocol in wasm (the deleted WASM bridge).** Rejected: this is exactly the parity tax ADR-055 removed. Shared code via `scp-mls` achieves in-browser execution without it.
3. **Leave the browser unsupported.** Rejected: in-browser SCP clients are high-value, and the feasibility work shows the cost is bounded.

## Implementation Slices (forward-only)

1. **`scp-mls` extraction** — create the crate (9 sync files + the 3 prerequisite fixes); compiles native **and** wasm32; `scp-runtime` adopts it (no behavior change on native). Tests on both targets.
2. **Browser driver MVP** — one context end-to-end in-tab: create/join, send+encrypt, receive+decrypt, process commit. Over shared `scp-mls`/`scp-protocol`.
3. **Browser platform infra + TS SDK browser backend** — restore key custody / storage / transport / time; wire the browser backend behind the existing `@limn-works/scp-ts` API.
4. **Re-add browser examples** (closes the intent behind #1951) as in-browser-client demos.
5. **Presence** — a separate ADR (cold-presence semantics now; attenuated keep-alive delegate as open research).

## Evidence

- wasm32 compile spike: `cargo check --target wasm32-unknown-unknown` → exit 0 on the lifted MLS machine.
- Participant-path feasibility audit: the create/join/send/receive/process-commit/close/event-log path is single-threadable; the only hard blockers (the durable-storage `block_in_place` bridge; paid-economy `await`s) are avoidable (in-memory provider + IndexedDB snapshot) or out of scope (free contexts; the deleted bridge fail-closed-rejected paid sends).
- Restoration source: the deleted bridge at `1a3b41a5e^` (`git show 1a3b41a5e^:crates/scp-ffi/wasm/...`).
