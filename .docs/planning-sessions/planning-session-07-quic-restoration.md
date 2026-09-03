# SCP Planning Session 07 — QUIC Transport Restoration and Integration

**Date:** June 1–2, 2026
**Scope:** Restore the broken `quic` cargo feature in `crates/scp-transport`, close the integration gaps the compile-break masked, and reconcile the affected PRD stories.
**Status:** Executing — PR-1 in merge queue; PR-2/3a/3b/4 pending. Decisions D1–D6 locked.
**Provenance:** ADR-037 (`.docs/adrs/phase-2.md`, Status: Decided, QUIC = Tier 1); spec §10.14 / §10.14.2 / §10.14.3 / §10.5.1 (`.docs/specs/10-infrastructure-and-self-hosting.md`); PRD stories SCP-254..257 (`.docs/prds/transport-expansion.json`).

## Progress Log

| PR | Status | Notes |
|----|--------|-------|
| PR-1 Restore lifecycle types | ✅ Merged (#1742) | Reviewed clean (cryptographer + bug-catcher). Scope grew: see "Modification 1". |
| PR-2 Green + gate optional transports | ✅ Merged (#1745) | Greened http3/udp/coap + widened gate to all four. Exposed + fixed flaky loopback DTLS tests (see Modification 6). |
| PR-3b Relay listener wiring | ✅ Merged (#1743) | One MEDIUM bug found & fixed (advertise-on-bind-failure). Carries scp-transport crypto-provider fix (Modification 5). |
| PR-3a Native selection | 🟡 In merge queue (#1746) | Reviewed (security SOUND + bug-catcher ×2). Fixed a HIGH IPv4-only-bind bug + 0-RTT doc wording + userinfo strip. **Selector built but not yet fed** — see PR-3c. |
| PR-3c Plumb transport discovery | ⏳ Pending (user-approved) | Fetch `.well-known/scp` transports at connect → feed selector so QUIC is actually selected end-to-end (transparent, D3). Starts after PR-3a. |
| PR-4 Conformance + PRD reconciliation | ⏳ Pending | Includes committing this plan artifact. |

- **Modification 6 (flaky DTLS tests — discovered via PR-2's gate):** PR-2's new gate ran the udp DTLS tests in CI for the first time ever; two flaked under CI parallelism. Root cause: the test DTLS client blocks the full 10s read timeout per `recv` (OpenSSL blocking DTLS can't fire its retransmission timer mid-`recv`), so a `SO_REUSEPORT`-misrouted loopback handshake compounds to ~150s and exhausts the 3-retry limit. Fix (PR-2): added `connect_with_timeout` (production `connect` unchanged at 10s); test client uses a 1.5s per-`recv` timeout — which MUST stay above OpenSSL's ~1s DTLS1.2 retransmission floor (400ms made every handshake abort) — with 8 attempts + backoff. Verified 20/20 green at `--test-threads 16`. The gate worked as intended: it caught real rot on first contact.
- **Modification 7 (PR-3c split):** PR-3a delivers the selector + QUIC client (verified, secure) but leaves QUIC unselected because the advertised-transports list isn't available at the FFI connect sites. User approved closing this in a follow-up PR-3c that fetches `.well-known/scp` transports at connect and feeds the selector (transparent — FFI does discovery, no signature change per D3).

- **Modification 4 (PR-2 scope — user-approved 2026-06-02):** PR-2's CI gate exposed that **http3, udp, and coap are also rotting** (same class as the quic break): `coap` won't compile standalone (its feature omits `udp` but `coap/adapter.rs` uses `crate::udp::dtls`), `http3` has a real `Http3Server::bind()` arity break **and** the same rustls dual-provider panic latent in `http3/config.rs:357` (bare `ServerConfig::builder()`), and `udp`/`http3` carry clippy debt. User chose "green all + widen gate": PR-2 now greens all three and widens the CI gate to clippy+test `quic,http3,udp,coap`. The initial quic-only ci.yml step (commit `ccb45e022`) is folded into this expanded PR.
- **Modification 5 (crypto-provider standardization):** PR-3b fixes a rustls dual-provider panic — `instant-acme` pulls `aws-lc-rs` alongside SCP's `ring`, making the bare `ServerConfig::builder()` process-default ambiguous (panics). Fix: pin `quinn` off `platform-verifier`, name `ring` explicitly via `builder_with_provider`. **Forward constraint for PR-3a:** since `platform-verifier` is dropped, the QUIC *client* config must supply its own `RootCertStore`/`ServerCertVerifier` via `builder_with_provider(ring)` — never an implicit/permissive fallback. The identical bare-builder latent panic at `http3/config.rs:357` is fixed in the expanded PR-2.

### Operational incident (worktree contention)

During parallel coder dispatch, agents given `isolation: "worktree"` had their **absolute-path Read/Edit/Write operations leak into the repo root** (`/Users/alec/Developer/limn/scp`, checked out to another session's `remediation/r3-wasm` branch) instead of their own worktree, because the root path prefix is shared. Agents self-detected and reverted; no deliverable damage (commits landed correctly on their own branches; main worktree left with only untracked files). **Mitigation for remaining dispatches:** every coder prompt now mandates worktree-absolute paths and a `git -C <worktree> rev-parse --abbrev-ref HEAD` branch-confirmation guard before editing. Reviewers are likewise told to read only from the worktree path.

### Modifications discovered during execution

- **Modification 1 (PR-1 scope):** Greening `--features quic` for clippy surfaced **pre-existing** lints in `quic/adapter.rs` and `quic/listener.rs` that had never run (CI never built the feature). PR-1 therefore also includes behavior-preserving clippy fixes beyond the pure restore: duration-unit constructors (`from_secs`→`from_hours`/`from_mins`, arithmetically identical), `too_many_lines` extraction of the subscribe read loop into a free `async fn` (verbatim body — same extraction reverted from #1734, now justified because PR-2 makes CI clippy the feature), doc backticks, one `map_or_else`. #1734's registration-leak fix is untouched. Verified behavior-preserving by bug-catcher (byte-equivalent extraction) and cryptographer (zero drift in crypto bodies).
- **Modification 2 (toolchain):** The plan assumed "signatures match exactly" (quinn 0.11.9 / rustls 0.23.37 unchanged — confirmed true). It did NOT anticipate that rustc/clippy **1.95.0** introduced new *style* lints postdating the deleted code; these drove Modification 1. No API drift; only lint surface.
- **Modification 3 (PR-1 file count):** Plan listed PR-1 as touching only `lifecycle.rs`. Actual: `lifecycle.rs` + `adapter.rs` + `listener.rs` (per Modification 1). All within `scp-transport`, all behavior-preserving.

### Corrections to the original investigation (now reflected below)

- Spec citation for probe/fallback is **§10.14.3 item 4**, not §10.14.3.4 [no such section]. Advertisement format is **§10.5.1**.
- The "~270 lines deleted" figure is closer to **~530 lines restored** (the four type bodies + impls + consts + the `ClientSessionStore` impl); `git show --stat` for PR-1 shows +561 in lifecycle.rs.

---

## 1. Root Cause

The `quic` feature does not compile. Commit `b288d64c5` ("production readiness — implement 28 remaining items") deleted ~270 lines of real, working type definitions from `crates/scp-transport/src/quic/lifecycle.rs` while correctly extracting `ReconnectBackoff` into `crates/scp-transport/src/backoff.rs` — but left every consumer (`QuicLifecycleManager`, its methods, ~30 tests, the `quic/mod.rs` re-export, and `quic/adapter.rs` which holds `RwLock<QuicLifecycleManager>`).

Deleted types (recoverable **verbatim** from `b516c46df:crates/scp-transport/src/quic/lifecycle.rs`, lines ~44–311):
`SessionTicket`, `SessionTicketStore` (+ `SessionTicketStoreInner` + `impl rustls::client::ClientSessionStore`), `ConnectionMigrationEvent`, `QuicKeepaliveConfig`, plus consts `DEFAULT_TICKET_STORE_CAPACITY`, `MAX_TLS13_TICKETS_PER_SERVER`, `DEFAULT_KEEPALIVE_INTERVAL` and the free fn `evict_oldest`.

CI never caught it: `.github/workflows/ci.yml` tests `scp-transport` only with `--features combined,local-cache`; no workflow builds `--features quic` or `--all-features`. The feature has been un-compilable since `b288d64c5` and CI has been structurally blind to it.

## 2. Gaps the Compile-Break Masked

1. **`QuicListener` is never started by the node binary.** `scp-node` serves only WebSocket; `QuicListener::start` is called only in unit tests. SCP-257 AC1 ("relay accepts QUIC on the same TLS port") is unmet at the binary level.
2. **No native QUIC↔WebSocket selection.** The QUIC adapter exists but nothing selects it. The only transparent fallback heuristic that ships is `webtransport/fallback.rs` (WebTransport→WebSocket, browser path). §10.14.3 item 4 (native probe/fallback) has no implementing code and no story.
3. **`transport_conformance!` is invoked nowhere** in the repo — not even for the native adapter.
4. **No cross-transport integration test** (SCP-257 AC6: publish via WebSocket → deliver to QUIC subscriber).
5. **`.well-known/scp` advertises `"quic"`** (`scp-node/src/well_known.rs`) — a transport the binary doesn't actually serve. Live inconsistency.

NAT/STUN/ICE selection (`crates/scp-transport/src/nat/`, `webrtc/`, `scp-media`) is a **separate subsystem** (WebRTC media, peer-to-peer DTLS-SRTP) and is out of scope.

## 3. Decisions (locked)

| # | Decision | Resolution | Basis |
|---|----------|-----------|-------|
| D1 | Probe preference order | Prefer QUIC when advertised | §10.5.1 (client SHOULD prefer QUIC) |
| D2 | Probe timeout | 3 seconds, fall back on timeout | §10.14.3 item 4 |
| D3 | Selection surface | **Internal / transparent** — below the `TransportAdapter` boundary; no FFI/SDK/capability-matrix change | mirrors existing `webtransport/fallback.rs` pattern |
| D4 | Client TLS trust | Reuse relay TLS trust model (`relay/connection.rs`); custom verifier for local `ws://` test relays | §10.14.3 (relay cert covers both protocols) |
| D5 | PR-3 split | Split into PR-3a (client selection) and PR-3b (relay listener wiring) | different crates, independent acceptance |
| D6 | Story status | Set SCP-256 and SCP-257 → `in-progress` (were falsely `done`); add new stories for native-selection and listener-wiring | artifact-flow: corrections flow down from spec |

**Removal was rejected:** the one-way artifact-flow invariant forbids deleting spec-mandated behavior without first amending a Decided Tier-1 ADR.

## 4. PR Decomposition (strictly ordered)

### PR-1 — Restore lifecycle types + green the `quic` feature  — 🟡 IN MERGE QUEUE (#1742)
*Done: restored all four types verbatim; feature builds + clippies clean + 687 lib/38 conformance/4 doc tests pass under `--features quic`. Also fixed pre-existing `adapter.rs`/`listener.rs` clippy debt (see Modification 1). Reviewed clean by cryptographer + bug-catcher. Branch `fix/restore-quic-lifecycle-types`, commit `8d7bf38c9`.*
- Re-insert the four deleted types into `lifecycle.rs` verbatim from `b516c46df` (lines ~44–311).
- **Do NOT** re-add `use rand::Rng` (lives only in `backoff.rs`) or restore `ReconnectBackoff` (re-exported from `backoff.rs`).
- Existing imports in `lifecycle.rs` already match the restored types (the 8 current unused-import warnings map 1:1).
- Green: `cargo clippy -p scp-transport --features quic --all-targets -- -D warnings` and `cargo test -p scp-transport --features quic`.

### PR-2 — CI coverage for optional transports
- Add to `.github/workflows/ci.yml`: clippy + test steps for `--features quic` (and `http3,udp,coap` where they co-compile; split per-feature if link conflicts via openssl/quinn).
- ci.yml is not an enforcement file; additive coverage is permitted.

### PR-3a — Native QUIC probe-and-fallback selection (transparent)
- New `crates/scp-transport/src/selection.rs`: `TransportSelector` / `select_and_connect`, modeled on `webtransport/fallback.rs`. Probe QUIC (3 s) when `.well-known/scp` advertises `"quic"`; fall back to `NativeRelayAdapter`; suppress re-probe until next well-known refresh. Returns `Box<dyn TransportAdapter>` — transparent to callers.
- Add `QuicAdapter::connect_url(...)` (host resolution + ALPN + `ClientConfig` with the restored `SessionTicketStore` for 0-RTT).
- Route `crates/scp-ffi/src/transport.rs` + `server.rs` connect sites through the selector (signatures unchanged). Plumb the advertised-transports list to those sites; degrade to WebSocket-only where unavailable.
- **Security gate:** PUBLISH/DELETE/UNSUBSCRIBE must never ride 0-RTT (§10.14.2). cryptographer + security-reviewer required.

### PR-3b — Wire relay QUIC listener into the node serve path
- In `scp-node` (`lib.rs` serve path + relay-start sites; `main.rs`), behind `cfg(feature="quic")`, start `QuicListener` on the same UDP port as the WebSocket TCP port, sharing `SubscriptionRegistry` + `BlobStorageBackend`; tie into the cancellation token.
- Advertise `"quic"` in `.well-known/scp` only when the listener is actually started (close gap #5).

### PR-4 — Conformance + capability matrix + story reconciliation
- `crates/scp-transport/tests/quic_conformance.rs`: invoke `transport_conformance!` against an in-process QUIC listener (extract the reusable harness from `adapter.rs` tests).
- Cross-transport test (publish-WS → receive-QUIC) for SCP-257 AC6.
- **Capability matrix untouched** (D3 = internal); document the no-change rationale in the PR.
- PRD reconciliation (`.docs/prds/transport-expansion.json`): SCP-254 keep `done`; SCP-255 keep `done` (verify AC6 by reading tests); SCP-256 → `done` after AC2 migration test lands; SCP-257 → `done` after PR-3b wiring + AC6 test; add new stories for native selection (§10.14.3 item 4) and listener wiring. Run `python3.12 scripts/validate-prd.py`.

**Sequence:** PR-1 → PR-2 → PR-3a → PR-3b → PR-4. PR-4's PRD status corrections must not land before the code that makes them true.

## 5. Risk Register (abridged)

- **quinn/rustls API drift** — Low (versions identical: quinn 0.11.9, rustls 0.23.37; `keep_alive_interval` + `ClientSessionStore` signatures verified unchanged).
- **`use rand` re-added** → unused-import clippy failure. PR-1 AC greps for it = 0.
- **Cross-feature link conflicts** (`udp`+`coap` → openssl; `quic`+`http3` → quinn) in the new CI step. Split per-feature if needed.
- **`transport_conformance!` has never been invoked** — the macro may assume a synchronous factory; QUIC needs an async listener. Budget extra time in PR-4.
- **0-RTT replay of non-idempotent ops** — security-critical; gated review on PR-3.
- **PRD status correction landing before code** → re-creates false-`done`. Enforce ordering.
