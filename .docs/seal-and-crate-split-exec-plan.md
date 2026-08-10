# Execution plan — close the nullifier arc, split the crate, ship a production server surface

**Status:** plan of record. Written 2026-08-10.
**Scope:** everything in the two original arcs. Unrelated drift was filed separately and is out of scope here.

---

## 0. Why this plan exists

Two arcs opened this workstream and neither is finished.

**The nullifier arc** — "no dev/test stand-in may be reachable on a shipped path, and prove absence mechanically." It was declared complete and "G1-proven." That claim was false: the gate proving it could not see the largest nullifier in the tree, because its allowlist-hygiene assertion compares each allowlist line against a hand-enumerated array of eleven nullifier feature names by exact match, and `allow_unencrypted_storage` is not one of the eleven.

**The crate-splitting arc** — `scp-node` unconditionally compiles the AWS S3 SDK, Postgres, redb, an ACME client the self-host path hard-rejects, and a Prometheus exporter. Never started. A tracking item has carried the architectural audit since 2026-05-03 and was never referenced.

Everything below serves one of those two.

### The load-bearing fact

`allow_unencrypted_storage` reaches all three shipped bridges for **exactly one reason**: `start_node_in_memory` and `start_node_local` call `Node::start_for_testing`, which is gated on it. Nothing else in `crates/scp-ffi/**` touches an item behind that feature — there is no `ProtocolRepository::new_for_testing` call anywhere in the FFI tree, and the only `start_for_testing` call sites are three, all inside those two functions (`crates/scp-ffi/common/src/server.rs:343`, `:459`, `:512`).

So the whole chain is one causal line:

> no production node API → dev constructors are the only node API → they need `Node::start_for_testing` → which needs `allow_unencrypted_storage` → which is enabled in four shipped manifests → which the gate allowlists → which makes the gate's "zero nullifiers, no exceptions" header false.

Adding a production `start` is not a feature request. It is the thing that lets the seal close.

**This is already a spec violation.** `.docs/specs/17-persistence-and-storage.md:410` states verbatim: *"Production code (FFI bridges, application nodes, SDK wrappers) must NOT enable this feature."* All four FFI manifests do (`crates/scp-ffi/Cargo.toml:69`, `crates/scp-ffi/common/Cargo.toml:67`, `crates/scp-ffi/napi/Cargo.toml:73`, `crates/scp-ffi/uniffi/Cargo.toml:62`). No spec change is needed to justify the fix.

---

## 1. Settled decisions

| Decision | Value |
|---|---|
| Dev constructors (`startInMemory` / `startLocal`) | Stay exposed in the **server SDKs**. Cut from production builds. |
| Production `start` | Added for **node** and **relay**, at parity. |
| SDK scope | **Rust** (already has `Node::start`), **Python**, **TypeScript**, **Swift**. |
| Swift | **IN, but `#if os(macOS)`-gated.** Production node and relay start are macOS-only. |
| Kotlin | **Removed entirely** — node and server bindings both. See Track E. |
| Storage for the production node | **Not a parameter.** Reuse the `SCP` instance's already-selected encrypted storage. See Track C. |

**Why Swift is macOS-only, and why that is a correctness constraint rather than a preference.** The Swift package declares `.iOS(.v17)` and `.macOS(.v14)` (`bindings/swift/Package.swift:6-9`) and `bindings/swift/Sources/SCP/Server.swift` carries **zero** platform guards today. macOS can bind a port and stay resident, so an embedded node is viable there. iOS cannot: apps suspend within seconds of backgrounding, and `BGTaskScheduler` grants opportunistic execution, not a persistent listener. An iOS-hosted node would bind a port that dies on backgrounding **and publish a DID document advertising a relay address it cannot serve** — a record that then survives republish cycles and relay slots long after the app is gone. That is a false guarantee: precisely the class of defect this whole arc exists to eliminate, so shipping it ungated would reintroduce the tenet violation in a new place. It is the same platform reality that justifies removing Kotlin (Track E); Swift's only difference is that it additionally ships macOS.

---

## 2. Review discipline — applies to every track

**Every track lands only after a genuine double-zero review.** Double-zero means **two consecutive full-roster passes that each return ZERO findings, both run against the identical final committed state.**

The rules that make that real:

- **A pass that produces findings is not a zero.** Fixing findings resets the count. Both clean passes must come *after* the last change; a clean pass on an earlier state says nothing about the state that ships.
- **Use the full default review roster** from `CLAUDE.md` — black-hat, red-hat, white-hat, security-reviewer, cryptographer, bug-catcher, chronicler, alignment-reviewer, completionist, inquisitor, api-design-reviewer, simplifier — adding or removing reviewers according to the nature of the change. Sizing the roster to the work is allowed. Skipping the bar is not.
- **Prior "reviewed" claims are not evidence.** Re-derive from the code. A review recorded by an earlier session, or by the agent that wrote the change, does not carry over.
- **No self-invented exemptions.** If a change genuinely warrants a reduced roster, that is agreed in advance and written down — never decided by whoever is about to merge. An exemption invented in prose and then relied upon is how unreviewed work has shipped here before.
- **Report the actual verdicts, not a summary of them.** State each reviewer's finding count and severity. A claimed "zero findings" that contradicts the same pass's own reported findings is a false statement to the user, not a rounding.
- **Confirm, then merge — never merge, then confirm.** Nothing is armed for merge before the second consecutive zero.

This is written into the plan of record because the discipline has repeatedly failed in practice in this repo, not because it is ceremony. A recovered session record shows only a small fraction of previously *claimed* double-zeros were real. One branch inside this very plan — the relay WRITE path in Track G — was reported clean when its review had in fact returned a BLOCKER plus several MEDIUM findings, and its final state has still never been reviewed at all. A recent pull request was merged with zero reviewers under an exemption its own author invented.

---

## 3. Tracks

### Track A — Crate splitting (build weight)

A tracking item has existed since 2026-05-03 with the architectural audit already done. **Build on it; do not re-derive.** One of its six acceptance criteria already landed as the dev-profile debug-info change and was never credited — check that box rather than redoing it.

**Verified claims:** `scp-node` and `scp-relay` both enable `sqlite-blob, redb-blob, postgres-blob, s3-blob, startup` unconditionally (`crates/scp-node/Cargo.toml:24-30`, `crates/scp-relay/Cargo.toml:18-24`). `scp-node`'s `[features]` table contains no corresponding gates; `scp-relay` has no `[features]` table at all. `instant-acme` is non-optional (`crates/scp-node/Cargo.toml:43`).

**Corrected claim — the Prometheus exporter is not dead weight.** An earlier draft asserted that `metrics::` had zero hits across every crate's `src` and that no library emits a single metric. Both halves are false, and the false negative came from a `git grep` pathspec that silently matched nothing. `scp-runtime` is a library and it does emit: `crates/scp-runtime/src/metrics.rs` defines eleven `counter!`/`gauge!`/`histogram!` emitters, and twelve further files call them on live production paths (`context/supervisor/supervisor.rs`, `context/supervisor/saga_journal.rs`, `context/messaging_helpers.rs`, and others). What *is* true, and what the gating decision actually rests on: `scp-node` and `scp-relay` reference `metrics` / `metrics-exporter-prometheus` **only in `main.rs`**, to install the global recorder and serve `/metrics` (`crates/scp-node/src/main.rs:1030-1060`, `crates/scp-relay/src/main.rs:65-112`). Gating them behind `node-bin` is therefore correct — a library consumer of `scp-node` needs no exporter — but the justification is "only the binary installs a recorder," not "nothing emits."

**Measured — and smaller than the earlier draft claimed.** Dropping `postgres-blob` + `s3-blob` removes **78 crates**, taking `scp-transport`'s resolved no-dev graph from 366 to 288 — a **21%** reduction — of which **23 are `aws-*`**. The earlier figures (150 crates, ~26%, 40 `aws-*`) are wrong; there are only 23 `aws-*` crates in the entire workspace graph, so 40 was never attainable. Measurement basis: `cargo tree -p scp-transport -e no-dev` with `sqlite-blob,redb-blob,startup` versus the same plus `postgres-blob,s3-blob`. Measured from a downstream crate the delta can only shrink, never grow — `aws-lc-rs` / `aws-lc-sys` arrive via rustls independently, so they drop out of the delta wherever rustls is already present. Treat 78 as an upper bound and re-measure per artifact (see Acceptance).

**Corrected claim:** `instant-acme` is *not* dead weight. The self-host path does hard-reject `TlsMode::Acme`, but ACME is live and default on the `Reach::Domain` path — `resolve_tls` (`crates/scp-node/src/lib.rs:2874`) falls through to `AcmeProvider` whenever no provider is supplied. Gating it is free for self-host consumers, not free in general → `acme` defaults **on**.

**Spec constraint:** §17.17 requires a shipped relay retain a durable blob backend — `InMemoryBlobStore` may "never be the sole reachable arm" (`.docs/specs/17-persistence-and-storage.md:581`). So `sqlite-blob` stays ungated. It is also load-bearing: `build_host_site_node` calls `BlobStorageBackend::sqlite` unconditionally (`crates/scp-node/src/self_host.rs:2223`), and that is the path every `host_site()` consumer funnels through.

**Feature table (`scp-node`):**

| Feature | Default | Controls |
|---|---|---|
| *(ungated)* | — | `scp-transport/sqlite-blob` — load-bearing for `host_site()` |
| `node-bin` | yes | `metrics`, `metrics-exporter-prometheus`, `startup`, `redb-blob`; `required-features` on `[[bin]]` |
| `acme` | yes | `instant-acme` |
| `cloud-blobs` | **no** | `postgres-blob`, `s3-blob` — the 78-crate win |

`scp-relay` is bin-only with no library consumers; it needs only `cloud-blobs`.

**The `cfg` work is the real work,** not the manifest edit. `scp-transport` needs no changes — it is already correctly gated. Downstream: the four FFI manifests and `scp-testing` must add `default-features = false` to their `scp-node` edge or the saving is not realized.

**Required inline fix:** `VALID_BACKENDS` is a hardcoded string constant (`crates/scp-transport/src/startup.rs:79`) interpolated straight into `storage_from_env`'s rejection message (`:171`). Once `postgres-blob` is default-off, setting that backend yields *"unknown storage backend 'postgres'. Valid options: sqlite, redb, postgres, s3, memory"* — naming the value it just rejected as valid. It must become `cfg`-derived and distinguish "not a backend" from "not compiled in — rebuild with `--features cloud-blobs`."

**Critical risk — R1.** With `acme` off, `resolve_tls` currently cannot fail — its signature returns `Arc<dyn TlsProvider>`, not a `Result`, and it ends in an infallible `unwrap_or_else` — and the tempting fix is to fall back to self-signed. **Forbidden.** That serves a self-signed cert to the public internet on a domain node whose operator asked for a CA cert. It must fail closed with a typed error, rejected at `validate_config` (`crates/scp-node/src/config.rs:573`). Note `dns_provider` already does exactly this fallback on DNS-API failure (`crates/scp-node/src/dns_provider.rs:417-424`) — in-repo prior art that will be cited as precedent. It is not: a transient-network fallback and a compile-time-absent backend are different things.

**Other risks:** `node-bin` must stay in `default` or `cargo build -p scp-node` silently emits no binary and the Dockerfile `COPY` fails. Cargo feature unification means both `scp-node` and `scp-relay` must change or neither is worth doing. Removing default features is semver-breaking for published crates.

**Acceptance:** a measured before/after size delta on clean from-scratch builds in isolated target dirs with identical feature sets and a unit-graph equivalence check — not "it compiles." A prior measurement here was confounded by the shared target dir. Also measure the three release cdylibs; that is the user-facing win. Rebuild the external consumer against local main as the real end-to-end test. Not complete until it has cleared double-zero as defined in §2.

**Slices:** A1 `cloud-blobs` (manifest + the diagnostic fix; largest win, zero behaviour change — ship and measure alone so the number is attributable). A2 `node-bin`. A3 `acme` (the only slice with a real fail-closed design decision; needs the security roster).

---

### Track B — The seal

**B1. Gate the dev constructor bodies, not the symbols.**

Release Swift bindings are generated *from the built library* with no `testing` feature. `#[cfg]`-erasing the exported bridge methods would delete them from the generated surface and force removing them from the Swift SDK — contradicting "dev constructors stay exposed." So erase the **`Node::start_for_testing` call sites** (three of them, across the two functions), keep every symbol:

```rust
#[cfg(any(test, feature = "testing"))]
… Node::start_for_testing(NodeConfig { … }) …
#[cfg(not(any(test, feature = "testing")))]
return Err(ServerError::DevHarnessUnavailable);
```

This is the existing pattern in the same file — `ServerError::AutoGenerateUnavailable` (`crates/scp-ffi/common/src/server.rs:107`, used at `:336`) — and satisfies SCP-CAPSEL-8012: the arm is provably absent from the artifact; what remains is a typed error, the honest absent state the tenets require.

**Payoff: zero edits to protected enforcement files.** The `#[cfg]`-erase alternative would force a `true → false` edit in the capability matrix and alias removals in the coverage script — both unambiguous weakening.

**B2. Remove the feature from the four FFI manifests.** Verified empirically: after removal, `allow_unencrypted_storage` is gone from the production resolve, and under `--features testing` it returns automatically via the existing feature chain (`crates/scp-node/Cargo.toml:115`). No extra wiring needed for test builds.

**B3. Remove the three allowlist entries from the gate** — `scp-core/allow_unencrypted_storage`, `scp-node/allow_unencrypted_storage`, `scp-runtime/allow_unencrypted_storage` (`scripts/check-shipped-feature-graph.sh:62`, `:77`, `:89`). These are a live violation of the gate's own header, which claims "ZERO nullifier features, no exceptions" (`:51-53`). The feature unseals `ProtocolRepository`'s `EncryptedStorage` bound — it nullifies confidentiality, which §17.17.2 names explicitly.

**B4. Add the node and relay binaries to the gate's artifact list.** The `ARTIFACTS` array covers only the three FFI bridges (`scripts/check-shipped-feature-graph.sh:99-103`). Verified: both binaries **pass the unmodified gate today**. This is pure future-regression protection — today nothing stops someone adding `testing` to a `scp-node` dependency and shipping a nullifier in the Docker image and the published binary, unobserved.

**B5. Drop `scp-platform/filesystem` from every edge that enables it — not just the `server` feature.** `start_node_local` holds the only `FilesystemStorage` *construction* in the whole FFI tree (`crates/scp-ffi/common/src/server.rs:448`), so gating the constructor is the right move. But **dropping the feature from `scp-ffi-common`'s `server` feature alone does not remove the impl from the shipped graph**, and an earlier draft claimed it did. `filesystem` is enabled in four places, and all four must go:

- `crates/scp-ffi/common/Cargo.toml:51` — the `server` feature itself
- `crates/scp-ffi/Cargo.toml:75` — PyO3's own unconditional `scp-platform` edge
- `crates/scp-ffi/napi/Cargo.toml:81` — NAPI's, likewise
- `crates/scp-ffi/uniffi/Cargo.toml:77` — UniFFI's, likewise

Only once all four are gone does the plaintext-capable `Storage` impl leave the shipped graph, and only then can `scp-platform/filesystem` come off the gate's allowlist.

**B6. Reframe the allowlist-hygiene check.** The main ⊆-subset gate is sound. The hygiene assertion is a **denylist**: `assert_allowlist_has_no_nullifier` (`scripts/check-shipped-feature-graph.sh:219`) iterates `NULLIFIER_CONTROL_FEATURES`, a hand-enumerated array of eleven nullifier names, and exact-matches each against the allowlist. It missed `allow_unencrypted_storage` for the only reason a denylist ever misses anything — the name is not in the array. Adding a twelfth string is another fixture chasing one more spelling.

Replace with a **classification registry**: every permitted entry carries a classification from a closed vocabulary (`durability-only` | `real-backend`), the allowlist is derived from it, and an assertion rejects any unclassified or unrecognised entry. A nullifier has no representable classification, so it cannot be added — names are never the mechanism. This mechanizes a requirement §17.17.2 already imposes.

**Approval needed:** deleting the old assertion is structurally the removal of an existing assertion. Fallback if not granted: keep both. Slightly redundant, still correct.

**Ordering — and the real trap.** B4 is independent and should land **first**, as its own commit. B1+B2+B3 must be **atomic in one commit** (manifest without code gate → compile failure; allowlist without manifest → three G1 failures; code gate without manifest → green but a no-op seal). B5 after. **B6 last** — if the classification registry lands before B3, the three nullifier entries would need a classification they cannot have, and CI reds on exactly the thing being fixed.

**Also required:** one CI lane runs `cargo test -p scp-ffi-napi --features server` (`.github/workflows/ci.yml:614`, job `rust-test-napi-production`) and today survives only via dev-dependency feature unification. Make it explicit: `--features server,testing`.

**After B1–B5 the seal is complete for protocol state.** `Node::start` (`crates/scp-node/src/config.rs:1159`) is bounded on `S: EncryptedStorage`, a *sealed* marker trait (`crates/scp-platform/src/encrypted.rs:35`, with a private `Sealed` supertrait at `:22`); the only implementors are `SqliteStorage`, `AppleStorage`, `EncryptingAdapter<S>`, and `Arc<T: EncryptedStorage>`. `InMemoryStorage` and `FilesystemStorage` implement neither. The compiler — not a gate — then forbids a plaintext protocol-state node on any shipped path.

*Out of audited scope, stated rather than assumed:* relay **blob** storage at-rest properties, and `FileKeyCustody`. Neither is changed by this plan.

Track B is not complete until it has cleared double-zero as defined in §2.

---

### Track C — Production node `start`

Add `node_start` to `crates/scp-ffi/common/src/server.rs`, routed through `Node::start`, plus FFI enum mirrors and a flat config object. Exposed on Rust (exists), Python, TypeScript, and Swift-on-macOS.

**Swift implementation note.** The `#if os(macOS)` guard goes on the hand-written SDK wrapper in `bindings/swift/Sources/SCP/Server.swift`. The UniFFI-generated layer is platform-agnostic and needs no guard. On iOS the capability is then **absent** — detectable — rather than present and broken. The existing dev constructors need no additional platform gating: after B1 they return a typed `DevHarnessUnavailable` in any non-`testing` build, so they are already inert in a shipped iOS app. Do not add redundant guards to them.

**Storage is not a parameter.** The `SCP` instance already made a mandatory, fail-closed storage selection, and both arms already satisfy `EncryptedStorage`. Reusing that handle means no new plumbing and avoids a guaranteed footgun: `SqliteStorage::new` takes a **directory** and acquires a *non-blocking* exclusive advisory lock on a sibling `scp.db.lock` file (`crates/scp-platform/src/sqlite/mod.rs:116-145`), so a `node_start` taking its own directory would fail hard on the most obvious call an agent writes — passing the same directory given to the instance. It also prevents a second store diverging from the first.

In-memory **is** accepted — it is durability-only, AES-256-GCM encrypted through the adapter, and already an explicit selection — but it must warn loudly that all state is lost on drop.

**Config object** (`NodeStartConfig`, deliberately not `NodeConfig` — both are in scope in the converting function):

Required: `reach`, `identity`, `blob_storage`, `tls`, `dht`, `cors_origins`.
Optional with fail-safe defaults: `bind_addr`, `http_bind_addr`, `dht_gateways`, `nat`, `projection_rate_limit`.

Note that the core `NodeConfig` (`crates/scp-node/src/config.rs:330-414`) also carries `storage` (supplied by the instance, per above) and `network_detector`; neither is a mirror field.

`tls` and `dht` are **required at the FFI layer** even though the core defaults them: two of the bridges are dynamically typed, where an optional field with a default means a typo'd key silently selects it. Stricter than the standard, never weaker.

`cors_origins` is required because the core's `None` means permissive `*` — confirmed behaviourally, `None` resolves to `AllowOrigin::any()` (`crates/scp-node/src/http.rs:305`). That must never be reachable by omission.

**`http_bind_addr` — resolved, no longer an open question.** Its `0.0.0.0:8443` default (`crates/scp-node/src/lib.rs:78`) is **not bound at `Node::start`**. The only socket `start` binds is the relay on `bind_addr`; `http_bind_addr` is merely stored on `NodeState` and read for NAT tier selection. The actual bind happens later, in `ApplicationNode::serve` → `serve_with_surface` (`crates/scp-node/src/http.rs:731`). So it needs no `cors_origins`-style treatment. Worth carrying forward as a separate defect, though: `serve_background*` ignores `NodeConfig::http_bind_addr` entirely and defaults to `127.0.0.1:8443` from its own parameter (`crates/scp-node/src/lib.rs:89`, applied at `:755`) — the config field is silently inert on that path.

**Enum mirrors:** `FfiReach` (complete), `FfiTlsMode` (omits `Custom` — `Custom(Arc<dyn TlsProvider>)`, a trait object, per its own doc at `config.rs:192`), `FfiDhtMode` (omits `Memory` — a `#[cfg(feature = "testing")]`-gated nullifier at `config.rs:237`, and its omission is enforced by the feature graph, not by discipline), the NAT mirror (the core enum is named **`NatSlot`**, not `NatMode`; omit both `Custom(Arc<dyn NatStrategy>)` and the `Tuned` variant, which also carries trait-object slots), and `FfiBlobBackend`.

**Deliberately not exposed:** `local_api`, `http3` (not compiled in any bridge — the field itself is `#[cfg(feature = "http3")]`-gated), the core `dht_gateways` field (destructured away as `dht_gateways: _` by `split_config`, `crates/scp-node/src/config.rs:627` — thread it into the DHT client where it is load-bearing instead), and `dns_provider`.

**Correction on `local_api`.** An earlier draft justified excluding it as "mints a dev bearer token on an unauthenticated control surface." The surface is *not* unauthenticated: `dev_router` layers a localhost-only `Host` check and a constant-time bearer comparison (`crates/scp-node/src/dev_api.rs:53-74`, `:114-127`, `:538-572`), and the token is 16 bytes of `OsRng`. The honest reason to withhold it is narrower and still sufficient: it is a *development* control plane whose token is minted by the node and handed back through the handle, which is not a shape we want to define across four SDKs in this pass.

**`dns_provider` is blocked upstream.** It silently *overrides* whatever `tls` selected — and overwrites `domain` with it (`crates/scp-node/src/config.rs:923-938`) — a hidden precedence rule an agent cannot read from the signature. It is also threaded only into `build_node_domain`; on `NatTraversal` / `Tunnel` / `Local` reaches it is dropped with no warning. The correct fix is a `TlsMode::DnsSubdomain { … }` variant in the **core** enum, which the mirror then carries. That is an ADR-052 change and must land first per the artifact-flow invariant. This is not a deferral of the capability; it is that the capability cannot be exposed correctly until the core primitive is fixed.

**Error surface:** three new codes in the Storage band, mapped **identically on all bridges**. Today `NodeError::InvalidConfig` maps on UniFFI to a `Validation` variant carrying the *transport-namespaced* code `TRANS_5050` (`crates/scp-ffi/uniffi/src/server.rs:79-82`) — the same code `ServerError::Relay` uses at `:37-40`, so the code cannot distinguish two unrelated failures — while PyO3 and NAPI map every non-passphrase error to an uncoded runtime error (`crates/scp-ffi/src/server.rs:36-56`, `crates/scp-ffi/napi/src/server.rs:34-52`). That three-way parity defect is fixed as part of this work.

**Known blockers to resolve in-PR:** UniFFI's `build_node_identity_from_uniffi` unconditionally errors on non-`testing` builds (`crates/scp-ffi/uniffi/src/server.rs:713-722`), so the `Existing { did }` identity arm would be dead on arrival on Swift. Fix it or do not ship the arm. And `Reach::Tunnel.public_url` is documented as "not yet threaded" (`crates/scp-node/src/config.rs:134-138`) — the node publishes loopback and warns (`:760-767`). Thread it in the core or omit the variant; do not propagate an accepted-then-ignored parameter to the SDKs.

Track C is not complete until it has cleared double-zero as defined in §2.

---

### Track D — Production relay `start` (parity)

Both SDK relay constructors call `test_relay_config()` (`crates/scp-ffi/common/src/server.rs:233`) — whose own doc says *"suitable for testing"* (`:232`) — hardcoding `127.0.0.1:0` and zero delivery jitter, with everything else at defaults. So an SDK-started relay is unreachable from another machine by construction; `delivery_jitter_ms: 0` also discards the traffic-analysis mitigation whose default is 50ms; and `max_connections_per_ip`, `max_total_connections`, `rate_limit_publishes_per_second`, `rate_limit_subscribes_per_minute`, `max_blob_size`, `max_blob_ttl`, and `max_query_limit` are unreachable from any SDK (`RelayConfig`, `crates/scp-transport/src/native/server.rs:125-184`). Those are the DoS-resistance knobs an operator needs. `RelayConfig` additionally carries `max_subscriptions_per_connection`, `ttl_check_interval`, `bridge_secret`, `bridge`, and `did_record_validation` — the last two are security-consequential and should be considered for the mirror rather than silently left at defaults.

This is a **capability gap, not a broken seal** — the relay code path never touches `Node::start_for_testing`, `EncryptedStorage`, or anything behind `allow_unencrypted_storage`. (The feature is still *enabled* on each bridge's `scp-node` edge at manifest level, which is B2's problem, not this track's.)

Add `relay_start` with an `FfiRelayConfig` exposing bind address, delivery jitter, the connection and rate limits, and the blob size/TTL/query caps. Rename the existing pair honestly and gate them behind `testing` alongside the node ones (Track B1's pattern applies unchanged).

Same SDK scope as Track C — Rust, Python, TypeScript, and Swift under `#if os(macOS)`.

Track D is not complete until it has cleared double-zero as defined in §2.

---

### Track E — Remove Kotlin node and server bindings

Kotlin's `ServerBindings` (`bindings/kotlin/scp-kt/src/main/kotlin/works/limn/scp/Server.kt:22`) has **no production implementor**. The only one in the repo is a test stub (`src/test/kotlin/works/limn/scp/ServerTest.kt:188`); the bridge field defaults to `null` (`bridge/CoroutineBridge.kt:1294`), so with the default the entire server surface is absent at runtime. Yet the capability matrix asserts `kotlin: true` for all ten Server operations (`.docs/standards/sdk-capability-matrix.json:1958-2020`) and the coverage gate passes because it is, by its own header, a **name-existence check** (`scripts/check-sdk-coverage.py:4-13`) whose Kotlin extractor deliberately walks `interface_declaration` nodes (`:1452`). An interface method with zero implementors satisfies it.

Remove the node and server surfaces from the Kotlin SDK entirely — interface declarations, `Node`/`Relay` companions, the stub, and its tests.

**Enforcement-file note:** this requires setting the affected matrix rows to `kotlin: false` with exemptions. That is *correcting a false claim*, not weakening a guarantee — the capability never existed. It must still be called out explicitly in the PR body for human review, never presented as a mechanical consequence.

Also fix while in that file: `Node.close()` and `Relay.close()` use `runBlocking(Dispatchers.Default)` (`Server.kt:229-231`, `:310-312`). The explicit dispatcher pin does mitigate the single-threaded-dispatcher deadlock the repo has already been bitten by, and the doc comment says so — but `runBlocking` still blocks the calling thread, so calling `close()` from a coroutine remains a hazard. Treat it as a real defect with a partial mitigation, not an unguarded deadlock.

Track E is not complete until it has cleared double-zero as defined in §2.

---

### Track F — The nullifier arc's scattered remainder

Independent of the seal, same tenet. Each is an always-succeeds construct, a fabricated value, or a verifier with no production caller. Parallelizable. Each is subject to §2 independently.

1. **Chunk signing emits an all-zero signature when the signer fails** — three paths, in `crates/scp-runtime/src/context/outlets/invoke.rs` (`:3481` no signer, `:3501` preimage/JCS failure, `:3515` signer error). The sibling dispatch path already refuses to (`outlets/dispatch.rs:2639-2665`); copy it, but note it returns `None` and breaks the pump rather than raising a typed error — the destination shape here should be a typed error, not a silent stream end.
2. **The revocation distributor returns success and distributes nothing** — `BridgeRevocationDistributor` (`crates/scp-ffi/common/src/resolvers.rs:806-820`), the only non-test implementor, wired into revoke on all three bridges.
3. **Outlet registration signatures are never verified** — `verify_outlet_registration_signature` (`crates/scp-protocol/src/context/outlets/registry.rs:564`) has zero production callers, and short-circuits `Ok(())` on an empty signature. Two distinct failures share this root and should be stated separately: all three bridges construct `OutletRegistration { signature: vec![] }` on the explicit register path (with a caller-supplied operator DID), *and* the context-params outlet-declaration path additionally fabricates `operator_did: "did:key:placeholder"` alongside the empty signature (`crates/scp-ffi/common/src/context_params.rs:334-337`).
4. **End-of-stream chunks carry hardcoded provenance and it is signed** — `placeholder_data_provenance` (`crates/scp-runtime/src/context/outlets/invoke.rs:3394-3409`) flows into the terminal chunk and through `wrap_chunk`, so the fabrication is attested.
5. **The dispatching DID resolver falls back to a non-verifying resolver** — `DispatchDidResolver::new` falls back to `BridgeDidResolver` (`crates/scp-ffi/common/src/resolvers.rs:649-669`), which performs no BEP44 signature verification, no self-certification check, and no sequence comparison; revoked keys validate.
6. **The always-"never revoked" checker is exported ungated** from the core facade — `NoOpRevocationChecker` (`crates/scp-protocol/src/trust/attestation.rs:722`), re-exported at `crates/scp-core/src/lib.rs:172` with no feature gate.
7. **A dead in-memory trust store is exported ungated** — `InMemoryFfiTrustStore` (`crates/scp-ffi/common/src/trust_store.rs:24`) behind the `resolvers` feature, which is a *default* feature, with zero callers in any bridge.
8. **Three integration test files are compiled out behind an always-false cfg while still registered as test targets** — `#![cfg(any())]` in `crates/scp-testing/tests/integration/{network_simulation,outlet_economy_wiring,persistence}.rs`, all three still declared as `[[test]]` targets, so CI reports green having executed nothing. Corrected counts: **3,370 lines and 18 `#[tokio::test]` functions** (an earlier draft's "112" was the count of *all* `fn` declarations — helpers and mock-trait methods included — and "3,373" was three lines off). The blocker they cite is the ADR-049 §15 deletion of `ContextCryptoProvider`, pending `NodeMlsFactory::with_backends`; that blocker no longer exists — `with_backends` is live at `crates/scp-runtime/src/crypto/mls/provider.rs:558` and `ContextManager` has no definition anywhere in the repo.
9. **The TypeScript trust evaluation derives booleans by parsing error prose** — six prefix tables consumed by `__classifyUcanError` via `startsWith` over Rust `Display` text (`bindings/typescript/src/trust.ts:398-431`) — checks only the first **attenuation/capability** (`att[0].with`, `:344-358`; an earlier draft said "attestation," which is a different and separately-always-empty field), and hardcodes behavioural zeros (`:701-703`, `:711`, `:753-756`) — under stories marked done.

---

### Track G — Unlanded work at risk

| Work | State | Action |
|---|---|---|
| Relay WRITE path | 11 commits, **local only, never pushed** | Push first — highest loss risk. Then a genuine review pass: the earlier "zero code defects" claim was false (the pass actually returned a BLOCKER plus several MEDIUMs), and the final collapse commit has never been reviewed. |
| MCP subscribe honest | 5 commits, **local only** | Push, review, PR. |
| Absence proofs | pushed, audited **incomplete** | Finish: Kotlin still exposes the deleted boolean, error codes diverge three ways, the parity harness was never extended. |
| UCAN revocation fail-closed | pushed, **unreviewed** | Review to double-zero, PR. |
| Welcome-join stale params | pushed, **review died mid-pass** | Re-review, PR. |

Every row above lands only through §2. "Push first" is a loss-prevention step, not a merge step.

---

## 4. Sequencing

```
B4 (gate artifacts)          ── independent, land first, own commit

Track G (push at-risk work)  ── independent, do immediately

B1+B2+B3 (atomic)  ─────────┬─► B5 (drop filesystem feature, all four edges)
        │                    └─► B6 (gate reframe — MUST be after B3)
        │
        ├─► Track C (production node start)
        │        └─► Track D (production relay start, parity)
        │
        └─► Track E (remove Kotlin) — independent of C/D but same review

Track A (crate splitting) ── AFTER the in-flight seal PR merges; four of six
                             files it edits are in flight there.
Track F ── fully parallel, no dependencies.
```

**Non-obvious edges:** B6 after B3 (else the registry demands a classification a nullifier cannot have). Track A after the open seal PR (concurrent edits to the feature graph from two directions is how an exception slips through unreviewed). Track D after C (shares the enum-mirror and config-object patterns).

**No track is complete until it has cleared double-zero as defined in §2.** The graph above orders *starts*; §2 governs *finishes*. A track that has landed code but not cleared two consecutive zero-finding full-roster passes does not unblock its dependents.

---

## 5. Decisions outstanding

1. **Approval to delete the old allowlist-hygiene assertion** (B6), or keep both.
2. **`TlsMode::DnsSubdomain` in the core enum** — required before `dns_provider` can be exposed at all.
3. **Promote the three `Proposed` ADRs** that merged code already depends on, and define the status vocabulary. Corrected counts: there are 64 ADR entries across 62 unique numbers (two numbers are reused). Exactly 3 carry `Proposed` and 11 carry `Accepted` — the only two words any rule defines, and only in `CLAUDE.md`. **47 carry `Decided`**, 2 carry `Superseded`, and 1 has no status line at all — so **50 of 64 entries use a status no rule defines**, not 47 of 62. The vocabularies also split cleanly by file format: every `Decided` is inside a `phase-N.md` file and every `Accepted` is in a standalone ADR file, which is itself worth deciding about.

---

## 6. Flags — unverified, stated rather than assumed

- Nothing in Tracks A or B was compiled. Feature-resolution claims come from `cargo tree` and from running the real gate script; compile-failure predictions are derived from reading `#[cfg]` boundaries. The implementing agent must confirm.
- The 78-crate / 21% `cloud-blobs` figure is measured on `scp-transport`'s graph in isolation and is an **upper bound** for any downstream artifact. The per-cdylib and per-binary numbers — the ones that matter — still need measuring under Track A's acceptance criteria.
- `S3BlobStore` / `PostgresBlobStore` are constructible, but not through the enum. `BlobStorageBackend` exposes named constructors for `in_memory`, `sqlite`, `redb`, `combined`, and `cached` only (`crates/scp-transport/src/native/storage.rs:503-556`) — no `s3()` and no `postgres()`, because both underlying `open` constructors are `async`. There *are* `From<S3BlobStore>` and `From<PostgresBlobStore>` impls (`:585`, `:592`), so a Rust caller can write `S3BlobStore::open(…).await?.into()`. Decide whether the FFI mirror carries these two backends at all before writing `FfiBlobBackend`; today an SDK caller cannot select two backends we ship.
- **The capability matrix may not be able to express "Swift: true, macOS-only."** `sdk-capability-matrix.json` is `schema_version` 1.0 and each operation is four plain booleans plus optional free-text `exemptions` / `coverage_exemptions` / `notes`; there is no platform qualifier. Both available answers are wrong: plain `true` overstates the Swift surface (it claims iOS), and `false` understates it (macOS genuinely ships). Prose in `notes` is not machine-checked. This is left unresolved deliberately — the matrix is a protected enforcement file and no schema extension should be invented here. It matters because the gate over that matrix is a name-existence check, which is the exact mechanism that let Kotlin's stub-backed surface report `true` for years (Track E).
- No spec section, ADR, or PRD story governs a production FFI node-start surface. Per the artifact-flow invariant this design should be written into an artifact before implementation.
- Relay blob-storage at-rest properties, and `FileKeyCustody`, were not audited.
