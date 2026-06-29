# Self-Hosting a Website on SCP

For concrete public-deployment recipes (direct IP / tunnel / reverse proxy), see [deploying-an-scp-website.md](./deploying-an-scp-website.md).

> **Status:** Living document — written as we build. Started 2026-06-13.
> **Goal:** Host a real, production website **entirely on SCP** — web server, data
> layer, networking, identity, and addressing all provided by the protocol, with
> **zero non-SCP infrastructure** (no nginx, no Express, no CDN, no tunneling
> service, no DNS registrar dependency). The site is reachable from the public
> internet and addressed protocol-natively.
>
> **First payload:** a plain `index.html` + CSS + JS ("hello world"). The payload
> is deliberately trivial; the point is that the *entire stack underneath it* is SCP.
>
> **Provenance:** specs `§10 Infrastructure & Self-Hosting`
> (`.docs/specs/10-infrastructure-and-self-hosting.md`) and
> `§18 Addressability & Deployment` (`.docs/specs/18-addressability-and-deployment.md`).
> Ground truth in this doc was established by direct code audit (file:line cited
> inline) on 2026-06-13.

---

## 1. What "a website on SCP" actually is

SCP is not a web framework. It hosts a site through its **broadcast context +
site projection** machinery:

1. Create a **broadcast context** (an MLS-governed, per-author-keyed space).
2. Publish each static asset (`index.html`, `style.css`, `app.js`, images…) as a
   **`BroadcastContent`** message — sealed under a per-author **AES-256-GCM**
   broadcast key into a **`BroadcastEnvelope`** and pushed onto the transport.
   (`crates/scp-protocol/src/context/broadcast_content.rs:298`,
   `crates/scp-protocol/src/crypto/sender_keys/broadcast.rs`)
3. **Enable site projection** on a node and **commit a deploy** — the node scans
   the encrypted blobs for the deploy, builds an immutable `path → blob_id` index,
   and atomically swaps it in. (`crates/scp-node/src/lib.rs` `commit_deploy`,
   `crates/scp-node/src/projection.rs`)
4. The node serves the site at the **origin root** in `--self-host` mode (spec
   §10.12.11 "Origin-root mount"), in addition to the canonical projection path:

   ```
   GET /                                        → the site's configured index_path
   GET /{*path}                                 → the corresponding site asset
   GET /scp/broadcast/{routing_id}/site/{*path} → canonical projection path
   ```

   Origin-root serving is required for browser correctness: an `index.html`
   referencing root-absolute assets (`/style.css`, `/app.js`) issues those
   requests at the origin root, which must resolve to the deployed site. The
   origin-root mount reuses the **same content handler** as the canonical path, so
   `ContentPath` traversal protection, decryption, `ETag`, `Cache-Control`, and CSP
   apply identically. It routes only to the single designated default site and
   **never** re-exposes the relay upgrade (`/scp/v1`) or bridge routes
   (`/v1/scp/bridge/*`), which are not mounted on the self-host public surface.

   `routing_id = SHA-256(context_id)` (no domain separator —
   `crates/scp-protocol/src/context/mod.rs:122` `broadcast_routing_id`).
   `site_handler` (`crates/scp-node/src/projection.rs`, `fn site_handler`) fetches the encrypted
   blob, **decrypts it server-side** with the broadcast key the node holds
   (`open_broadcast_trusted`, `projection.rs`), and returns **plaintext**
   bytes with the right `Content-Type`, `ETag`, `Cache-Control`, CSP, and CORS
   headers. A browser fetches and renders it normally; it
   never sees MessagePack, MLS, or ciphertext.

Encryption is therefore **at rest and on the wire to the relay** — the relay is a
dumb pipe that only ever holds ciphertext — while the **origin node is the
decryption/serving point**.

### The load-bearing architectural fact

> **The website is *only ever* served over HTTP from the origin node.**

There is **no** relay-served path for site assets and **no** client-side broadcast
pull+decrypt:

- `open_broadcast` (the signature-verifying *client* decryptor,
  `broadcast.rs:615`) has **zero production callers** — only the host-side
  `open_broadcast_trusted` is wired, inside `scp-node`'s HTTP projection.
- `broadcast_subscribe` (FFI `crates/scp-ffi/src/context.rs:4052` →
  `subscribe_broadcast` `crates/scp-runtime/src/context/broadcast_helpers.rs:58`)
  is **local roster membership bookkeeping only** — it opens no socket and
  decrypts nothing.
- The generic transport-receive path `deliver_incoming`
  (`crates/scp-runtime/src/context/messaging_helpers.rs:1002`) is **MLS-only**; it
  has no `BroadcastEnvelope` branch.

**Consequence:** "is the website reachable?" reduces exactly to "**is the origin
node's HTTP port inbound-reachable?**" Everything below is about answering that
*without* a manual port-forward and *without* DNS.

---

## 2. Addressing — DNS-free, no central authority

Three addressing paths, none requiring DNS-as-central-authority:

| Path | Who can use it | DNS? | Notes |
|------|----------------|------|-------|
| **Raw public IP:port** | any browser, today | none | `https://<public-ip>:<port>/` (origin-root mount; the canonical `…/scp/broadcast/<rid>/site/<path>` route also works). The self-host surface serves **self-signed HTTPS (TLS 1.3) by default** (§10.12.11) with a SAN for the external IP, so raw-IP HTTPS matches; browsers show a one-time cert warning. The routing_id route is registered unconditionally and ignores the `Host` header. Plaintext `http://` is an opt-out via `SCP_NODE_SELF_HOST_PLAINTEXT=1`. |
| **`did:dht`** | SCP-aware clients | none | Real BitTorrent **Mainline DHT** publish via the `mainline` v6 crate, BEP44 signed mutable items (`crates/scp-identity/src/dht_client/pkarr_client.rs:271` publish / `:303` resolve). Gated behind the `production-dht` feature. No central authority in the publish path; the optional HTTP gateway is a signature-verified resolve-only fallback, empty by default. |
| **Virtual host** (`Host:` header → routing_id) | any browser | needs DNS | Convenience only; out of scope for the DNS-free goal. |

### Known addressing gaps (honest)

- **The published DID document carries only relay endpoints — there is *no*
  HTTP/site service-endpoint type** (`SCPRelay` and `SCPBroadcastContext` are the
  network endpoint types in the closed set at
  `crates/scp-identity/src/document.rs`; both point at relay URLs, not an origin
  HTTP `IP:port`; no `SCPSite`/`SCPHttp` exists). So a client
  **cannot today discover the website's `IP:port` from `did:dht` alone** — it
  learns the relay, not the site. Closing the loop needs a new service-endpoint
  type. *(Tracked in §6.)*
- **No DANE/cert-fingerprint-over-DID.** Only local TOFU relay pinning exists
  (`crates/scp-transport/src/native/cert_pin.rs`). A self-signed node cert can't
  be verified against a DID-published fingerprint yet.
- **PyO3/NAPI client `identity_resolve` use `InMemoryDhtClient`** (resolve against
  an empty in-process map, not the network). Only the node binary and the UniFFI
  per-instance production build hit the real DHT.

---

## 3. Host-side reachability — NAT traversal without a port-forward

A node behind a home NAT can make *itself* inbound-reachable using SCP's own
stack. The reachability strategy `DefaultNatStrategy::select_tier`
(`crates/scp-node/src/lib.rs`, `impl NatStrategy for DefaultNatStrategy`) runs in the **`host_site` / `--self-host` path** and — critically —
operates on **`http_bind_addr.port()`, the public HTTP/site port (default 8443)**,
not the internal relay port (see `fn build_no_domain_inner`, `crates/scp-node/src/lib.rs`).

- **Tier 1 — UPnP-IGD (`igd-next`) / NAT-PMP (`natpmp`)**: real implementations
  (see `crates/scp-transport/src/nat/upnp.rs`, `fn map_port`). One-shot `map_port` opens an inbound **TCP** mapping on the router for
  the HTTP port → the website becomes reachable, no manual port-forward.
- **Tier 2 — STUN** (RFC 8489, `crates/scp-transport/src/nat/mod.rs`): discovers
  the external `IP:port`, classifies NAT type, self-tests reachability, then
  publishes `ws://<external-ip>:<port>/scp/v1` into the DID document on the real
  Mainline DHT.
- **Tier 3 — bridge relay reverse-tunnel** (symmetric-NAT fallback): **not wired
  node-side**, and the bridge only forwards relay blob frames, never HTTP.

**Skipping the STUN probe behind a tunnel/proxy.** When the node is reached
through an external tunnel or reverse proxy (so the local NAT probe would measure
the wrong external address), set `SCP_NODE_SELF_HOST_NO_NAT=1` to skip the STUN
reachability probe and bind the loopback relay URL directly without probing
(`crates/scp-node/src/main.rs`). Related self-host env vars: `SCP_NODE_SELF_HOST_PORT`
(public HTTP/site port), `SCP_NODE_SELF_HOST_PLAINTEXT=1` (plaintext opt-out,
§10.12.11), and `SCP_NODE_SELF_HOST_REFRESH_SECS` (NAT lease-renewal interval
override).

### The NAT-PMP self-test wrinkle (Finding D, verified)

On startup the Tier-1 path opens the TCP mapping **then runs a reachability
self-test that sends a STUN binding over a *UDP* socket** and asserts the reply's
mapped address equals the *TCP* mapping (`crates/scp-node/src/lib.rs`, `fn try_tier1_upnp`;
`crates/scp-transport/src/nat/mod.rs`, `fn probe_reachability`). On this host the UDP external port
(measured 64503) won't equal the TCP mapped port (8443), so the **self-test fails
and Tier 1 is "rejected," falling through to Tier 2 (STUN)** (`lib.rs`, `fn try_tier1_upnp`).

**This does not break hosting.** The NAT-PMP TCP mapping is created *before* the
self-test and is **not released** on failure (see the no-release fall-through in `fn try_tier1_upnp`, `crates/scp-node/src/lib.rs`) — so port 8443 stays
forwarded regardless of which tier "wins." The website is reachable over raw-IP
TCP, which is exactly what's mapped. The only consequence is cosmetic: the
published `ws://` relay URL carries the Tier-2 (UDP) address — irrelevant to the
website, since the site is served raw-IP:port over HTTP and there is no
broadcast-over-relay client path anyway. A protocol-aware self-test (skip/adapt for
the TCP HTTP mapping) is a Phase-2, spec-touching (§10.12.2) fix.

### Bridge relay = the privacy-preserving default (design input)

The Tier-3 bridge relay is mis-framed in the code as merely a *symmetric-NAT
fallback*. It is actually the answer to the biggest self-hosting footgun (§3,
IP-doxing): if a node is reachable via a **neutral public bridge's IP**, the DID
resolves to the bridge and the operator's **home IP never enters the DHT**. So the
safe-by-default posture for non-experts is: **default = reachable via a bridge
relay (home IP private); direct home-IP exposure = explicit power-user opt-in**
(faster, fully decentralized, but consciously publishing your IP). Phase 1 builds
the direct-exposure opt-in (a *conscious* operator stress test); the
bridge-as-default is what turns this from a footgun into a product. The bridge
currently forwards only relay blob frames, not HTTP — wiring HTTP through it is
future work.

### Host-side gaps (honest)

1. **`upnp` cargo feature is OFF by default** and not enabled on `scp-node`'s
   `scp-transport` dependency → a stock build's Tier 1 silently no-ops. *Fix: build
   with `--features upnp`.*
2. ~~The shipped `scp-node` binary mandates `SCP_NODE_DOMAIN` and never calls
   `no_domain()`.~~ **Fixed:** the binary now has an opt-in `--self-host` run mode
   (`SCP_NODE_SELF_HOST=1`) (`crates/scp-node/src/main.rs` `run_self_host` builds `HostSiteConfig { reach, tls, dht, … }` and calls `host_site_until`;
   the publish/projection wiring lives in `crates/scp-node/src/self_host.rs`). In
   self-host mode the binary does its own NAT traversal on the public HTTP/site
   port. Domain is only mandated on the default (non-self-host) path. NAT
   port-mapping still requires building with `--features upnp` (§3.1).
3. **STUN is discovery-only — no ICE agent, no hole-punching.** Tier 2 *assumes*
   the NAT keeps the hole open. True for **cone NAT**; false for **symmetric NAT**.
4. ~~No NAT-PMP/UPnP lease renewal wired into the node path.~~ **Fixed:** the
   `--self-host` path now renews the NAT port-mapping lease at 50% of the
   gateway-reported TTL (spec §10.12.2) via a contained renewal task tied to the
   node's shutdown. The mapping created during startup is re-issued before
   expiry (NAT-PMP re-send / UPnP re-add, both idempotent), so the site stays
   publicly reachable indefinitely while the node runs. Renewal failures log a
   warning and retry after a short backoff rather than dropping the mapping; the
   loop is cancelled and awaited before the mapping is released on shutdown.
5. **Self-host path (`host_site` / `--self-host`) serves self-signed HTTPS (TLS 1.3) by
   default** (spec §10.12.11 "Transport security (website surface)"). The node is
   its own CA ("be your own CA"): the cert is self-signed with no DNS name and no
   CA authority, presenting SANs for `localhost`, `127.0.0.1`, and — when known at
   serve time — the node's external/LAN IP, so raw-IP HTTPS presents a matching
   SAN. Browsers show a one-time untrusted-certificate warning (expected for the
   no-DNS model). Rationale: §10.12.6's "self-signed certs provide no trust
   benefit" applies to SCP-protocol peers (who authenticate the relay via the
   self-certifying DID document), **not** to web browsers — which can only speak
   HTTP or HTTPS, and whose HTTPS-Only modes (e.g. Safari) refuse to open
   `http://` origins. Plaintext is an explicit opt-out via
   `SCP_NODE_SELF_HOST_PLAINTEXT=1` (restores `http://` on the self-host surface;
   disclosed in the startup banner). Confidentiality/integrity of the website's
   underlying broadcast content is already provided by per-author AES-256-GCM
   broadcast encryption (§9.16); the self-signed TLS layer only satisfies the
   browser's transport requirement, it is not a new trust anchor.
6. **WebRTC adapter is mock-only scaffolding** (`webrtc = []` empty feature, no
   ICE/TURN, constructed nowhere) — not a viable p2p path today.

---

## 4. This machine — empirical network facts (2026-06-13)

Measured directly on the host:

```
Local IP:        192.168.1.203   (interface en1)
Gateway:         192.168.1.1
Public IP:       71.249.150.234  (Verizon FiOS, residential, dynamic)

NAT mapping:     endpoint-independent  →  CONE NAT          ✅
                 (same external port 64503 across 3 STUN servers, one socket)
NAT-PMP:         gateway responded result=0 on UDP 5351     ✅  (supports auto-mapping)
UPnP-IGD (SSDP): no response (macOS multicast quirk; non-fatal — NAT-PMP suffices)
```

**Verdict for this host:** the website *can* be made publicly reachable at
`71.249.150.234` with **no manual port-forward**, because (a) the NAT is cone, so
Tier-2's hole-stays-open assumption holds, and (b) the gateway speaks **NAT-PMP**,
so Tier-1 can auto-open the HTTP port. The only required engineering is enabling
the `upnp` feature and running `scp-node --self-host` (which uses `HostSiteConfig::defaults` + `host_site_until`). This path serves **self-signed HTTPS (TLS 1.3) by
default** (§10.12.11) — browsers show a one-time cert warning over raw-IP; set
`SCP_NODE_SELF_HOST_PLAINTEXT=1` to fall back to plaintext `http://` for a DNS-free
stress test (the content is public broadcast anyway).

Probe scripts: `/tmp/scp_nat_probe.py` (STUN NAT classification),
`/tmp/scp_upnp_probe.py` (SSDP + NAT-PMP). *(To be moved into the repo as a
reusable diagnostic — see §6.)*

---

## 5. Build plan

> Governed by the artifact flow (specs → ADRs → stories → code). Each code change
> goes through a worktree + the full review roster per `CLAUDE.md`.

**Governance (verified):** **No new ADR.** §10.12.2 + §10.12.8 and ADR-032
(Addressability/Deployment), ADR-035 (broadcast projection), ADR-042
(`BroadcastContent`/site delivery) + the reachability PRD already govern the
mechanism *and* the "node opens a router port" security consideration (§10.12.2).
The only upstream edit artifact-flow requires: **one clarifying sentence** in
§10.12.8 / §18.6 that the `scp-node` reference binary exposes a `--self-host` mode
via `host_site_until`, plus **PRD stories** (validate with
`scripts/validate-prd.py`). That spec sentence + PRD is execution step 1.

**Security posture = implementation requirements (not optional):**
self-host is **opt-in only** (`--self-host` flag / `SCP_NODE_SELF_HOST=1`, never a
default; `upnp` stays a non-default cargo feature); a **loud, legible startup log**
("opening TCP <port> to the public internet; home IP <x> now publicly bound to DID
<y>"); **clean teardown** releases the mapping on shutdown; dev/bridge endpoints
stay **loopback-only** (verify, don't assume); IP-doxing and the self-signed-cert
(no-CA) posture stated explicitly (the self-host surface serves self-signed HTTPS
by default per §10.12.11, with plaintext available only as an explicit
`SCP_NODE_SELF_HOST_PLAINTEXT=1` opt-out).
Per-IP rate limiting is already built (`ProjectionRateLimiter`); it
defends CPU/keys against per-source floods but **cannot** defend a residential
uplink against volumetric/distributed DDoS — that requires upstream scrubbing a
home line doesn't have. Honest, not fixable from here.

**Phase 0 — Diagnostics (done):** NAT/UPnP/STUN probe of the host. ✅

**Phase 1 — Minimal viable self-host (cone-NAT, this machine):** ✅ implemented
- Build path with `production-dht` + `upnp` features.
- The `scp-node --self-host` binary mode builds `HostSiteConfig { reach: Reach::NatTraversal, tls, dht, … }` and calls `host_site_until`:
  probes NAT → NAT-PMP-maps the HTTP port → STUN-confirms → publishes `did:dht` to
  Mainline. Serves self-signed HTTPS by default (§10.12.11);
  `SCP_NODE_SELF_HOST_PLAINTEXT=1` opts out to plaintext for a DNS-free stress test.
- Create a broadcast context; publish `index.html`/CSS/JS as encrypted assets;
  `enable_broadcast_projection_with_site`; `commit_deploy`.
- Verify reachable from the public internet at
  `https://71.249.150.234:<port>/` (origin root; cert warning expected over raw IP).

**Phase 2 — Production hardening:**
- ✅ NAT-PMP/UPnP **lease renewal** wired into the `--self-host` node path
  (renews at 50% of the gateway-reported TTL; cancelled + released on shutdown).
- File-backed (Redb) persistent storage + persistent identity custody.
- Liveness/auto-remap on IP change; clean shutdown releases the mapping.

**Phase 3 — Close the DNS-free addressing loop (protocol work):**
- New DID-document **site service endpoint** so a client can resolve
  `did:dht` → the site's `IP:port` (not just the relay).
- (Optional) cert-fingerprint-over-DID for CA-less self-signed TLS verification.

**Phase 4 — TLS without a central CA:**
- ✅ Self-signed TLS (TLS 1.3) on the self-host path is the default
  (§10.12.11); the node is its own CA, with SANs for `localhost`/`127.0.0.1`/the
  external IP. Plaintext is the explicit `SCP_NODE_SELF_HOST_PLAINTEXT=1` opt-out.
- (Future) DID-fingerprint pinning over the self-signed cert (bind the cert
  fingerprint into the BEP44-signed DID document) so an SCP-aware client can verify
  it without a CA — §10.12.11 "Future: CA-less authentication."

---

## 6. Open items / gaps to close (tracked here, not as throwaway issues)

- [ ] `upnp` feature not enabled by default for `scp-node` (§3.1).
- [x] `scp-node` binary now has a `--self-host`/NAT-traversal serving mode (§3.2) —
      the opt-in `--self-host` run mode uses `HostSiteConfig` + `host_site_until` and
      does its own NAT traversal on the public site port; serves self-signed HTTPS by
      default (§10.12.11).
- [x] NAT-PMP/UPnP lease renewal wired into the `--self-host` node path (§3.4) —
      renews at 50% of the gateway-reported TTL, retries on failure, released on
      shutdown.
- [ ] DID document lacks an HTTP/site service-endpoint type (§2 gaps).
- [ ] Tier-3 bridge reverse-tunnel not wired node-side; bridge can't carry HTTP
      (blocks symmetric-NAT hosts — does **not** block this cone-NAT host).
- [ ] Move NAT/UPnP/STUN probe scripts into the repo as a reusable diagnostic.

---

## 7. Running log

- **2026-06-13** — Established full ground truth via code audit (7 parallel
  agents). Confirmed the broadcast/site-projection architecture, the HTTP-only
  serving path, real Mainline-DHT `did:dht` publishing, and the host-side
  NAT-traversal tiers + their gaps. Probed the host: **cone NAT + NAT-PMP
  supported** → public self-hosting with no port-forward is achievable here.
  Created this guide.
- **2026-06-13 (status / resume point)** — Phase 1 plan approved; execution
  **blocked by an Anthropic session rate limit (resets 8 pm America/New_York)** —
  coder subagents returned zero work. **Done so far:** the website payload is
  authored at `crates/scp-node/assets/selfhost/{index.html,style.css,app.js}`
  (the real hello-world, viewable as a local file). **Resume at 8 pm ET by
  re-dispatching the two coder agents** (branches `feat/self-host-node-mode` and
  `docs/self-host-binary-prd`) per the step-ordered plan below; the agent prompts
  are fully specified. After build + full-roster review + local CI (`--features
  upnp`), the only remaining step is the operator-consented live run (opens TCP
  8443 via NAT-PMP, publishes did:dht). Verify public reachability from OFF this
  network (phone on cellular / external box) — home routers often don't hairpin.
- **2026-06-13** — Produced code-verified Phase 1 plan. Key resolutions:
  **no new ADR** (mechanism already specced §10.12 + ADR-032/035/042); the binary
  must run **both** an `ApplicationNode` (`no_domain`) **and** an in-process
  `Supervisor` connected to its own loopback relay to close publish→commit_deploy;
  verified the full publish→commit→serve call
  sequence and the `get_broadcast_key_for_local_author` → `BroadcastKey::from_parts`
  → `enable_broadcast_projection_with_site` path; documented Finding D (TCP-mapping
  vs UDP self-test, hosting unaffected) and the bridge-as-privacy-default reframing.
  No enforcement files / capability-matrix / pipeline_wiring changes required.
- **2026-06-14 (as-built reconciliation)** — `--self-host` is implemented and
  tested; corrected this guide to match the as-built code. **Publish mechanism
  (corrected):** there is **no** directly-shared `Arc` blob backend between the
  supervisor and the node. The in-process `Supervisor` connects to the node's
  **own loopback relay** (`ws://127.0.0.1:<relay_port>/scp/v1`, `RelayUrlSource::
  DhtResolved`, authenticated with the node's bridge bearer token via
  `connect_loopback_supervisor`, `crates/scp-node/src/self_host.rs`); the supervisor
  publishes sealed `BroadcastContent` envelopes onto that relay, the relay stores
  the encrypted blobs, and `commit_deploy` scans **that same relay's blob storage**
  to build the `path → blob_id` index. Supervisor↔node communication is via the
  relay, not a shared backend. **Other as-built facts verified at this date:**
  self-host serves self-signed HTTPS (TLS 1.3) by default with plaintext opt-out
  (`SCP_NODE_SELF_HOST_PLAINTEXT=1`) per §10.12.11; the `scp-node --self-host`
  binary mode selects `no_domain()` (§3 gap #2 / §6 resolved); origin-root mount
  (`/` → index) per §10.12.11; the self-host DID is stable across restarts
  (load-or-create via `ApplicationNodeBuilder::identity_with_storage()`,
  `crates/scp-node/src/main.rs`); `SCP_NODE_SELF_HOST_NO_NAT=1` skips the STUN
  probe behind a tunnel/proxy; NAT-PMP/UPnP lease renews at 50% TTL.
- **2026-06-14 (library entrypoint)** — the self-host deploy+serve core is now
  also exposed as a public library API, `scp_node::host_site(HostSiteConfig)` /
  `host_site_until(config, shutdown)` (`crates/scp-node/src/self_host.rs`), so
  "host a website on SCP" is usable as a normal async Rust call in addition to
  the turnkey `scp-node --self-host` binary. The binary is now a thin wrapper
  over `host_site_until` (env/CLI parsing, the loud banner, and the live-URL
  print stay binary-only via an `on_ready` callback). A runnable example lives at
  `crates/scp-node/examples/website.rs` (`cargo run -p scp-node --example
  website`). The library default is **fail-safe**: `DhtMode::Memory` publishes
  nothing; public hosting is a deliberate `DhtMode::Production` opt-in (which
  publishes the host's address bound to its DID to the DHT — the same IP-to-
  identity disclosure the binary gates behind `--self-host` + its banner). No new
  protocol logic, specs, ADRs, or enforcement/capability-matrix changes — a
  packaging/ergonomics refactor of the already-shipped self-host flow.
- **2026-06-16 (ADR-052 P3a/P5)** — `ApplicationNodeBuilder` and its `.no_domain()` / `.identity_with_storage()` methods were deleted in ADR-052 Phase B-P3a (PR #1815). The `--self-host` binary path now builds `HostSiteConfig { reach: Reach::NatTraversal, tls, dht, … }` and calls `host_site_until` directly (`crates/scp-node/src/main.rs` `run_self_host`). Updated §3, §4, §5, and §6 to reflect the current API. Running log entries from 2026-06-13/2026-06-14 referenced the former typestate builder and are preserved as historical record.
