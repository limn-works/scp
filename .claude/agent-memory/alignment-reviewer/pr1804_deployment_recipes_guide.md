---
name: pr1804-deployment-recipes-guide
description: PR #1804 docs-only deployment-recipes guide review — technical accuracy of three SCP website exposure recipes against scp-node host_site code
metadata:
  type: project
---

PR #1804 (branch `docs/scp-website-deployment-recipes`) adds `.docs/guides/deploying-an-scp-website.md` documenting three ways to publicly expose `scp_node::host_site`: (1) direct raw-IP + NAT-PMP/UPnP + self-signed HTTPS, (2) outbound tunnel (cloudflared — how ctx.network deploys), (3) reverse proxy (nginx/Caddy). Plus two pointer edits (self-hosting guide + examples/README).

**Verdict: no findings — claims are accurate.** Reviewed for technical accuracy / honest claims against `crates/scp-node/src/self_host.rs` and `examples/website.rs`.

Verified-correct claims:
- `skip_nat`: guide says false=probe STUN+open router port via NAT-PMP/UPnP (needs `--features upnp`), true=loopback only. Matches struct doc (self_host.rs:724-725) and `build_host_site_node` (1683-1726): under `#[cfg(not(feature="upnp"))]` mappers are `(None,None)` so NAT-PMP/UPnP genuinely requires `--features upnp`; `skip_nat` calls `.skip_nat_probe()`.
- `plaintext`: false=self-signed HTTPS, true=plain HTTP (for tunnel/proxy TLS termination). Matches doc 718-721.
- `dht_mode`: Memory=never publish (fail-safe default), Production=publish addr->DID to global Mainline DHT = IP-to-identity/location disclosure, deliberate opt-in. Matches DhtMode doc (640-664) and host_site runtime warn log (949-953).
- Self-signed cert warns in browsers: honest (Recipe 1 trade-off + at-a-glance "no (self-signed)").
- Tunnel/proxy edge terminates TLS / sees plaintext / is an operator: honestly stated in both recipes' trade-offs.
- ctx.network deployed via Cloudflare tunnel: matches host_site being the standalone deploy path (task #28 in repo).
- cloudflared yaml (`service: https://localhost:8443` + `noTLSVerify: true`), nginx (`proxy_pass http://127.0.0.1:8443`), Caddy (`reverse_proxy 127.0.0.1:8443`) — all valid as written; default port 8443 = DEFAULT_HTTP_BIND_ADDR (self_host.rs:713).
- At-a-glance table internally consistent with per-recipe rust snippets (skip_nat/plaintext/dht_mode columns all match).
- Pointer edits (self-hosting-a-website-on-scp.md +link, examples/README.md +link) point at correct relative paths.

Note: guide's Recipe-1 build line `cargo run --release --features upnp` says "in your app; or build scp-node with --features upnp" — `upnp` is an scp-node feature; a downstream app must re-export/enable it. Phrasing already hedges this ("in your app"). Not a defect.
