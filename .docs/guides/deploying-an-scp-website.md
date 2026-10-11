# Deploying an SCP Website: Three Recipes

An SCP self-hosted site is an ordinary Rust program that calls
[`scp_node::host_site`](../../crates/scp-node/examples/website.rs) — the SCP node *is* the
web server (content is published as encrypted broadcast blobs and decrypted on serve; there is
no separate web server and no DNS requirement on the origin). See the example at
`crates/scp-node/examples/website.rs` and the background guide
[`self-hosting-a-website-on-scp.md`](./self-hosting-a-website-on-scp.md).

On every build without `scp-node`'s `testing` feature, `host_site` fails closed when it has
to create an identity, returning
`HostSiteError::NodeBuild(NodeError::Identity(IdentityError::NoPreRotationBackend))`, a typed
value a caller matches without reading the message text. `host_site` first
reloads any identity its storage directory holds, and creates one on `Node::start`'s
`Generate` path only when the directory holds none. On a build without `testing`, that path
returns `NoPreRotationBackend` whatever custody or storage the caller supplies: it takes no
`PreRotationCustody` input. A failed run persists no identity, so the next run against the
same directory takes the same path. So on a shipped build, each recipe below fails on every
run whose `storage_path` directory holds no identity, and its `Verify` step cannot succeed.
No build creates an identity without a test-harness stand-in until a production
`PreRotationCustody` backend exists ([#1729](https://github.com/limn-works/scp/issues/1729)):
a `testing` build mints it through `InMemoryPreRotationCustody`, which holds the
pre-rotation key only in process memory, so the reveal that spec §9.7.4.1 item 4 says
recovers a root compromise is unreachable for that identity.

A shipped build that finds an identity in its `storage_path` directory reloads it and serves,
without checking how it was created ([#2558](https://github.com/limn-works/scp/issues/2558)).
Each recipe uses `storage_path: Some("./data")`, so a recipe run once from a `testing` build
leaves an identity that a shipped build then serves with. Never point a shipped build at a
directory a `testing` build wrote. `crates/scp-node/examples/README.md` states the same limits
for the example.

What changes between deployments is **not the code** — it's a few `HostSiteConfig` fields plus
the surrounding network plumbing. The same `host_site` call powers all three recipes below; each
recipe lists only the option deltas and the external infrastructure.

The three knobs that matter:

| Field | Meaning |
|---|---|
| `reach: Reach` | `Reach::NatTraversal` = probe the external address (STUN) and open a router port via NAT-PMP/UPnP (needs `--features upnp`). `Reach::Tunnel { public_url }` = the tunnel provides external reachability; skip NAT probing entirely. *(Note: `public_url` is not yet threaded — the node publishes a loopback URL and emits a runtime warning; reachability comes from the tunnel/proxy itself, not this field.)* `Reach::Local` = no probing; loopback only (dev/demo). *(Only these three variants are valid for `host_site`. `Reach::Domain` is valid in `NodeConfig` but returns `HostSiteError::InvalidConfig` here.)* |
| `tls: TlsMode` | `TlsMode::SelfSigned` (default) = serve self-signed HTTPS (be-your-own-CA, no DNS). `TlsMode::Plaintext` = serve plain HTTP (for when a tunnel or proxy terminates TLS in front). *(Only these two variants are valid for `host_site`. `Acme`/`Terminated`/`Custom` are valid in `NodeConfig` but return `HostSiteError::InvalidConfig` here.)* |
| `dht: DhtMode` | `DhtMode::Disabled` (default) = turn the DHT layer off, so the node publishes nothing (it discloses no address) and its DHT resolution arm answers `Ok(None)`. `DhtMode::Production` = publish the node's public address bound to its DID to the global Mainline DHT — an IP-to-identity / approximate-location disclosure, and a deliberate opt-in. A third variant, `DhtMode::Memory`, compiles only under `scp-node`'s `testing` feature, because ADR-062, capability injection, made it test-harness-only. A build that does not enable `testing` cannot name it. |

---

> **Annotation, 2026-09-13.** Everything below is the record as its author wrote it on the
> date this file carries, restored unedited except for one later rename: four lines
> below (Recipe 1's IP-exposure trade-off, the Recipe 2 and Recipe 3 code comments, and the
> `dht` row of the At a glance table) replaced `DhtMode::Memory` with `DhtMode::Disabled`,
> because `Disabled` is now the no-publish default and `Memory` compiles only under
> `testing`. The identity model it reads — the Mainline distributed hash table and the identifier written as a `did:` string — was
> replaced on 2026-08-30 by ADR-063, the inception-derived key-event-log identity substrate,
> whose rules `.docs/specs/09-security-model.md` §9.7.4.2 and `.docs/specs/03-identity.md`
> §3.10 carry, and whose curve Alec settled on 2026-09-10 as ECDSA on NIST P-256
> (`.docs/specs/09-security-model.md` §9.5). A record of what a named party read on a named
> date states what that party read, so this annotation records what replaced the model and
> no other sentence below is edited to match.

## Recipe 1 — Direct (raw public IP, no operator)

The pure-SCP path: your machine is the public endpoint, with no third party in the data path.

```rust
host_site(HostSiteConfig {
    site_dir: Some("./site".into()),
    storage_path: Some("./data".into()),
    dht: DhtMode::Production,    // publish address->DID so the site is DID-discoverable
    // tls defaults to TlsMode::SelfSigned — self-signed HTTPS (be your own CA)
    ..HostSiteConfig::defaults(Reach::NatTraversal)  // probe + open a router port via NAT-PMP/UPnP
})
```

Build with NAT-PMP/UPnP support so the router port opens automatically. `upnp` is a feature of
the `scp-node` crate, so a downstream app re-exposes it through its own `Cargo.toml`:

```toml
# your app's Cargo.toml
[features]
upnp = ["scp-node/upnp"]
```

```sh
cargo run --release --features upnp
```

External infrastructure:

- A router that allows an inbound port. NAT-PMP/UPnP does this automatically on most consumer
  routers (verified working on a residential cone-NAT connection during development). If your
  router lacks NAT-PMP/UPnP, forward the port manually.
- No DNS, no certificate authority, no tunnel, no proxy.

Trade-offs:

- **IP exposure:** every visitor sees your machine's public IP. With `dht: DhtMode::Production` that
  IP is additionally bound to your node's DID in the global DHT. Use `dht: DhtMode::Disabled` to keep
  the address out of the DHT and share the raw IP out-of-band instead.
- **Certificate:** self-signed, so browsers show a warning. A browser-trusted cert without a CA
  dependency requires a DNS name + ACME, which reintroduces DNS — out of scope for the pure path.
- **Reachability:** fails behind CGNAT or a router with no port-control. Use Recipe 2 there.

Verify from *off* your network: `curl -k https://<public-ip>:<port>/`.

---

## Recipe 2 — Outbound tunnel (IP hidden)

The origin keeps an outbound tunnel to an edge that fronts it. Your home IP is never exposed.
**This is how `ctx.network` is deployed**, using a Cloudflare tunnel — but any tunnel works
(ngrok, Tailscale Funnel, a WireGuard box, …); only the tunnel software differs, the SCP config
is identical.

```rust
host_site(HostSiteConfig {
    site_dir: Some("./site".into()),
    storage_path: Some("./data".into()),
    // tls defaults to TlsMode::SelfSigned — self-signed HTTPS origin; tunnel connects noTLSVerify
    // dht defaults to DhtMode::Disabled — don't publish; the tunnel hostname is the address
    ..HostSiteConfig::defaults(Reach::Tunnel {
        public_url: "https://example.com".into(),  // the tunnel provides reachability; no NAT probe
    })
})
```

External infrastructure (Cloudflare example):

```yaml
# ~/.cloudflared/<tunnel>.yml
tunnel: <tunnel-uuid>
credentials-file: ~/.cloudflared/<tunnel-uuid>.json
ingress:
  - hostname: example.com
    service: https://localhost:8443
    originRequest:
      noTLSVerify: true        # self-signed origin behind the already-encrypted tunnel
  - service: http_status:404
```

- CNAME the hostname to the tunnel; the edge issues and serves a real (Let's Encrypt) certificate.
- Run `cloudflared tunnel run <tunnel>` (e.g. as a service / LaunchAgent).

Trade-offs:

- **Operator in the path:** the edge terminates public TLS, so it sees plaintext and controls
  availability — a trusted operator. Honest dual layer: SCP remains the origin and source of
  truth; the edge is a CDN/ingress in front of it.
- **IP exposure:** none — only the outbound tunnel reaches your node. Works behind CGNAT and
  locked-down routers where Recipe 1 cannot.
- If your tunnel terminates to plain HTTP instead of HTTPS, set `tls: TlsMode::Plaintext`.

Verify: `curl https://example.com/` from anywhere; `curl -sk https://127.0.0.1:8443/` locally.

---

## Recipe 3 — Reverse proxy (your own front door)

A reverse proxy (nginx, Caddy, …) you control terminates public TLS and forwards to the node on
loopback. Standard for anyone who already runs a web server or has a VPS with a domain.

```rust
host_site(HostSiteConfig {
    site_dir: Some("./site".into()),
    storage_path: Some("./data".into()),
    tls: TlsMode::Plaintext,         // node serves plain HTTP on loopback; proxy adds TLS
    // dht defaults to DhtMode::Disabled
    ..HostSiteConfig::defaults(Reach::Tunnel {
        public_url: "https://example.com".into(),  // the proxy faces the internet, not the node
    })
})
```

External infrastructure:

```nginx
# nginx
server {
    listen 443 ssl;
    server_name example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8443;
    }
}
```

```caddyfile
# Caddy (automatic Let's Encrypt)
example.com {
    reverse_proxy 127.0.0.1:8443
}
```

To keep the loopback hop encrypted too, set `tls: TlsMode::SelfSigned` (the default — omit the
`tls` override) and point the proxy at `https://127.0.0.1:8443` with upstream TLS verification
disabled (the upstream cert is self-signed), mirroring Recipe 2's `noTLSVerify`.

Trade-offs:

- **Operator in the path:** the proxy terminates TLS and sees plaintext — but *you* run it, so
  there is no third-party operator.
- **IP exposure:** visitors see the proxy's IP. On a VPS that is the VPS's IP, not your home IP;
  on the same machine it is your own.
- Certificates are real and browser-trusted (the proxy's ACME client), at the cost of a domain.

Verify: `curl https://example.com/`; locally `curl http://127.0.0.1:8443/`.

---

## At a glance

| | Recipe 1 — Direct | Recipe 2 — Tunnel | Recipe 3 — Proxy |
|---|---|---|---|
| `reach` | `Reach::NatTraversal` | `Reach::Tunnel { public_url }` | `Reach::Tunnel { public_url }` |
| `tls` | `TlsMode::SelfSigned` (default) | `TlsMode::SelfSigned` (default) | `TlsMode::Plaintext` (or `SelfSigned`) |
| `dht` | `DhtMode::Production` or `Disabled` | `DhtMode::Disabled` (default) | `DhtMode::Disabled` (default) |
| Third-party operator in path | none | the tunnel edge | none (you run the proxy) |
| Home IP exposed | yes | no | only if proxy is on the same machine |
| Browser-trusted cert | no (self-signed) | yes (edge) | yes (proxy ACME) |
| Works behind CGNAT | no | yes | yes (if proxy is reachable) |
| Extra infra | router NAT-PMP/UPnP | tunnel daemon | proxy + domain |

Pick by constraint: **Recipe 1** for full self-sovereignty when you can accept IP exposure and a
self-signed cert; **Recipe 2** when the home IP must stay hidden or the network blocks inbound
ports; **Recipe 3** when you already run a web server or VPS and want a normal cert and domain.
