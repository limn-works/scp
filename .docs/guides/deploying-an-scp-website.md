# Deploying an SCP Website: Three Recipes

An SCP self-hosted site is an ordinary Rust program that calls
[`scp_node::host_site`](../../crates/scp-node/examples/website.rs) — the SCP node *is* the
web server (content is published as encrypted broadcast blobs and decrypted on serve; there is
no separate web server and no DNS requirement on the origin). See the runnable example at
`crates/scp-node/examples/website.rs` and the background guide
[`self-hosting-a-website-on-scp.md`](./self-hosting-a-website-on-scp.md).

What changes between deployments is **not the code** — it's a few `HostSiteOptions` fields plus
the surrounding network plumbing. The same `host_site` call powers all three recipes below; each
recipe lists only the option deltas and the external infrastructure.

The three knobs that matter:

| Field | Meaning |
|---|---|
| `skip_nat` | `false` = probe the external address (STUN) and open a router port via NAT-PMP/UPnP (needs `--features upnp`). `true` = bind loopback only; something else (a tunnel or proxy) provides reachability. |
| `plaintext` | `false` = serve self-signed HTTPS (be-your-own-CA, no DNS). `true` = serve plain HTTP (for when a tunnel or proxy terminates TLS in front). |
| `dht_mode` | `Memory` = never publish this node's address (fail-safe default). `Production` = publish the node's public address bound to its DID to the global Mainline DHT — an IP-to-identity / approximate-location disclosure, and a deliberate opt-in. |

---

## Recipe 1 — Direct (raw public IP, no operator)

The pure-SCP path: your machine is the public endpoint, with no third party in the data path.

```rust
host_site(HostSiteOptions {
    site_dir: Some("./site".into()),
    storage_path: Some("./data".into()),
    skip_nat: false,                  // probe + open a router port via NAT-PMP/UPnP
    plaintext: false,                 // self-signed HTTPS (be your own CA)
    dht_mode: DhtMode::Production,    // publish address->DID so the site is DID-discoverable
    ..Default::default()
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

- **IP exposure:** every visitor sees your machine's public IP. With `dht_mode: Production` that
  IP is additionally bound to your node's DID in the global DHT. Use `dht_mode: Memory` to keep
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
host_site(HostSiteOptions {
    site_dir: Some("./site".into()),
    storage_path: Some("./data".into()),
    skip_nat: true,                  // the tunnel provides reachability; open no router port
    plaintext: false,                // self-signed HTTPS origin (tunnel connects noTLSVerify)
    dht_mode: DhtMode::Memory,       // don't publish; the tunnel hostname is the address
    ..Default::default()
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
- If your tunnel terminates to plain HTTP instead of HTTPS, set `plaintext: true`.

Verify: `curl https://example.com/` from anywhere; `curl -sk https://127.0.0.1:8443/` locally.

---

## Recipe 3 — Reverse proxy (your own front door)

A reverse proxy (nginx, Caddy, …) you control terminates public TLS and forwards to the node on
loopback. Standard for anyone who already runs a web server or has a VPS with a domain.

```rust
host_site(HostSiteOptions {
    site_dir: Some("./site".into()),
    storage_path: Some("./data".into()),
    skip_nat: true,                  // the proxy faces the internet, not the node
    plaintext: true,                 // node serves plain HTTP on loopback; proxy adds TLS
    dht_mode: DhtMode::Memory,
    ..Default::default()
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

To keep the loopback hop encrypted too, set `plaintext: false` and point the proxy at
`https://127.0.0.1:8443` with upstream TLS verification disabled (the upstream cert is
self-signed), mirroring Recipe 2's `noTLSVerify`.

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
| `skip_nat` | `false` | `true` | `true` |
| `plaintext` | `false` | `false` | `true` (or `false`) |
| `dht_mode` | `Production` or `Memory` | `Memory` | `Memory` |
| Third-party operator in path | none | the tunnel edge | none (you run the proxy) |
| Home IP exposed | yes | no | only if proxy is on the same machine |
| Browser-trusted cert | no (self-signed) | yes (edge) | yes (proxy ACME) |
| Works behind CGNAT | no | yes | yes (if proxy is reachable) |
| Extra infra | router NAT-PMP/UPnP | tunnel daemon | proxy + domain |

Pick by constraint: **Recipe 1** for full self-sovereignty when you can accept IP exposure and a
self-signed cert; **Recipe 2** when the home IP must stay hidden or the network blocks inbound
ports; **Recipe 3** when you already run a web server or VPS and want a normal cert and domain.
