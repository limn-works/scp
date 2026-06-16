# scp-node examples

## `website` — host a static website on SCP from Rust

This is the developer-facing way to host a website on SCP: a normal async Rust
library call, [`scp_node::host_site`]. It is the same deploy + serve core that
the turnkey `scp-node --self-host` binary runs, exposed as a library function so
you can embed it in your own program.

Run it:

```sh
cargo run -p scp-node --example website
```

Then open the printed URL in a browser.

### What this example does

It hosts the small site under [`website-site/`](./website-site/) (an
`index.html` + `style.css`). The page is published as encrypted broadcast
content and served back through the node's projection handler — there is no
traditional web server and no DNS.

### Local demo vs public hosting

The example is a **LOCAL demo**. It sets:

- `tls: TlsMode::Plaintext` — serve plain HTTP (no self-signed-cert dance);
- `reach: Reach::Local` — no NAT/UPnP probing and loopback-only addressing, so
  **no router port is opened**;
- `dht: DhtMode::Memory` — use an in-memory DHT, so **nothing is published
  to the network**.

The listener binds `0.0.0.0`, so it is reachable on your LAN at the host's local
IP — but with `Reach::Local` and the in-memory DHT, it is never exposed beyond
the local network and the node's address is never published.

For **public hosting** (direct IP, outbound tunnel, or reverse proxy), see the
[deployment recipes](../../../.docs/guides/deploying-an-scp-website.md) — the
`reach`/`tls`/`dht` knob table and step-by-step recipes are there, including the
DHT location-disclosure trade-off that `DhtMode::Production` opts into. The
[background guide](../../../.docs/guides/self-hosting-a-website-on-scp.md) covers
addressing, NAT traversal, and the full self-host architecture in depth.

### Turnkey alternative

If you don't need to embed hosting in your own program, the `scp-node` binary
hosts a site directly:

```sh
scp-node --self-host --site-dir ./my-site
```

[`scp_node::host_site`]: https://docs.rs/scp-node
