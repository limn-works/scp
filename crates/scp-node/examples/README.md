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

For **public hosting**, switch `reach` and opt into `dht: DhtMode::Production`.
That selects the production Mainline DHT, which **publishes the host's public
address bound to the node's DID** — an IP-to-identity / approximate-location
disclosure. Make that choice deliberately. The other defaults are public-ready:
`tls: TlsMode::SelfSigned` (the "be your own CA" no-DNS model) and
`reach: Reach::NatTraversal` (NAT-PMP/UPnP, built with `--features upnp`). If
your node sits behind a tunnel/proxy (e.g. a Cloudflare tunnel) use
`Reach::Tunnel { public_url }` and let the tunnel provide external reachability.

See the full guide: [`.docs/guides/self-hosting-a-website-on-scp.md`](../../../.docs/guides/self-hosting-a-website-on-scp.md).

For the three ways to expose a site publicly (direct IP, outbound tunnel, reverse proxy), see the [deployment recipes guide](../../../.docs/guides/deploying-an-scp-website.md).

### Turnkey alternative

If you don't need to embed hosting in your own program, the `scp-node` binary
hosts a site directly:

```sh
scp-node --self-host --site-dir ./my-site
```

[`scp_node::host_site`]: https://docs.rs/scp-node
