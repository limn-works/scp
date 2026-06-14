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

- `plaintext: true` — serve plain HTTP (no self-signed-cert dance);
- `skip_nat: true` — skip all NAT/UPnP port mapping, so **no router port is
  opened**;
- `dht_mode: DhtMode::Memory` — use an in-memory DHT, so **nothing is published
  to the network**.

The listener binds `0.0.0.0`, so it is reachable on your LAN at the host's local
IP — but with `skip_nat` and the in-memory DHT, it is never exposed beyond the
local network and the node's address is never published.

For **public hosting**, drop `plaintext`/`skip_nat` and opt into
`dht_mode: DhtMode::Production`. That selects the production Mainline DHT, which
**publishes the host's public address bound to the node's DID** — an
IP-to-identity / approximate-location disclosure. Make that choice
deliberately. The other defaults are public-ready: self-signed HTTPS (the "be
your own CA" no-DNS model) and NAT probing (NAT-PMP/UPnP, built with
`--features upnp`). If your node sits behind a tunnel/proxy (e.g. a Cloudflare
tunnel) keep `skip_nat: true` and let the tunnel provide external reachability.

See the full guide: [`.docs/guides/self-hosting-a-website-on-scp.md`](../../../.docs/guides/self-hosting-a-website-on-scp.md).

### Turnkey alternative

If you don't need to embed hosting in your own program, the `scp-node` binary
hosts a site directly:

```sh
scp-node --self-host --site-dir ./my-site
```

[`scp_node::host_site`]: https://docs.rs/scp-node
