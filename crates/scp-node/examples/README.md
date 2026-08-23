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

**On a shipped build this exits 1 on every run.** `host_site` asks for
`IdentitySource::Persisted`, and creating a new identity needs a
`PreRotationCustody` backend whose only implementation is the test harness, so a
shipped build fails closed rather than mint a nullifier-backed identity. The
example's own doc comment quotes the exact error. Reloading a stored identity
carries no gate, but the node's own identity paths never mint one, so
`$XDG_DATA_HOME/scp/node` never comes to hold one. Build with `--features
testing` to run the example end to end.

### What this example does

It hosts the small site under [`website-site/`](./website-site/) (an
`index.html` + `style.css`). The page is published as encrypted broadcast
content and served back through the node's projection handler — there is no
traditional web server and no DNS.

### Local demo vs public hosting

The example is a **LOCAL demo**: `HostSiteConfig::defaults(Reach::Local)` with
`tls: TlsMode::Plaintext` and `dht: DhtMode::Disabled` — no NAT probe, no router
port opened, nothing published. (The source doc-comment explains each choice.)

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
SCP_NODE_DHT_MODE=disabled scp-node --self-host --site-dir ./my-site
```

`--self-host` on its own defaults to publishing: `SCP_NODE_DHT_MODE` defaults to
`production`, which puts the host's public IP, bound to its DID, on the global
Mainline DHT. Set it to `disabled` for a site that publishes nothing. This path
hits the same wall as the example above.

[`scp_node::host_site`]: https://docs.rs/scp-node
