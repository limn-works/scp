# scp-node examples

## `website` — host a static website on SCP from Rust

This is the developer-facing way to host a website on SCP: a normal async Rust
library call, [`scp_node::host_site`]. It is the same deploy + serve core that
the turnkey `scp-node --self-host` binary runs, exposed as a library function so
you can embed it in your own program.

Run it:

```sh
cargo run -p scp-node --features testing --example website
```

Then open the printed URL in a browser.

**Without `scp-node`'s `testing` feature, this exits 1 on every run**, and that
includes `cargo run -p scp-node --example website` from a checkout. `host_site`
asks for `IdentitySource::Persisted`, and creating a new identity needs a
`PreRotationCustody` backend whose only implementation is the test harness, so
a build without `testing` fails closed rather than mint a nullifier-backed
identity. The example's own doc comment quotes the error.

Each run stores its identity in a new, randomly named directory under the
system temporary directory, created with `tempfile::TempDir` and removed when
the example exits. On Unix the example sets that directory's mode to 0700 and
exits with an error if it reads back any group or other bit. The example never
uses the `scp-node` binary's default storage directory, and a run never reloads
an identity an earlier run left behind. The binary reloads any identity it finds
in its default directory without checking how it was created, so an
identity a `testing` run minted must never land there.

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
