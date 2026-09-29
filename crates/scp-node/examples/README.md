# scp-node examples

## `website` — host a static website on SCP from Rust

This is the developer-facing way to host a website on SCP: a normal async Rust
library call, [`scp_node::host_site`]. It is the same deploy + serve core that
the turnkey `scp-node --self-host` binary runs, exposed as a library function so
you can embed it in your own program.

**Until a production `PreRotationCustody` backend exists ([#1729]), no build
runs this example without a test-harness stand-in.** `cargo run -p scp-node
--example website` compiles, then exits 1 on every run. `host_site` asks for
`IdentitySource::Persisted`, which `Node::start` resolves by loading the stored
identity or, when the directory holds none, creating one on its `Generate`
path. The example gives it a new, empty directory on every run, so every run
takes `Generate`. On a build without `scp-node`'s `testing` feature that path
returns `NoPreRotationBackend` whatever custody or storage is supplied: it
takes no `PreRotationCustody` input, so it fails closed rather than mint a
nullifier-backed identity. The example's own doc comment quotes the error.

A `testing` build is not a way to run it. `testing` mints the identity through
`scp_platform::testing::InMemoryPreRotationCustody`, the test-harness
pre-rotation stand-in, which holds the pre-rotation key only in process
memory. The key is gone when the process exits, so the reveal that spec
§9.7.4.1 item 4 says recovers a root compromise is unreachable for that
identity. The same
feature also turns on `allow_unencrypted_storage` and the `scp-platform` and
`scp-dht` test doubles.

Each run stores its identity in a new, randomly named directory under the
system temporary directory, created with `tempfile::TempDir` and removed when
`main` returns: after an error, or after a Ctrl-C once the site is serving.
`host_site` installs its signal handlers only when it starts serving, so a
Ctrl-C during startup kills the process and leaves the directory behind. On
Unix the example sets that directory's mode to 0700 and exits with an error
if it reads back any group or other bit. The example never uses the `scp-node` binary's default storage directory, and a
run never reloads an identity an earlier run left behind. The binary reloads any
identity it finds in its default directory without checking how it was created
([#2558]), so an identity a `testing` build minted must never land there.

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
Mainline DHT. Set it to `disabled` for a site that publishes nothing. When its
default storage directory holds no identity, this path exits with the same
`NoPreRotationBackend` error as the example above. When that directory already
holds an identity, the binary reloads it and serves, whatever build created it
([#2558]).

[`scp_node::host_site`]: https://docs.rs/scp-node
[#1729]: https://github.com/limn-works/scp/issues/1729
[#2558]: https://github.com/limn-works/scp/issues/2558
