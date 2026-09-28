//! Host a static website on SCP. Run:
//! `cargo run -p scp-node --features testing --example website`
//! Then open the printed URL.
//!
//! Override the port with the `PORT` env var, e.g.
//! `PORT=9000 cargo run -p scp-node --features testing --example website`.
//!
//! WITHOUT `scp-node`'s `testing` FEATURE THIS EXITS 1 ON EVERY RUN. That covers
//! `cargo run -p scp-node --example website` from a checkout as well as a build
//! against the published crate. It fails with
//! `IdentityError::NoPreRotationBackend`, whose message begins:
//!
//! ```text
//! Error: NodeBuild("identity error: no production pre-rotation custody backend
//! available; pre-rotation recovery custody is not yet implemented
//! ```
//!
//! `host_site` asks for `IdentitySource::Persisted`, and creating a new identity
//! requires a `PreRotationCustody` backend (spec §9.7.4.1 §3). The only
//! implementation is the test-harness `InMemoryPreRotationCustody`, so a build
//! without `testing` fails closed here instead of minting a nullifier-backed
//! identity.
//!
//! Each run stores its identity in a fresh directory of its own under the system
//! temporary directory, never in the `scp-node` binary's default storage
//! directory. A `testing` run mints its identity with that test-harness custody,
//! and the binary reloads whatever identity its storage directory holds without
//! checking how it was created, so writing there would put a test-harness
//! identity behind a shipped `scp-node --self-host`.
//!
//! This is a safe LOCAL demo: it uses `TlsMode::Plaintext` (plain HTTP),
//! `Reach::Local` (no NAT/UPnP probe, loopback-only addressing), and
//! `DhtMode::Disabled` — so NO router port is opened and NOTHING is published to
//! the network. (The listener binds `0.0.0.0`, so it is also reachable on the
//! LAN at the host's local IP, but never beyond it.) For PUBLIC hosting, pass
//! `Reach::NatTraversal` or `Reach::Tunnel { public_url }` to `defaults(...)`, set
//! `tls: TlsMode::SelfSigned` (the default), and opt into `DhtMode::Production`
//! (which publishes the host's address bound to its DID to the DHT — a location
//! disclosure). See the guide: `.docs/guides/self-hosting-a-website-on-scp.md`.

use scp_node::{DhtMode, HostSiteConfig, Reach, TlsMode, host_site};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use 8080 (not the 8443 HostSiteConfig default) to avoid colliding with a real node.
    let port: u16 = std::env::var("PORT").map_or(8080, |raw| {
        raw.parse::<u16>().unwrap_or_else(|_| {
            eprintln!("PORT={raw:?} is not a valid u16 port number; using 8080");
            8080
        })
    });
    host_site(HostSiteConfig {
        tls: TlsMode::Plaintext,
        dht: DhtMode::Disabled,
        // `CARGO_MANIFEST_DIR` makes the sample-site path independent of the
        // directory `cargo run` is invoked from.
        site_dir: Some(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/website-site").into()),
        // A fresh directory per run: see the doc comment for why this example
        // never uses the default storage directory the binary shares.
        storage_path: Some(
            std::env::temp_dir().join(format!("scp-website-example-{}", std::process::id())),
        ),
        port,
        on_ready: Some(Box::new(|ready| {
            let scheme = if ready.plaintext { "http" } else { "https" };
            println!("Site is live — open: {scheme}://localhost:{}/", ready.port);
        })),
        ..HostSiteConfig::defaults(Reach::Local)
    })
    .await?;
    Ok(())
}
