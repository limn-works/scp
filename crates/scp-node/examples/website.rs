//! Host a static website on SCP. Run: `cargo run -p scp-node --example website`
//! Then open the printed URL.
//!
//! Override the port with the `PORT` env var, e.g.
//! `PORT=9000 cargo run -p scp-node --example website`.
//!
//! ON A SHIPPED BUILD THIS EXITS 1 ON EVERY RUN, and prints:
//!
//! ```text
//! Error: NodeBuild("identity error: no production pre-rotation custody backend
//! available; pre-rotation recovery custody is not yet implemented — see
//! #1729 / RFC #2130")
//! ```
//!
//! `host_site` asks for `IdentitySource::Persisted`, and creating a new identity
//! requires a `PreRotationCustody` backend (spec §9.7.4.1 §3). The only
//! implementation is the test-harness `InMemoryPreRotationCustody`, so a shipped
//! build fails closed here instead of minting a nullifier-backed identity. The
//! trailing tag is part of the message the program prints, quoted verbatim.
//! Reloading a stored identity carries no gate, but the node's own identity
//! paths never mint one, so `$XDG_DATA_HOME/scp/node` never comes to hold one. A `testing`
//! build creates and persists one, and then serves the site.
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
