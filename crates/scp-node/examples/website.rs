//! Host a static website on SCP. Run: `cargo run -p scp-node --example website`
//! Then open the printed URL.
//!
//! Override the port with the `PORT` env var, e.g.
//! `PORT=9000 cargo run -p scp-node --example website`.
//!
//! This is a safe LOCAL demo: it serves plain HTTP, skips all NAT/UPnP port
//! mapping, and uses an in-memory DHT — so NO router port is opened and NOTHING
//! is published to the network. (The listener binds `0.0.0.0`, so it is also
//! reachable on the LAN at the host's local IP, but never beyond it.) For PUBLIC
//! hosting, drop `plaintext`/`skip_nat` and opt into `DhtMode::Production` (which
//! publishes the host's address bound to its DID to the DHT — a location
//! disclosure). See the guide: `.docs/guides/self-hosting-a-website-on-scp.md`.

use scp_node::{DhtMode, HostSiteOptions, host_site};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    host_site(HostSiteOptions {
        // `CARGO_MANIFEST_DIR` makes the sample-site path independent of the
        // directory `cargo run` is invoked from.
        site_dir: Some(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/website-site").into()),
        // Local demo: plaintext + skip-NAT + in-memory DHT means nothing is
        // published and no router port is opened.
        plaintext: true,
        skip_nat: true,
        dht_mode: DhtMode::Memory,
        // `PORT` overrides the bind port. The demo defaults to 8080 (not the
        // conventional 8443) so it won't collide with a real node already
        // bound to 8443. Unset or unparseable `PORT` falls back to 8080.
        port: std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(8080),
        ..Default::default()
    })
    .await?;
    Ok(())
}
