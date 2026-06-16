//! Host a static website on SCP. Run: `cargo run -p scp-node --example website`
//! Then open the printed URL.
//!
//! Override the port with the `PORT` env var, e.g.
//! `PORT=9000 cargo run -p scp-node --example website`.
//!
//! This is a safe LOCAL demo: it uses `TlsMode::Plaintext` (plain HTTP),
//! `Reach::Local` (no NAT/UPnP probe, loopback-only addressing), and
//! `DhtMode::Memory` — so NO router port is opened and NOTHING is published to
//! the network. (The listener binds `0.0.0.0`, so it is also reachable on the
//! LAN at the host's local IP, but never beyond it.) For PUBLIC hosting, switch
//! `reach` to `Reach::NatTraversal` or `Reach::Tunnel { public_url }`, set
//! `tls: TlsMode::SelfSigned` (the default), and opt into `DhtMode::Production`
//! (which publishes the host's address bound to its DID to the DHT — a location
//! disclosure). See the guide: `.docs/guides/self-hosting-a-website-on-scp.md`.

use scp_node::{DhtMode, HostSiteConfig, Reach, TlsMode, host_site};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    host_site(HostSiteConfig {
        // Local demo: plaintext TLS + Reach::Local (skips NAT) + in-memory DHT
        // means nothing is published and no router port is opened.
        tls: TlsMode::Plaintext,
        dht: DhtMode::Memory,
        // `CARGO_MANIFEST_DIR` makes the sample-site path independent of the
        // directory `cargo run` is invoked from.
        site_dir: Some(concat!(env!("CARGO_MANIFEST_DIR"), "/examples/website-site").into()),
        // `PORT` overrides the bind port. The demo defaults to 8080 (not the
        // conventional 8443) so it won't collide with a real node already bound
        // to 8443. An unset `PORT` uses 8080 silently; a set-but-invalid `PORT`
        // warns and falls back to 8080.
        port: std::env::var("PORT").map_or(8080, |raw| {
            raw.parse::<u16>().unwrap_or_else(|_| {
                eprintln!("PORT={raw:?} is not a valid u16 port number; using 8080");
                8080
            })
        }),
        ..HostSiteConfig::defaults(Reach::Local)
    })
    .await?;
    Ok(())
}
