//! Subscribes to a routing ID on an SCP relay and prints every received
//! envelope in real time.
//!
//! Usage:
//!   `cargo run -p scp-transport --example relay-listen -- [RELAY_URL] [ROUTING_ID_HEX]`
//!
//! Defaults:
//!   `RELAY_URL`      = `ws://127.0.0.1:19000/scp/v1`
//!   `ROUTING_ID_HEX` = aa…aa (32 bytes of 0xaa)

use futures::StreamExt;
use scp_transport::native::NativeRelayAdapter;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::{RoutingId, TransportAdapter, TransportEvent};

fn hex_to_32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate().take(32) {
        let s = std::str::from_utf8(chunk).unwrap_or("00");
        out[i] = u8::from_str_radix(s, 16).unwrap_or(0);
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args: Vec<String> = std::env::args().collect();
    let url = args
        .get(1)
        .map_or("ws://127.0.0.1:19000/scp/v1", |s| s.as_str());
    let routing_id = args.get(2).map_or([0xaa; 32], |h| hex_to_32(h));

    let rid = RoutingId::new(routing_id);

    eprintln!("Connecting to {url}...");
    // Semantic note: DhtResolved is used here because it is the only
    // RelayUrlSource variant that permits ws:// (plaintext) connections
    // (§10.12.6). The URL was not actually resolved via DHT -- it is a
    // CLI-provided local address. This is acceptable for examples targeting
    // local development relays. Production code must use the variant matching
    // the actual discovery path (Explicit, WellKnown, PeerDiscovered, etc.).
    let sourced = SourcedRelayUrl {
        url: url.to_owned(),
        source: RelayUrlSource::DhtResolved,
    };
    let adapter = NativeRelayAdapter::connect_sourced(&sourced)
        .await
        .unwrap_or_else(|e| {
            eprintln!("connection failed: {e}");
            std::process::exit(1);
        });

    eprintln!("Subscribing to routing_id {}...", hex(&routing_id));
    let mut stream = adapter.subscribe(&rid, None).await.unwrap_or_else(|e| {
        eprintln!("subscribe failed: {e}");
        std::process::exit(1);
    });

    eprintln!("Listening. Press Ctrl-C to stop.\n");

    while let Some(event) = stream.next().await {
        match event {
            TransportEvent::Envelope(env) => {
                let payload = String::from_utf8_lossy(&env.encrypted_blob);
                println!(
                    "[RECV] routing_id={} ttl={}s payload=\"{}\" ({} bytes)",
                    hex(&env.routing_id),
                    env.blob_ttl,
                    payload,
                    env.encrypted_blob.len(),
                );
            }
            TransportEvent::BackfillComplete => {
                println!("[EVENT] backfill complete");
            }
            TransportEvent::Reconnected => {
                println!("[EVENT] reconnected to relay");
            }
            TransportEvent::Terminated { reason } => {
                println!("[EVENT] terminated: {reason}");
                break;
            }
            TransportEvent::Error(e) => {
                println!("[ERROR] {e}");
            }
            TransportEvent::SuppressionDetected(_) => {}
        }
    }
}
