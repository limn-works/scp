//! Publishes messages to a routing ID on an SCP relay.
//!
//! Usage:
//!   `cargo run -p scp-transport --example relay-send -- [RELAY_URL] [ROUTING_ID_HEX] "message"`
//!
//! If no message is given, sends a series of demo messages.
//!
//! Defaults:
//!   `RELAY_URL`      = `ws://127.0.0.1:19000/scp/v1`
//!   `ROUTING_ID_HEX` = aa…aa (32 bytes of 0xaa)

use scp_core::envelope::create_outer_envelope;
use scp_transport::native::NativeRelayAdapter;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::{RoutingId, TransportAdapter};

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

async fn send_message(adapter: &NativeRelayAdapter, routing_id: &[u8; 32], text: &str) {
    let envelope = create_outer_envelope(routing_id, None, 60, text.as_bytes().to_vec())
        .unwrap_or_else(|e| {
            eprintln!("failed to create envelope: {e}");
            std::process::exit(1);
        });

    match adapter.send(&envelope).await {
        Ok(blob_id) => {
            println!(
                "[SENT] blob_id={} payload=\"{text}\" ({} bytes)",
                hex(blob_id.as_bytes()),
                text.len(),
            );
        }
        Err(e) => {
            eprintln!("[ERR]  send failed: {e}");
        }
    }
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

    let rid_hex = hex(&routing_id);

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
    let profile = scp_transport::profile::TransportProfile::platform_default();
    let adapter = NativeRelayAdapter::connect_sourced(&sourced, Some(&profile))
        .await
        .unwrap_or_else(|e| {
            eprintln!("connection failed: {e}");
            std::process::exit(1);
        });

    eprintln!("Connected. Routing ID: {rid_hex}\n");

    // If a message was provided on the command line, send just that.
    if let Some(msg) = args.get(3) {
        send_message(&adapter, &routing_id, msg).await;
        return;
    }

    // Otherwise, send a demo conversation.
    let messages = [
        "Hey, this is a real SCP envelope sent through the SDK.",
        "OuterEnvelope wraps the payload, relay routes by routing_id.",
        "The relay is a dumb pipe -- it sees only opaque blobs.",
        "In production this payload would be MLS-encrypted ciphertext.",
        "Ship it.",
    ];

    let rid = RoutingId::new(routing_id);
    eprintln!(
        "Sending {} messages to routing_id {rid_hex}...\n",
        messages.len()
    );
    let _ = rid; // just used for printing

    for msg in &messages {
        send_message(&adapter, &routing_id, msg).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    eprintln!("\nDone.");
}
