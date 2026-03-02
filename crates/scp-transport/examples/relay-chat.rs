//! Interactive chat client for an SCP relay.
//!
//! Subscribes to a routing ID and prints incoming messages while accepting
//! stdin input to send messages in real time.
//!
//! Usage:
//!   `cargo run -p scp-transport --example relay-chat -- [RELAY_URL] [ROUTING_ID_HEX]`
//!
//! Defaults:
//!   `RELAY_URL`      = `ws://127.0.0.1:9000/scp/v1`
//!   `ROUTING_ID_HEX` = aa…aa (32 bytes of 0xaa)

use futures::StreamExt;
use scp_core::envelope::create_outer_envelope;
use scp_transport::native::NativeRelayAdapter;
use scp_transport::{RoutingId, TransportAdapter, TransportEvent};
use std::sync::Arc;
use tokio::io::AsyncBufReadExt;

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
        .map_or("ws://127.0.0.1:9000/scp/v1", |s| s.as_str());
    let routing_id = args.get(2).map_or([0xaa; 32], |h| hex_to_32(h));
    let rid = RoutingId::new(routing_id);

    eprintln!("Connecting to {url}...");
    let adapter = Arc::new(NativeRelayAdapter::connect(url).await.unwrap_or_else(|e| {
        eprintln!("connection failed: {e}");
        std::process::exit(1);
    }));

    eprintln!("Subscribing to routing_id {}...", hex(&routing_id));
    let mut stream = adapter.subscribe(&rid, None).await.unwrap_or_else(|e| {
        eprintln!("subscribe failed: {e}");
        std::process::exit(1);
    });

    eprintln!("Ready. Type a message and press Enter to send. Ctrl-C to quit.\n");

    // Spawn receiver task
    let recv_handle = tokio::spawn(async move {
        while let Some(event) = stream.next().await {
            match event {
                TransportEvent::Envelope(env) => {
                    let payload = String::from_utf8_lossy(&env.encrypted_blob);
                    println!("\r< {payload}");
                    eprint!("> ");
                }
                TransportEvent::Terminated { reason } => {
                    eprintln!("\r[terminated: {reason}]");
                    break;
                }
                TransportEvent::Error(e) => {
                    eprintln!("\r[error: {e}]");
                }
                TransportEvent::SuppressionDetected(_)
                | TransportEvent::BackfillComplete
                | TransportEvent::Reconnected => {}
            }
        }
    });

    // Read stdin and send
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    eprint!("> ");
    while let Ok(Some(line)) = lines.next_line().await {
        let text = line.trim();
        if text.is_empty() {
            eprint!("> ");
            continue;
        }

        let envelope = create_outer_envelope(&routing_id, None, 60, text.as_bytes().to_vec())
            .unwrap_or_else(|e| {
                eprintln!("[envelope error: {e}]");
                std::process::exit(1);
            });

        match adapter.send(&envelope).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("[send error: {e}]");
            }
        }
        eprint!("> ");
    }

    recv_handle.abort();
}
