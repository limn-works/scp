#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
//! Interactive CLI demo: two terminals exchange encrypted messages through
//! a real SCP relay.
//!
//! ```text
//! Terminal 1: cargo run -p scp-demo -- --name Alice
//! Terminal 2: cargo run -p scp-demo -- --name Bob --join
//! ```
//!
//! # What's real
//!
//! - WebSocket transport via `RelayServer` + `NativeRelayAdapter`
//! - AES-256-GCM sender key encryption with AAD binding
//! - did:dht identity creation via `InMemoryKeyCustody`
//! - Pseudonym-based routing (HMAC-SHA256 derived)
//! - Outer envelope serialization
//!
//! # What's demo scaffolding
//!
//! - Key exchange via `/tmp/` files (production uses HPKE over MLS)
//! - Single sender key per participant (production uses MLS group ratchet)

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;

use clap::Parser;
use futures::StreamExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncBufReadExt;
use tokio::sync::mpsc;

use scp_core::crypto::sender_keys::encrypt::{decrypt_sender_layer, encrypt_sender_layer};
use scp_core::crypto::sender_keys::{SenderKey, generate_sender_key};
use scp_core::envelope::pseudonym::derive_pseudonym;
use scp_identity::{DidDht, DidMethod};
use scp_platform::testing::InMemoryKeyCustody;
use scp_transport::native::adapter::NativeRelayAdapter;
use scp_transport::native::server::{RelayConfig, RelayServer};
use scp_transport::native::storage::BlobStorageBackend;
use scp_transport::relay::connection::{RelayUrlSource, SourcedRelayUrl};
use scp_transport::traits::{RoutingId, TransportAdapter, TransportEvent};

// ANSI color codes.
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";
const YELLOW: &str = "\x1b[33m";

const RELAY_PORT: u16 = 9000;
const INVITE_PATH: &str = "/tmp/scp-demo-invite.json";
const JOINED_PATH: &str = "/tmp/scp-demo-joined.json";
const CTX_ID: &str = "scp-demo-chat";

#[derive(Parser)]
#[command(name = "scp-demo", about = "SCP encrypted chat demo")]
struct Cli {
    /// Your display name (e.g., Alice, Bob).
    #[arg(long)]
    name: String,
    /// Join an existing session (read invite file instead of creating one).
    #[arg(long, default_value_t = false)]
    join: bool,
}

/// Invite file written by the creator for the joiner.
#[derive(serde::Serialize, serde::Deserialize)]
struct InviteFile {
    context_id_hex: String,
    routing_id_hex: String,
    creator_did: String,
    creator_name: String,
    sender_key_hex: String,
    relay_url: String,
}

/// Response file written by the joiner for the creator.
#[derive(serde::Serialize, serde::Deserialize)]
struct JoinedFile {
    joiner_did: String,
    joiner_name: String,
    sender_key_hex: String,
}

/// A chat message serialized to JSON, then encrypted.
#[derive(serde::Serialize, serde::Deserialize)]
struct ChatMessage {
    sender_did: String,
    sender_name: String,
    text: String,
}

fn context_id_bytes() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CTX_ID.as_bytes());
    h.finalize().into()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if cli.join {
        run_joiner(&cli.name).await;
    } else {
        run_creator(&cli.name).await;
    }
}

// ---------------------------------------------------------------------------
// Creator: starts relay, creates identity, writes invite, waits for joiner.
// ---------------------------------------------------------------------------

async fn run_creator(name: &str) {
    println!(
        "\n{BOLD}{YELLOW}=== SCP Encrypted Chat Demo ==={RESET}\n\
         {DIM}Starting relay on 127.0.0.1:{RELAY_PORT}...{RESET}"
    );

    // 1. Start relay.
    let config = RelayConfig {
        bind_addr: SocketAddr::from(([127, 0, 0, 1], RELAY_PORT)),
        delivery_jitter_ms: 0,
        ..RelayConfig::default()
    };
    let storage = Arc::new(BlobStorageBackend::in_memory());
    let server = RelayServer::new(config, storage);
    let (_shutdown, addr) = server.start().await.expect("failed to start relay");
    let relay_url = format!("ws://{addr}/scp/v1");
    println!("{DIM}  Relay listening on {addr}{RESET}");

    // 2. Create identity.
    let custody = InMemoryKeyCustody::new();
    let dht = DidDht::new();
    let (identity, _doc) = dht.create(&custody).await.expect("failed to create DID");
    let did_short = truncate_did(&identity.did);
    println!("{DIM}  Identity: {did_short}{RESET}");

    // 3. Generate sender key (AES-256-GCM).
    let my_sender_key = generate_sender_key();
    println!("{DIM}  Sender key generated (AES-256-GCM, 256-bit){RESET}");

    // 4. Derive routing pseudonym.
    let ctx_bytes = context_id_bytes();
    let pseudonym = derive_pseudonym(&custody, &identity.identity_key, CTX_ID.as_bytes())
        .await
        .expect("failed to derive pseudonym");
    let routing_arr: [u8; 32] = pseudonym
        .public_key
        .as_bytes()
        .try_into()
        .expect("pseudonym must be 32 bytes");
    println!(
        "{DIM}  Routing pseudonym: {}...{RESET}",
        &hex::encode(routing_arr)[..16]
    );

    // 5. Write invite file.
    let invite = InviteFile {
        context_id_hex: hex::encode(ctx_bytes),
        routing_id_hex: hex::encode(routing_arr),
        creator_did: identity.did.clone(),
        creator_name: name.to_owned(),
        sender_key_hex: hex::encode(my_sender_key.as_bytes()),
        relay_url: relay_url.clone(),
    };
    std::fs::write(INVITE_PATH, serde_json::to_string_pretty(&invite).unwrap())
        .expect("failed to write invite file");
    println!("{DIM}  Invite written to {INVITE_PATH}{RESET}");

    println!(
        "\n{BOLD}Waiting for peer to join...{RESET}\n\
         {DIM}  In another terminal: cargo run -p scp-demo -- --name Bob --join{RESET}\n"
    );

    // 6. Poll for joined file.
    loop {
        if std::path::Path::new(JOINED_PATH).exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    let joined: JoinedFile =
        serde_json::from_str(&std::fs::read_to_string(JOINED_PATH).unwrap()).unwrap();

    // Clean up temp files.
    let _ = std::fs::remove_file(INVITE_PATH);
    let _ = std::fs::remove_file(JOINED_PATH);

    // Parse peer's sender key.
    let peer_sk_bytes: [u8; 32] = hex::decode(&joined.sender_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let peer_sender_key = SenderKey::from_bytes(peer_sk_bytes);

    print_chat_header(name, &joined.joiner_name, &relay_url);

    chat_loop(
        name,
        &relay_url,
        &my_sender_key,
        &peer_sender_key,
        &identity.did,
        &joined.joiner_did,
        &routing_arr,
        &ctx_bytes,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Joiner: reads invite, creates identity, writes joined file.
// ---------------------------------------------------------------------------

async fn run_joiner(name: &str) {
    println!(
        "\n{BOLD}{YELLOW}=== SCP Encrypted Chat Demo ==={RESET}\n\
         {DIM}Looking for invite at {INVITE_PATH}...{RESET}"
    );

    // 1. Wait for invite file.
    loop {
        if std::path::Path::new(INVITE_PATH).exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    let invite: InviteFile =
        serde_json::from_str(&std::fs::read_to_string(INVITE_PATH).unwrap()).unwrap();
    println!("{DIM}  Found invite from {}{RESET}", invite.creator_name);

    // 2. Create identity.
    let custody = InMemoryKeyCustody::new();
    let dht = DidDht::new();
    let (identity, _doc) = dht.create(&custody).await.expect("failed to create DID");
    let did_short = truncate_did(&identity.did);
    println!("{DIM}  Identity: {did_short}{RESET}");

    // 3. Generate sender key.
    let my_sender_key = generate_sender_key();
    println!("{DIM}  Sender key generated (AES-256-GCM, 256-bit){RESET}");

    // 4. Parse invite data.
    let ctx_bytes: [u8; 32] = hex::decode(&invite.context_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let routing_arr: [u8; 32] = hex::decode(&invite.routing_id_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let peer_sk_bytes: [u8; 32] = hex::decode(&invite.sender_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let peer_sender_key = SenderKey::from_bytes(peer_sk_bytes);

    // 5. Write joined file.
    let joined = JoinedFile {
        joiner_did: identity.did.clone(),
        joiner_name: name.to_owned(),
        sender_key_hex: hex::encode(my_sender_key.as_bytes()),
    };
    std::fs::write(JOINED_PATH, serde_json::to_string_pretty(&joined).unwrap())
        .expect("failed to write joined file");
    println!("{DIM}  Join response written to {JOINED_PATH}{RESET}");

    // Small delay to let creator read the file before we delete it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    print_chat_header(name, &invite.creator_name, &invite.relay_url);

    chat_loop(
        name,
        &invite.relay_url,
        &my_sender_key,
        &peer_sender_key,
        &identity.did,
        &invite.creator_did,
        &routing_arr,
        &ctx_bytes,
    )
    .await;
}

// ---------------------------------------------------------------------------
// Chat loop.
// ---------------------------------------------------------------------------

async fn chat_loop(
    name: &str,
    relay_url: &str,
    my_sender_key: &SenderKey,
    peer_sender_key: &SenderKey,
    my_did: &str,
    peer_did: &str,
    routing_id: &[u8; 32],
    ctx_bytes: &[u8; 32],
) {
    let sourced = SourcedRelayUrl {
        url: relay_url.to_owned(),
        source: RelayUrlSource::DhtResolved,
    };

    // Two adapters: one for sending, one for receiving (separate WS connections).
    let send_adapter = NativeRelayAdapter::connect_sourced(&sourced)
        .await
        .expect("failed to connect to relay for sending");
    let recv_adapter = NativeRelayAdapter::connect_sourced(&sourced)
        .await
        .expect("failed to connect to relay for receiving");

    // Subscribe to the shared routing ID.
    let routing = RoutingId::new(*routing_id);
    let mut stream = recv_adapter
        .subscribe(&routing, None)
        .await
        .expect("failed to subscribe");

    // Channel for forwarding decoded incoming messages to the main loop.
    let (incoming_tx, mut incoming_rx) = mpsc::unbounded_channel::<String>();

    let ctx_hex = hex::encode(ctx_bytes);
    let peer_sk = peer_sender_key.clone();
    let my_did_recv = my_did.to_owned();
    let peer_did_recv = peer_did.to_owned();
    let ctx_hex_recv = ctx_hex.clone();

    // Background receiver task.
    tokio::spawn(async move {
        let mut recv_seq = 0u64;
        while let Some(event) = stream.next().await {
            match event {
                TransportEvent::Envelope(outer) => {
                    // Try to decrypt with peer's sender key at current sequence.
                    // On failure, try sequence 0..recv_seq+10 as a fallback
                    // (handles minor reordering / our own echoed messages).
                    let plaintext = try_decrypt_any_seq(
                        &peer_sk,
                        &outer.encrypted_blob,
                        &ctx_hex_recv,
                        &peer_did_recv,
                        recv_seq,
                    );

                    let Some(plain) = plaintext else {
                        // Not from peer (probably our own echo) — skip.
                        continue;
                    };

                    recv_seq += 1;

                    let Ok(msg) = serde_json::from_slice::<ChatMessage>(&plain) else {
                        continue;
                    };

                    if msg.sender_did == my_did_recv {
                        // Our own message echoed back — skip.
                        continue;
                    }

                    let _ = incoming_tx.send(format!(
                        "\r{CYAN}{BOLD}{}>{RESET} {}{DIM} ({} bytes over wire){RESET}",
                        msg.sender_name,
                        msg.text,
                        outer.encrypted_blob.len(),
                    ));
                }
                TransportEvent::Terminated { reason } => {
                    eprintln!("{DIM}Subscription terminated: {reason}{RESET}");
                    break;
                }
                _ => {}
            }
        }
    });

    // Main input loop.
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut send_seq = 0u64;

    loop {
        print!("{GREEN}{BOLD}{name}>{RESET} ");
        std::io::stdout().flush().unwrap();

        tokio::select! {
            biased;
            Some(display) = incoming_rx.recv() => {
                println!("{display}");
            }
            line = lines.next_line() => {
                if let Ok(Some(text)) = line {
                    let text = text.trim().to_owned();
                    if text.is_empty() {
                        continue;
                    }
                    if text == "/quit" {
                        println!("{DIM}Goodbye!{RESET}");
                        break;
                    }
                    if text == "/info" {
                        println!(
                            "{DIM}  Context ID: {CTX_ID}\n  \
                             Context hash: {}...\n  \
                             Routing ID:   {}...\n  \
                             My DID:       {}\n  \
                             Peer DID:     {}\n  \
                             Messages sent: {send_seq}{RESET}",
                            &hex::encode(ctx_bytes)[..16],
                            &hex::encode(routing_id)[..16],
                            truncate_did(my_did),
                            truncate_did(peer_did),
                        );
                        continue;
                    }

                    // Build message.
                    let msg = ChatMessage {
                        sender_did: my_did.to_owned(),
                        sender_name: name.to_owned(),
                        text,
                    };
                    let payload = serde_json::to_vec(&msg).unwrap();

                    // Encrypt with sender key (AES-256-GCM with AAD).
                    let ciphertext = encrypt_sender_layer(
                        my_sender_key,
                        &payload,
                        &ctx_hex,
                        my_did,
                        0,
                        send_seq,
                    )
                    .expect("encryption failed");

                    // Wrap in outer envelope.
                    let outer = scp_core::envelope::OuterEnvelope {
                        version: 0x0100,
                        routing_id: routing_id.to_vec(),
                        recipient_hint: None,
                        blob_ttl: 300,
                        encrypted_blob: ciphertext,
                    };

                    match send_adapter.send(&outer).await {
                        Ok(_blob_id) => {
                            send_seq += 1;
                        }
                        Err(e) => {
                            eprintln!("{DIM}Send error: {e}{RESET}");
                        }
                    }
                } else {
                    println!("{DIM}Goodbye!{RESET}");
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Try decrypting with the peer's sender key at a range of sequence numbers.
/// Returns the first successful decryption, or `None`.
fn try_decrypt_any_seq(
    sender_key: &SenderKey,
    ciphertext: &[u8],
    ctx_hex: &str,
    sender_did: &str,
    expected_seq: u64,
) -> Option<Vec<u8>> {
    // Try expected sequence first.
    if let Ok(plain) =
        decrypt_sender_layer(sender_key, ciphertext, ctx_hex, sender_did, 0, expected_seq)
    {
        return Some(plain);
    }
    // Fallback: try a small window around the expected sequence.
    let start = expected_seq.saturating_sub(2);
    let end = expected_seq.saturating_add(5);
    for seq in start..=end {
        if seq == expected_seq {
            continue;
        }
        if let Ok(plain) = decrypt_sender_layer(sender_key, ciphertext, ctx_hex, sender_did, 0, seq)
        {
            return Some(plain);
        }
    }
    None
}

fn truncate_did(did: &str) -> String {
    if did.len() > 30 {
        format!("{}...{}", &did[..20], &did[did.len() - 8..])
    } else {
        did.to_owned()
    }
}

fn print_chat_header(my_name: &str, peer_name: &str, relay_url: &str) {
    println!(
        "\n{BOLD}{GREEN}Connected!{RESET} {my_name} <-> {peer_name}\n\
         {DIM}  Relay: {relay_url}\n\
         Encryption: AES-256-GCM sender keys\n  \
         Transport: WebSocket (SCP native relay){RESET}\n\
         \n{DIM}Type a message and press Enter.\n\
         /info — show context details\n\
         /quit — exit{RESET}\n"
    );
}
