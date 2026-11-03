//! The `scp-node sign-binding` local command (`09-security-model.md` §9.6.3
//! "How a node gets its key and its binding", step 2), its refusal on storage
//! that holds no node key (`17-persistence-and-storage.md` §17.3 "Node key"),
//! and the refusal of a configured binding by the modes that keep no node key
//! (step 4).

#![allow(clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};

use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use scp_did::{Identifier, NodeUrl};
use scp_protocol::node::{NodeBinding, node_url_hash};

const OPERATOR: [u8; 32] = [0x0a; 32];
const URL: &str = "wss://node.example.com/scp/v1";
const HEAD: [u8; 32] = [0x0b; 32];
const STORAGE_KEY: [u8; 32] = [0x42; 32];

/// Draws the node key into the storage directory `storage` as a node's first
/// start does (§9.6.3 step 1), through the start path's own function, and
/// returns its compressed public key.
fn draw_node_key(storage: &std::path::Path) -> [u8; 33] {
    std::fs::create_dir_all(storage).expect("storage directory");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async {
        let sqlite =
            scp_node::self_host::open_sqlite(storage, &zeroize::Zeroizing::new(STORAGE_KEY))
                .await
                .expect("open the node's storage");
        let key =
            scp_node::node_key::load_or_generate(&scp_core::store::ProtocolRepository::new(sqlite))
                .await
                .expect("draw the node key");
        *key.node_key()
    })
}

fn sign_binding(storage: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_scp-node"))
        .arg("sign-binding")
        .args(["--operator", &Identifier::from_bytes(OPERATOR).to_string()])
        .args(["--url", URL])
        .args(["--key-state-head", &hex::encode(HEAD)])
        .args(["--storage-path", storage.to_str().expect("utf-8 path")])
        .env("SCP_STORAGE_KEY", hex::encode(STORAGE_KEY))
        .stdin(Stdio::null())
        .output()
        .expect("spawn scp-node sign-binding")
}

fn member<const N: usize>(json: &serde_json::Value, name: &str) -> [u8; N] {
    let mut out = [0u8; N];
    hex::decode_to_slice(json[name].as_str().expect("a hex member"), &mut out)
        .expect("the member's length");
    out
}

/// Two runs against one storage directory sign with the node key a start
/// drew there, and each signature verifies under that key over P for the
/// arguments given.
#[test]
fn sign_binding_signs_p_with_the_key_the_storage_keeps() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = tmp.path().join("node");
    let drawn = draw_node_key(&storage);
    let mut keys = Vec::new();
    for _ in 0..2 {
        let output = sign_binding(&storage);
        assert!(
            output.status.success(),
            "sign-binding failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("stdout is JSON");
        let node_key: [u8; 33] = member(&json, "node_key");
        let url_hash: [u8; 32] = member(&json, "url_hash");
        let possession_sig: [u8; 64] = member(&json, "possession_sig");
        assert_eq!(
            url_hash,
            node_url_hash(&NodeUrl::new(URL).expect("a node URL"))
        );
        let digest = NodeBinding::signing_digest(
            &Identifier::from_bytes(OPERATOR),
            &node_key,
            &url_hash,
            &HEAD,
        );
        verify_prehash_strict(
            &P256PublicKey::from_sec1(&node_key).expect("a P-256 key"),
            &digest,
            &possession_sig,
        )
        .expect("possession_sig verifies under node_key over P");
        keys.push(node_key);
    }
    assert_eq!(
        keys,
        [drawn, drawn],
        "both runs sign with the key the start drew"
    );
}

/// On storage that holds no node key, `sign-binding` exits 1 with the
/// no-key refusal and draws none: a key it drew would be one no node started
/// with.
#[test]
fn sign_binding_refuses_storage_that_holds_no_node_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = tmp.path().join("node");
    let output = sign_binding(&storage);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("holds no node key"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "no signature on stdout");
    let second = sign_binding(&storage);
    assert_eq!(
        second.status.code(),
        Some(1),
        "the refused run drew no key for a later run to sign with"
    );
}

/// A malformed argument exits 2 and creates no storage.
#[test]
fn sign_binding_refuses_a_malformed_head_before_opening_storage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage = tmp.path().join("node");
    let output = Command::new(env!("CARGO_BIN_EXE_scp-node"))
        .arg("sign-binding")
        .args(["--operator", &Identifier::from_bytes(OPERATOR).to_string()])
        .args(["--url", URL])
        .args(["--key-state-head", "00"])
        .args(["--storage-path", storage.to_str().expect("utf-8 path")])
        .stdin(Stdio::null())
        .output()
        .expect("spawn scp-node sign-binding");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--key-state-head"));
    assert!(!storage.exists());
}

/// The modes that keep no node key across starts refuse a configured
/// binding, from either variable, before they start. `--ephemeral` compiles
/// only in a `testing` build; a shipped build refuses the mode itself.
#[test]
fn the_modes_without_a_node_key_refuse_a_configured_binding() {
    let mut modes = vec!["--relay-only"];
    if cfg!(feature = "testing") {
        modes.push("--ephemeral");
    }
    for mode in modes {
        for (name, value) in [("SCP_NODE_BINDING", "{}"), ("SCP_NODE_URL", URL)] {
            let output = Command::new(env!("CARGO_BIN_EXE_scp-node"))
                .arg(mode)
                .env(name, value)
                .env("SCP_RELAY_BIND_ADDR", "127.0.0.1:0")
                .env("SCP_NODE_BIND_ADDR", "127.0.0.1:0")
                .env("SCP_NODE_DOMAIN", "node.example.com")
                .env_remove(if name == "SCP_NODE_URL" {
                    "SCP_NODE_BINDING"
                } else {
                    "SCP_NODE_URL"
                })
                .stdin(Stdio::null())
                .output()
                .expect("spawn scp-node");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(1), "{mode} {name}: {stderr}");
            assert!(
                stderr.contains(&format!("{mode} keeps no node key")),
                "{mode} {name}: {stderr}"
            );
        }
    }
}
