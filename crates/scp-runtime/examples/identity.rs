//! Identity creation and DID document inspection.
//!
//! Demonstrates creating a new SCP identity using `did:dht`,
//! inspecting the resulting DID document, and publishing it
//! to the (in-memory) DHT.
//!
//! Usage:
//!   `cargo run -p scp-core --example identity`

use std::sync::Arc;

use scp_identity::DidMethod;
use scp_identity::cache::DidCache;
use scp_identity::dht::DidDht;
use scp_identity::dht_client::InMemoryDhtClient;
use scp_platform::testing::InMemoryKeyCustody;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Set up key custody — holds Ed25519 key material in memory.
    let custody = Arc::new(InMemoryKeyCustody::new());

    // 2. Wire the DID method with an in-memory DHT client and cache.
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let cache = Arc::new(DidCache::new());
    let sign_fn = DidDht::<InMemoryDhtClient>::make_sign_fn(Arc::clone(&custody));
    let did_dht = DidDht::with_client_and_signer(dht_client, cache, sign_fn);

    // 3. Create the identity — generates keys and builds the DID document.
    let (identity, document) = did_dht.create(&*custody).await?;

    println!("DID: {}", identity.did);
    println!("Identity key handle: {:?}", identity.identity_key);
    println!(
        "Active signing key handle: {:?}",
        identity.active_signing_key
    );
    println!();

    // 4. Inspect the DID document.
    println!("DID Document:");
    println!("  ID: {}", document.id);
    println!(
        "  Verification methods: {}",
        document.verification_method.len()
    );
    for vm in &document.verification_method {
        println!("    - {} (type: {:?})", vm.id, vm.method_type);
    }
    println!("  Services: {}", document.service.len());
    println!();

    // 5. Publish to the DHT.
    did_dht.publish(&identity, &document).await?;
    println!("Published to DHT successfully.");

    // 6. Resolve it back.
    let resolved = did_dht.resolve(&identity.did).await?;
    assert_eq!(resolved.id, document.id);
    println!("Resolved from DHT — document matches.");

    Ok(())
}
