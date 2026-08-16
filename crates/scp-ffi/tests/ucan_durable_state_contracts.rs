//! Contracts the durable UCAN state must hold under concurrency, under refusal,
//! and under a current-thread runtime — `PyO3` bridge.
//!
//! Each test here pins one review finding against the branch that made the UCAN
//! revocation list and nonce tracker durable:
//!
//! - Two revocations running at once must both survive a rebuild
//!   ([`concurrent_revocations_of_two_tokens_both_survive_a_restart`]).
//! - Registering a context that is already registered must leave the registered
//!   state untouched ([`re_registration_never_replaces_a_live_revocation`]).
//! - A validation the pipeline refuses must write no durable nonce record
//!   ([`a_refused_validation_writes_no_nonce_record`]).
//! - A caller inside a current-thread tokio runtime must reach durable storage
//!   rather than being refused
//!   ([`a_current_thread_caller_still_revokes_and_rebuilds`]).
//!
//! Run with:
//! ```sh
//! DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
//!   cargo test -p scp-ffi --test ucan_durable_state_contracts --features testing
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Barrier, Once};

use _scp_core::runtime::{self, PyBridgeInstance, SqliteKeyMaterial, StorageConfig};
use _scp_core::scp::PyScp;
use scp_platform::traits::Storage as _;
use zeroize::Zeroizing;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        pyo3::prepare_freethreaded_python();
        _scp_core::init_runtime().unwrap();
    });
}

const CREATOR_DID: &str = "did:key:test";

/// Rounds of two simultaneous revocations run by
/// [`concurrent_revocations_of_two_tokens_both_survive_a_restart`]. One round
/// can lose a token id only when the two writes interleave the wrong way, so the
/// test runs many rounds: a fix that narrows the window rather than removing it
/// loses at least one id across them.
const REVOCATION_RACE_ROUNDS: usize = 16;

/// A syntactically valid UCAN whose issuer is the context creator, so
/// `BridgeRevocationAuthorizer` authorizes the creator to revoke it. [`token`]
/// derives every other test token from this one by replacing only the signature
/// segment, so each derived token keeps this issuer and hashes to its own
/// revocation id.
const TOKEN_A: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9.\
    eyJpc3MiOiJkaWQ6a2V5OnRlc3QiLCJhdWQiOiJkaWQ6a2V5OnRlc3QyIiwiZXhwIjo5OTk5OTk5OTk5LCJubmMiOiIxNjk5OTk5MDAwMDAwLWFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOltdLCJwcmYiOltdfQ.\
    dGVzdC1zaWduYXR1cmUtYnl0ZXMtMDAwMDAwMDAwMDAw";

/// Builds the `index`-th distinct token by varying only the signature segment,
/// so every token parses to the same issuer and hashes to its own revocation id.
fn token(index: usize) -> String {
    let header_and_payload = TOKEN_A.rsplit_once('.').expect("the constant is a JWT").0;
    let signature = base64_url_no_pad(format!("test-signature-bytes-{index:012}").as_bytes());
    format!("{header_and_payload}.{signature}")
}

/// Encodes bytes as unpadded base64url, the encoding a JWT segment uses.
fn base64_url_no_pad(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Builds a `PyBridgeInstance` over the `SQLCipher` database in `dir`.
fn sqlite_instance(dir: &std::path::Path) -> Arc<PyBridgeInstance> {
    let key = SqliteKeyMaterial::Raw(Zeroizing::new(vec![0x5au8; 32]));
    Arc::new(
        PyBridgeInstance::with_storage_py(StorageConfig::Sqlite {
            path: dir.to_path_buf(),
            key,
        })
        .expect("opening the SQLCipher database must succeed"),
    )
}

/// Releases the `SQLCipher` advisory lock so the next instance can open the same
/// database, which is what `SCP.shutdown()` does at the SDK surface.
fn close_storage(bi: &PyBridgeInstance) {
    if let Some(provider) = bi.storage_provider() {
        provider.close();
    }
}

/// Reads the predicate that step 10 of the ADR-016 validation pipeline
/// consults, through the same `RevocationChecker` the pipeline builds.
fn checker_reports_revoked(bi: &PyBridgeInstance, context_id: &str, token_cid: &str) -> bool {
    use scp_core::crypto::ucan::validate::RevocationChecker as _;
    runtime::with_context(bi, context_id, |rt| {
        let checker = _scp_core::bridge_adapters::BridgeRevocationChecker {
            revocation_list: &rt.revocation_list,
        };
        Ok(checker.is_revoked(token_cid))
    })
    .unwrap()
}

/// Lists every durable key the context owns.
///
/// The prefix is the whole `context/{ctx}/` namespace rather than the nonce
/// prefix alone, so a regression that writes the nonce record under any other
/// name still shows up here.
fn durable_context_keys(bi: &PyBridgeInstance, context_id: &str) -> Vec<String> {
    let storage = bi
        .storage_provider()
        .expect("the instance selected storage");
    let prefix = format!("context/{context_id}/");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(storage.list_keys(&prefix)).unwrap()
}

/// D1 — two revocations that run at the same time must both reach the durable
/// record, and both must still be refused by the next bridge instance.
///
/// Each revocation writes only the token id it revoked, so neither write
/// carries a snapshot that could drop the other. A revocation path that read the
/// whole list, cloned it, released the lock, and wrote it back would drop
/// whichever id the later-landing write did not carry, which reinstates the
/// restart bypass as a race.
#[test]
fn concurrent_revocations_of_two_tokens_both_survive_a_restart() {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let context_id = format!("ctx-concurrent-{}", uuid::Uuid::new_v4());
    let tokens: Vec<String> = (0..REVOCATION_RACE_ROUNDS * 2).map(token).collect();
    let cids: Vec<String> = tokens
        .iter()
        .map(|t| scp_core::crypto::ucan::revoke::compute_revocation_cid(t))
        .collect();
    {
        let mut unique = cids.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            cids.len(),
            "every token must hash to its own id"
        );
    }

    {
        let bi_a = sqlite_instance(dir.path());
        runtime::register_ffi_state(&bi_a, &context_id, CREATOR_DID, &[]).unwrap();

        for round in 0..REVOCATION_RACE_ROUNDS {
            let barrier = Arc::new(Barrier::new(2));
            let mut handles = Vec::new();
            for token in [tokens[round * 2].clone(), tokens[round * 2 + 1].clone()] {
                let bi = Arc::clone(&bi_a);
                let ctx = context_id.clone();
                let barrier = Arc::clone(&barrier);
                handles.push(std::thread::spawn(move || {
                    let scp = PyScp::from_bridge_instance(bi);
                    barrier.wait();
                    scp.ucan_revoke(&ctx, &token, CREATOR_DID)
                }));
            }
            for handle in handles {
                handle
                    .join()
                    .expect("the revoking thread must not panic")
                    .expect("the context creator may revoke a token it issued");
            }
        }
        close_storage(&bi_a);
    }

    let bi_b = sqlite_instance(dir.path());
    runtime::register_ffi_state(&bi_b, &context_id, CREATOR_DID, &[]).unwrap();
    for (index, cid) in cids.iter().enumerate() {
        assert!(
            checker_reports_revoked(&bi_b, &context_id, cid),
            "revocation {index} must survive the restart"
        );
    }
    close_storage(&bi_b);
}

/// D2 — a second registration of a context that is already registered must
/// leave the registered state exactly as it is.
///
/// The registered state already refuses a revoked token. A registration path
/// that replaced the entry with freshly hydrated state would be safe only
/// because hydration reads the same record; a registration path that replaced
/// the entry with state built before another caller's revocation landed would
/// drop that revocation. The `PyO3` bridge answers by refusing the second
/// registration outright and touching nothing.
#[test]
fn re_registration_never_replaces_a_live_revocation() {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let context_id = format!("ctx-reregister-{}", uuid::Uuid::new_v4());
    let cid_a = scp_core::crypto::ucan::revoke::compute_revocation_cid(TOKEN_A);

    let bi = sqlite_instance(dir.path());
    runtime::register_ffi_state(&bi, &context_id, CREATOR_DID, &[]).unwrap();
    let scp = PyScp::from_bridge_instance(Arc::clone(&bi));
    scp.ucan_revoke(&context_id, TOKEN_A, CREATOR_DID).unwrap();

    let second = runtime::register_ffi_state(&bi, &context_id, CREATOR_DID, &[]);
    assert!(
        second.is_err(),
        "a second registration of a registered context must be refused"
    );
    assert!(
        checker_reports_revoked(&bi, &context_id, &cid_a),
        "the refused registration must leave the live revocation in place"
    );
    close_storage(&bi);
}

/// D3 — a validation the pipeline refuses must write no durable nonce record.
///
/// The refused token never reaches step 9, so nothing recorded a nonce and
/// nothing is written. Writing the whole nonce map after every pipeline run let
/// a caller holding no credential drive a full re-encode of a map capped at
/// 100 000 entries, once per rejected request.
#[test]
fn a_refused_validation_writes_no_nonce_record() {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let context_id = format!("ctx-refused-{}", uuid::Uuid::new_v4());

    let bi = sqlite_instance(dir.path());
    runtime::register_ffi_state(&bi, &context_id, CREATOR_DID, &[]).unwrap();
    assert!(
        durable_context_keys(&bi, &context_id).is_empty(),
        "a fresh context holds no durable record"
    );

    let scp = PyScp::from_bridge_instance(Arc::clone(&bi));
    let refused = scp.ucan_validate(
        &context_id,
        TOKEN_A,
        "outlet_call:anything",
        "did:key:test2",
        None,
    );
    assert!(
        refused.is_err(),
        "a token carrying an unverifiable signature must be refused"
    );
    assert_eq!(
        durable_context_keys(&bi, &context_id),
        Vec::<String>::new(),
        "a refused validation must write no durable key at all"
    );
    close_storage(&bi);
}

/// D4 — a caller inside a current-thread tokio runtime must reach durable
/// storage.
///
/// `block_in_place` panics inside a current-thread runtime and `Handle::block_on`
/// deadlocks there, so the storage bridge drives the future on a dedicated
/// thread instead. A bridge whose tokio runtime is current-thread hosts the MCP
/// server task, and refusing this regime denied every outlet invocation for a
/// reason unrelated to the token presented.
#[tokio::test]
async fn a_current_thread_caller_still_revokes_and_rebuilds() {
    setup();
    assert_eq!(
        tokio::runtime::Handle::current().runtime_flavor(),
        tokio::runtime::RuntimeFlavor::CurrentThread,
        "this test must run on a current-thread runtime to exercise the regime"
    );

    let dir = tempfile::tempdir().unwrap();
    let context_id = format!("ctx-current-thread-{}", uuid::Uuid::new_v4());
    let cid_a = scp_core::crypto::ucan::revoke::compute_revocation_cid(TOKEN_A);

    {
        let bi_a = sqlite_instance(dir.path());
        // Registration hydrates the durable record, so this call alone crosses
        // the sync-to-async boundary from inside the current-thread runtime.
        runtime::register_ffi_state(&bi_a, &context_id, CREATOR_DID, &[])
            .expect("registration must reach storage from a current-thread runtime");
        let scp = PyScp::from_bridge_instance(Arc::clone(&bi_a));
        scp.ucan_revoke(&context_id, TOKEN_A, CREATOR_DID)
            .expect("revocation must reach storage from a current-thread runtime");
        close_storage(&bi_a);
    }

    let bi_b = sqlite_instance(dir.path());
    runtime::register_ffi_state(&bi_b, &context_id, CREATOR_DID, &[]).unwrap();
    assert!(
        checker_reports_revoked(&bi_b, &context_id, &cid_a),
        "the revocation a current-thread caller made must survive the restart"
    );
    close_storage(&bi_b);
}

/// D5 — two registrations that run at the same time on one instance must both
/// complete.
///
/// Each registration builds its state, including the durable read, before it
/// takes the registry's shard write guard, so neither one holds that guard
/// across storage I/O while the other waits for it.
#[test]
fn concurrent_registrations_of_two_contexts_both_complete() {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let bi = sqlite_instance(dir.path());
    let barrier = Arc::new(Barrier::new(2));

    let mut handles = Vec::new();
    let mut ids = Vec::new();
    for _ in 0..2 {
        let context_id = format!("ctx-parallel-{}", uuid::Uuid::new_v4());
        ids.push(context_id.clone());
        let bi = Arc::clone(&bi);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            runtime::register_ffi_state(&bi, &context_id, CREATOR_DID, &[])
        }));
    }
    for handle in handles {
        handle
            .join()
            .expect("the registering thread must not panic")
            .expect("both registrations must succeed");
    }
    for context_id in &ids {
        assert!(
            !checker_reports_revoked(&bi, context_id, "cid-never-revoked"),
            "each registered context must answer through its own state"
        );
    }
    close_storage(&bi);
}
