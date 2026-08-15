//! A UCAN revoked before a restart must not validate after one — `PyO3` bridge.
//!
//! The bridge holds each context's `RevocationList` and `NonceTracker` in a
//! per-instance registry. Before the durable UCAN state landed, both were
//! rebuilt empty on every `PyBridgeInstance`, so a token revoked by one process
//! validated again in the next one. These tests drive the real `ucan_revoke`
//! entry point on one instance, drop it, build a second instance over the same
//! `SQLCipher` database, register the context through the real registration path,
//! and assert that the token the first instance revoked is still refused.
//!
//! Run with:
//! ```sh
//! DYLD_LIBRARY_PATH=$(python3.12 -c "import sysconfig; print(sysconfig.get_config_var('LIBDIR'))") \
//!   cargo test -p scp-ffi --test ucan_revocation_restart --features testing
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Once};

use _scp_core::runtime::{self, PyBridgeInstance, SqliteKeyMaterial, StorageConfig};
use _scp_core::scp::PyScp;
use zeroize::Zeroizing;

static INIT: Once = Once::new();

fn setup() {
    INIT.call_once(|| {
        pyo3::prepare_freethreaded_python();
        _scp_core::init_runtime().unwrap();
    });
}

/// A syntactically valid UCAN whose issuer is the context creator, so
/// `BridgeRevocationAuthorizer` authorizes the creator to revoke it.
const TEST_TOKEN: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuMTAuMCJ9.\
    eyJpc3MiOiJkaWQ6a2V5OnRlc3QiLCJhdWQiOiJkaWQ6a2V5OnRlc3QyIiwiZXhwIjo5OTk5OTk5OTk5LCJubmMiOiIxNjk5OTk5MDAwMDAwLWFhYmJjY2RkMTEyMjMzNDQiLCJhdHQiOltdLCJwcmYiOltdfQ.\
    dGVzdC1zaWduYXR1cmUtYnl0ZXMtMDAwMDAwMDAwMDAw";

const CREATOR_DID: &str = "did:key:test";

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

/// The contract: revoke on instance A, drop A, rebuild instance B over the same
/// database, and the revoked token is still revoked.
#[test]
fn revocation_survives_a_bridge_instance_restart() {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let context_id = format!("ctx-restart-{}", uuid::Uuid::new_v4());
    let token_cid = scp_core::crypto::ucan::revoke::compute_revocation_cid(TEST_TOKEN);

    // Instance A: register the context, then revoke through the real entry
    // point (`PyScp::ucan_revoke`), which runs the core revocation pipeline and
    // writes the durable record.
    {
        let bi_a = sqlite_instance(dir.path());
        runtime::register_ffi_state(&bi_a, &context_id, CREATOR_DID, &[]).unwrap();
        assert!(
            !checker_reports_revoked(&bi_a, &context_id, &token_cid),
            "a fresh context must start with nothing revoked"
        );

        let scp_a = PyScp::from_bridge_instance(Arc::clone(&bi_a));
        scp_a
            .ucan_revoke(&context_id, TEST_TOKEN, CREATOR_DID)
            .expect("the context creator may revoke a token it issued");
        assert!(
            checker_reports_revoked(&bi_a, &context_id, &token_cid),
            "the revoking instance must refuse the token immediately"
        );
        close_storage(&bi_a);
    }

    // Instance B: a different `PyBridgeInstance` over the same database, with
    // an empty registry. `register_ffi_state` rebuilds the revocation list from
    // the durable record before the instance can answer any validation.
    let bi_b = sqlite_instance(dir.path());
    runtime::register_ffi_state(&bi_b, &context_id, CREATOR_DID, &[]).unwrap();
    assert!(
        checker_reports_revoked(&bi_b, &context_id, &token_cid),
        "a token revoked before the restart must still be revoked after it"
    );
    close_storage(&bi_b);
}

/// A token nobody revoked stays valid across the same restart, so the durable
/// record carries the revocation rather than blanket-denying every token.
#[test]
fn an_unrevoked_token_stays_valid_across_a_restart() {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let context_id = format!("ctx-restart-clean-{}", uuid::Uuid::new_v4());
    let other_cid = scp_core::crypto::ucan::revoke::compute_revocation_cid("some-other-token");

    {
        let bi_a = sqlite_instance(dir.path());
        runtime::register_ffi_state(&bi_a, &context_id, CREATOR_DID, &[]).unwrap();
        let scp_a = PyScp::from_bridge_instance(Arc::clone(&bi_a));
        scp_a
            .ucan_revoke(&context_id, TEST_TOKEN, CREATOR_DID)
            .unwrap();
        close_storage(&bi_a);
    }

    let bi_b = sqlite_instance(dir.path());
    runtime::register_ffi_state(&bi_b, &context_id, CREATOR_DID, &[]).unwrap();
    assert!(
        !checker_reports_revoked(&bi_b, &context_id, &other_cid),
        "hydration must restore only the CIDs that were revoked"
    );
    close_storage(&bi_b);
}

/// One context's revocation must not leak into another context on the same
/// database, because each context keys its own durable record.
#[test]
fn revocation_does_not_cross_context_boundaries() {
    setup();
    let dir = tempfile::tempdir().unwrap();
    let revoked_ctx = format!("ctx-restart-a-{}", uuid::Uuid::new_v4());
    let clean_ctx = format!("ctx-restart-b-{}", uuid::Uuid::new_v4());
    let token_cid = scp_core::crypto::ucan::revoke::compute_revocation_cid(TEST_TOKEN);

    {
        let bi_a = sqlite_instance(dir.path());
        runtime::register_ffi_state(&bi_a, &revoked_ctx, CREATOR_DID, &[]).unwrap();
        runtime::register_ffi_state(&bi_a, &clean_ctx, CREATOR_DID, &[]).unwrap();
        let scp_a = PyScp::from_bridge_instance(Arc::clone(&bi_a));
        scp_a
            .ucan_revoke(&revoked_ctx, TEST_TOKEN, CREATOR_DID)
            .unwrap();
        close_storage(&bi_a);
    }

    let bi_b = sqlite_instance(dir.path());
    runtime::register_ffi_state(&bi_b, &revoked_ctx, CREATOR_DID, &[]).unwrap();
    runtime::register_ffi_state(&bi_b, &clean_ctx, CREATOR_DID, &[]).unwrap();
    assert!(
        checker_reports_revoked(&bi_b, &revoked_ctx, &token_cid),
        "the context whose creator revoked the token must refuse it after the restart"
    );
    assert!(
        !checker_reports_revoked(&bi_b, &clean_ctx, &token_cid),
        "a context that never revoked the token must still accept it after the restart"
    );
    close_storage(&bi_b);
}
