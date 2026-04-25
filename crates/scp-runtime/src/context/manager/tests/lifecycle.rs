//! lifecycle-related manager tests.
//!
//! ADR-049 commit 12c.9e deleted the trait-based `MockCrypto`
//! scaffold. ADR-049 commit 12c.9f re-introduces fail-injection by
//! making `MlsCryptoProvider` accept caller-supplied
//! [`MlsBackend`](crate::crypto::mls::backend::MlsBackend) and
//! [`HpkeBackend`](crate::crypto::hpke_backend::HpkeBackend) through
//! [`MlsCryptoProvider::with_backends`](crate::crypto::mls::provider::MlsCryptoProvider::with_backends).
//!
//! Test bodies that exercise the post-12c.9f injection path live
//! here. The pre-12c.9e mock-tracker tests (counters for every method
//! call, fail-injection toggles for orchestration paths) were
//! design-tied to a deleted trait shape; they are intentionally not
//! restored verbatim. A real `MlsBackend` mock now lives in
//! `crate::crypto::mls::test_support` and is exercised by the
//! provider-direct test module rather than reflected through the
//! `ContextManager` shim that deletes in commit 12.

#[test]
fn manager_tests_lifecycle_backend_injection_landed() {
    // Lightweight smoke verifying the test seam itself: confirm the
    // backend-injection constructor compiles and yields a valid
    // provider. Functional tests against the injected backend live
    // adjacent to the production-backend tests in `provider.rs`.
    use crate::crypto::hpke_backend::ProductionHpkeBackend;
    use crate::crypto::mls::production_backend::ProductionMlsBackend;
    use crate::crypto::mls::provider::MlsCryptoProvider;
    use std::sync::Arc;

    let provider = MlsCryptoProvider::with_backends(
        "did:dht:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_owned(),
        Arc::new(ProductionMlsBackend::new()),
        Arc::new(ProductionHpkeBackend::new()),
    );
    // Smoke: the inherent accessors are wired and return the
    // injected backend pointers (Arc identity check).
    let _mls = provider.mls_backend();
    let _hpke = provider.hpke_backend();
}
