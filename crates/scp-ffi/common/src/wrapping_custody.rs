//! The supervisor's wrapping custody source for a bridge instance (spec 09
//! §9.16.1): an identity's wrapping key lives in the custody registered for
//! that identity.
//!
//! Each bridge keeps its identity registry in its own entry type, so
//! [`registry_wrapping_custody_source`] takes the registry and a projection to
//! the entry's custody. The production source answers only registered
//! identities. Under `testing`, [`with_unregistered_test_custody`] wraps it
//! for fixtures that create contexts for DIDs they never registered; the
//! production source carries no test branch.

use std::sync::Arc;

use dashmap::DashMap;
use scp_core::context::supervisor::{ErasedCustody, WrappingCustody, WrappingCustodySource};
use scp_did::DID;
use scp_platform::traits::KeyCustody;

/// The wrapping custody source over a bridge's identity registry.
///
/// It reads `registry` through a `Weak`, so the supervisor does not keep the
/// registry alive, and answers `None` for an identity that is not registered
/// (or once the registry is gone), which fails the actor build closed with
/// `WrappingKeyCustodyUnavailable`.
#[must_use]
pub fn registry_wrapping_custody_source<E, C>(
    registry: &Arc<DashMap<String, E>>,
    custody_of: fn(&E) -> &Arc<C>,
) -> WrappingCustodySource
where
    E: Send + Sync + 'static,
    C: KeyCustody + 'static,
{
    let registry = Arc::downgrade(registry);
    Arc::new(move |owner: &DID| {
        let registry = registry.upgrade()?;
        // One statement, so the registry's shard guard drops at its end.
        let custody = Arc::clone(custody_of(registry.get(owner.0.as_str())?.value()));
        let custody: Arc<dyn WrappingCustody> = Arc::new(ErasedCustody(custody));
        Some(custody)
    })
}

/// Test seam: `source`, except that an identity it does not answer gets the
/// custody in `slot` once a fixture has set it.
///
/// A registered identity still resolves to its own custody. The slot is read
/// through a `Weak`, like the registry.
#[cfg(feature = "testing")]
#[must_use]
pub fn with_unregistered_test_custody<C: KeyCustody + 'static>(
    source: WrappingCustodySource,
    slot: &Arc<std::sync::OnceLock<Arc<C>>>,
) -> WrappingCustodySource {
    let slot = Arc::downgrade(slot);
    Arc::new(move |owner: &DID| {
        if let Some(custody) = source(owner) {
            return Some(custody);
        }
        let test_custody = slot.upgrade().and_then(|slot| slot.get().cloned())?;
        let custody: Arc<dyn WrappingCustody> = Arc::new(ErasedCustody(test_custody));
        Some(custody)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use scp_platform::testing::InMemoryKeyCustody;

    struct Entry {
        custody: Arc<InMemoryKeyCustody>,
    }

    const fn custody_of(entry: &Entry) -> &Arc<InMemoryKeyCustody> {
        &entry.custody
    }

    fn did(s: &str) -> DID {
        DID(s.to_owned())
    }

    /// Generates a key through `served` and reports whether `owner_custody`
    /// holds it, which tells which custody the source handed out.
    async fn served_by(
        served: &Arc<dyn WrappingCustody>,
        owner_custody: &InMemoryKeyCustody,
    ) -> Result<bool, scp_platform::PlatformError> {
        let handle = served.generate_hpke_p256().await?;
        Ok(owner_custody.public_key(&handle).await.is_ok())
    }

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn a_registered_identity_gets_its_own_custody_and_others_get_none() -> TestResult {
        let registry: Arc<DashMap<String, Entry>> = Arc::new(DashMap::new());
        let alice_custody = Arc::new(InMemoryKeyCustody::new());
        registry.insert(
            "did:alice".to_owned(),
            Entry {
                custody: Arc::clone(&alice_custody),
            },
        );
        let source = registry_wrapping_custody_source(&registry, custody_of);

        let served = source(&did("did:alice")).ok_or("alice is registered")?;
        assert!(served_by(&served, &alice_custody).await?);
        assert!(source(&did("did:bob")).is_none());

        drop(registry);
        assert!(
            source(&did("did:alice")).is_none(),
            "the source must not keep the registry alive"
        );
        Ok(())
    }

    #[cfg(feature = "testing")]
    #[tokio::test]
    async fn the_test_custody_answers_only_unregistered_identities_once_set() -> TestResult {
        let registry: Arc<DashMap<String, Entry>> = Arc::new(DashMap::new());
        let alice_custody = Arc::new(InMemoryKeyCustody::new());
        registry.insert(
            "did:alice".to_owned(),
            Entry {
                custody: Arc::clone(&alice_custody),
            },
        );
        let slot: Arc<std::sync::OnceLock<Arc<InMemoryKeyCustody>>> = Arc::default();
        let source = with_unregistered_test_custody(
            registry_wrapping_custody_source(&registry, custody_of),
            &slot,
        );

        assert!(
            source(&did("did:bob")).is_none(),
            "an unset slot serves nobody"
        );

        let test_custody = Arc::clone(slot.get_or_init(|| Arc::new(InMemoryKeyCustody::new())));
        let bob = source(&did("did:bob")).ok_or("the set slot serves bob")?;
        assert!(served_by(&bob, &test_custody).await?);
        let alice = source(&did("did:alice")).ok_or("alice is registered")?;
        assert!(served_by(&alice, &alice_custody).await?);
        assert!(!served_by(&alice, &test_custody).await?);
        Ok(())
    }
}
