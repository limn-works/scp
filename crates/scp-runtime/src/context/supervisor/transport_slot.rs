//! The `Supervisor`'s rebindable transport binding.
//!
//! A [`TransportSlot`] is the one `ContextTransportProvider` a `Supervisor`
//! holds. Every context actor and the `KeyPackage` store actor copy the slot's
//! `Arc` into their dependencies when they spawn, and every transport call the
//! slot receives reads the provider currently bound inside it through an
//! [`ArcSwap`] and forwards the call to that provider. A bridge that starts a
//! node calls [`TransportSlot::replace`] to bind the node's relay transport,
//! so running actors reach that relay on their next send without a respawn
//! (`construction.md` §"Node start — `NodeStartConfig`").
//!
//! `ArcSwap` is one of the read primitives ADR-049 Decision 12, the lock-free
//! read invariant, allows; a load takes no lock.
//!
//! A call that loaded a provider before a [`replace`](TransportSlot::replace)
//! finishes on that provider: the call holds the provider's `Arc`, so the
//! provider stays alive until the call returns.

use std::sync::Arc;

use arc_swap::ArcSwap;
use scp_protocol::context::{ContextError, ContextParams};

use crate::context::builder::{ContextCreationError, ContextTransportProvider};

/// The rebindable transport a `Supervisor` hands to every actor it spawns.
///
/// Built once, in `Supervisor::with_providers_and_journal`, around the
/// provider the caller passed. [`replace`](Self::replace) is the only writer.
pub struct TransportSlot {
    /// The provider every forwarded call reaches.
    current: ArcSwap<Arc<dyn ContextTransportProvider>>,
}

impl TransportSlot {
    /// Builds a slot bound to `initial`.
    #[must_use]
    pub fn new(initial: Arc<dyn ContextTransportProvider>) -> Self {
        Self {
            current: ArcSwap::from_pointee(initial),
        }
    }

    /// Binds `next` and returns the provider it displaced.
    ///
    /// A call already running on the displaced provider finishes there; every
    /// call that starts after this returns reaches `next`.
    pub fn replace(
        &self,
        next: Arc<dyn ContextTransportProvider>,
    ) -> Arc<dyn ContextTransportProvider> {
        Arc::clone(&*self.current.swap(Arc::new(next)))
    }

    /// Returns whether `provider` is the provider currently bound, compared by
    /// allocation address.
    #[must_use]
    pub fn holds(&self, provider: &Arc<dyn ContextTransportProvider>) -> bool {
        Arc::ptr_eq(&**self.current.load(), provider)
    }

    /// The provider currently bound. The caller's `Arc` keeps that provider
    /// alive for the whole call, across a concurrent [`replace`](Self::replace).
    fn bound(&self) -> Arc<dyn ContextTransportProvider> {
        Arc::clone(&**self.current.load())
    }
}

#[async_trait::async_trait]
impl ContextTransportProvider for TransportSlot {
    fn is_connected(&self) -> bool {
        self.current.load().is_connected()
    }

    async fn publish_context(
        &self,
        context_id: &[u8; 32],
        params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        self.bound().publish_context(context_id, params).await
    }

    async fn delete_published(&self, context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        self.bound().delete_published(context_id).await
    }

    async fn send_message(
        &self,
        context_id: &[u8; 32],
        encrypted_payload: &[u8],
        ttl: scp_protocol::envelope::outer::BlobTtl,
    ) -> Result<(), ContextError> {
        self.bound()
            .send_message(context_id, encrypted_payload, ttl)
            .await
    }

    async fn send_to_routing_id(
        &self,
        routing_id: &[u8; 32],
        payload: &[u8],
        ttl: u32,
    ) -> Result<(), ContextError> {
        self.bound()
            .send_to_routing_id(routing_id, payload, ttl)
            .await
    }

    async fn publish_key_package(
        &self,
        owner_did: &str,
        kp_bytes: &[u8],
    ) -> Result<(), ContextError> {
        self.bound().publish_key_package(owner_did, kp_bytes).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    /// Counts the sends it receives. When `gate` is set, a send counts
    /// itself, then waits for `gate` before it returns.
    #[derive(Default)]
    struct Recording {
        sends: AtomicUsize,
        gate: Option<Arc<Notify>>,
        entered: Arc<Notify>,
    }

    impl Recording {
        fn sends(&self) -> usize {
            self.sends.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl ContextTransportProvider for Recording {
        fn is_connected(&self) -> bool {
            true
        }
        async fn publish_context(
            &self,
            _context_id: &[u8; 32],
            _params: &ContextParams,
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn delete_published(
            &self,
            _context_id: &[u8; 32],
        ) -> Result<(), ContextCreationError> {
            Ok(())
        }
        async fn send_message(
            &self,
            _context_id: &[u8; 32],
            _encrypted_payload: &[u8],
            _ttl: scp_protocol::envelope::outer::BlobTtl,
        ) -> Result<(), ContextError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            if let Some(gate) = &self.gate {
                self.entered.notify_one();
                gate.notified().await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn replace_routes_later_sends_to_the_new_provider() {
        let a = Arc::new(Recording::default());
        let b = Arc::new(Recording::default());
        let a_dyn: Arc<dyn ContextTransportProvider> = a.clone();
        let b_dyn: Arc<dyn ContextTransportProvider> = b.clone();
        let slot = TransportSlot::new(Arc::clone(&a_dyn));
        slot.send_message(
            &[1; 32],
            b"x",
            scp_protocol::envelope::outer::BlobTtl::fresh(
                scp_protocol::envelope::outer::BlobClass::Message,
            ),
        )
        .await
        .unwrap();

        let displaced = slot.replace(Arc::clone(&b_dyn));
        assert!(
            Arc::ptr_eq(&displaced, &a_dyn),
            "replace returns the displaced provider"
        );
        slot.send_message(
            &[2; 32],
            b"x",
            scp_protocol::envelope::outer::BlobTtl::fresh(
                scp_protocol::envelope::outer::BlobClass::Message,
            ),
        )
        .await
        .unwrap();

        assert_eq!((a.sends(), b.sends()), (1, 1));
    }

    #[tokio::test]
    async fn a_send_in_flight_across_replace_finishes_on_the_provider_it_loaded() {
        let gate = Arc::new(Notify::new());
        let a = Arc::new(Recording {
            gate: Some(Arc::clone(&gate)),
            ..Recording::default()
        });
        let b = Arc::new(Recording::default());
        let slot = Arc::new(TransportSlot::new(a.clone()));
        let in_flight = tokio::spawn({
            let slot = Arc::clone(&slot);
            async move {
                slot.send_message(
                    &[7; 32],
                    b"x",
                    scp_protocol::envelope::outer::BlobTtl::fresh(
                        scp_protocol::envelope::outer::BlobClass::Message,
                    ),
                )
                .await
            }
        });
        a.entered.notified().await;

        slot.replace(b.clone());
        gate.notify_one();
        in_flight.await.unwrap().unwrap();

        assert_eq!(
            a.sends(),
            1,
            "a send that loaded the first provider finishes there"
        );
        assert_eq!(
            b.sends(),
            0,
            "the replacement sees no part of a send that started before it"
        );
    }

    #[test]
    fn holds_tracks_replace() {
        let a: Arc<dyn ContextTransportProvider> = Arc::new(Recording::default());
        let b: Arc<dyn ContextTransportProvider> = Arc::new(Recording::default());
        let slot = TransportSlot::new(Arc::clone(&a));
        assert!(slot.holds(&a) && !slot.holds(&b));
        slot.replace(Arc::clone(&b));
        assert!(slot.holds(&b) && !slot.holds(&a));
    }
}
