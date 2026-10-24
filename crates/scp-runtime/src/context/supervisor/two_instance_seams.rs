//! Two-instance receive seams for bridge tests (`testing` only).
//!
//! A bridge test that needs one SCP instance to receive exactly what another
//! sent captures the sender's context payloads ([`ContextSendCapture`]) and
//! delivers them to the receiver's actor itself
//! ([`Supervisor::test_deliver_incoming`]), the way a relay subscription
//! would, without a relay. Every bridge calls these, so the seams exist once.

use std::sync::{Arc, PoisonError, RwLock};

use scp_protocol::context::{ContextError, ContextParams};

use super::Supervisor;
use crate::context::actor::bounded_reply_await;
use crate::context::actor::commands::{MessagingCommand, QueriesCommand};
use crate::context::builder::{ContextCreationError, ContextTransportProvider};
use crate::context::messaging_helpers::DeliverOutcome;

/// The payloads a supervisor has sent to its contexts, oldest first.
///
/// Clones share one buffer; [`Self::transport`] is the transport that fills
/// it. The buffer is a `std::sync::RwLock` taken only through `write()` and
/// never held across an `.await` (`clippy.toml` bans `std::sync::Mutex` in this
/// crate).
#[derive(Clone, Default)]
pub struct ContextSendCapture(Arc<RwLock<Vec<Vec<u8>>>>);

impl ContextSendCapture {
    /// A context transport that records every payload sent into this capture
    /// and reports success for every other operation.
    #[must_use]
    pub fn transport(&self) -> Box<dyn ContextTransportProvider> {
        Box::new(CapturingTransport(self.clone()))
    }

    /// Every payload captured since the last call, oldest first; clears them.
    #[must_use]
    pub fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.0.write().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Records every payload a supervisor sends to a context.
struct CapturingTransport(ContextSendCapture);

#[async_trait::async_trait]
impl ContextTransportProvider for CapturingTransport {
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

    async fn delete_published(&self, _context_id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }

    async fn send_message(
        &self,
        _context_id: &[u8; 32],
        encrypted_payload: &[u8],
        _ttl: scp_protocol::envelope::outer::BlobTtl,
    ) -> Result<(), ContextError> {
        self.0
            .0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .push(encrypted_payload.to_vec());
        Ok(())
    }
}

impl Supervisor {
    /// Makes `member_did`, which joined `context_id` from a Welcome on this
    /// supervisor, a receiving member here: this supervisor treats the DID as
    /// local, and its actor holds the access key `inviter` minted for the
    /// member.
    ///
    /// No join path registers the joiner as a local DID yet, and the access
    /// key reaches a new member by the pull-based HPKE distribution of spec
    /// 09 §9.17.2 item 1 (§9.16.2), which no bridge runs yet; this stands in
    /// for both, as the full-stack harness does.
    ///
    /// # Errors
    ///
    /// - The errors of [`Self::test_install_access_key`].
    /// - [`ContextError::InvalidState`] if `inviter` holds no access key for
    ///   `member_did`.
    /// - [`ContextError::TransportFailed`] if `inviter`'s actor does not
    ///   answer.
    pub async fn test_admit_joined_member(
        &self,
        inviter: &Self,
        context_id: &str,
        member_did: &str,
    ) -> Result<(), ContextError> {
        self.register_local_did(scp_did::DID(member_did.to_owned()))
            .await;
        let (reply, rx) = tokio::sync::oneshot::channel();
        let query = QueriesCommand::GetAllAccessKeys {
            context_id: context_id.to_owned(),
            reply,
        };
        inviter.dispatch_query(query).await?;
        let keys = bounded_reply_await(rx).await.map_err(|e| {
            ContextError::TransportFailed(format!(
                "Supervisor::test_admit_joined_member — inviter's actor did not reply: {e:?}"
            ))
        })??;
        let key = keys.get(member_did).cloned().ok_or_else(|| {
            ContextError::InvalidState("the inviter holds no access key for this member".to_owned())
        })?;
        self.test_install_access_key(context_id, member_did, key)
            .await
    }

    /// How many commands wait in `context_id`'s actor mailbox behind the one
    /// it is processing, or `None` if no actor is registered for it. A test
    /// reads it to know that a caller's command has reached the mailbox and
    /// waits on the actor's current turn.
    #[must_use]
    pub fn test_queued_commands(&self, context_id: &str) -> Option<usize> {
        self.lookup(context_id)
            .map(|handle| handle.queued_commands())
    }

    /// Hands `envelope_bytes` to `context_id`'s actor through the production
    /// `MessagingCommand::DeliverIncoming`, the path a relay subscription
    /// takes, and awaits the actor's reply.
    ///
    /// The inner result is the actor's answer: a payload it refuses is an
    /// inner `Err`, not a failure of this call.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::dispatch_command`], and
    /// [`ContextError::TransportFailed`] if the actor does not reply.
    pub async fn test_deliver_incoming(
        &self,
        context_id: &str,
        envelope_bytes: Vec<u8>,
    ) -> Result<Result<DeliverOutcome, ContextError>, ContextError> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        let deliver = MessagingCommand::DeliverIncoming {
            context_id: context_id.to_owned(),
            envelope_bytes,
            mode: crate::context::actor::commands::DeliveryMode::Live,
            reply,
        };
        self.dispatch_command(context_id, deliver).await?;
        bounded_reply_await(rx).await.map_err(|e| {
            ContextError::TransportFailed(format!(
                "Supervisor::test_deliver_incoming — actor did not reply: {e:?}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_capturing_transport_records_sends_in_order_and_take_clears()
    -> Result<(), ContextError> {
        let capture = ContextSendCapture::default();
        let transport = capture.transport();
        assert!(transport.is_connected());
        transport
            .send_message(
                &[1; 32],
                b"first",
                scp_protocol::envelope::outer::BlobTtl::fresh(
                    scp_protocol::envelope::outer::BlobClass::Message,
                ),
            )
            .await?;
        transport
            .send_message(
                &[2; 32],
                b"second",
                scp_protocol::envelope::outer::BlobTtl::fresh(
                    scp_protocol::envelope::outer::BlobClass::Message,
                ),
            )
            .await?;
        assert_eq!(capture.take(), vec![b"first".to_vec(), b"second".to_vec()]);
        assert!(capture.take().is_empty(), "take clears the capture");
        Ok(())
    }
}
