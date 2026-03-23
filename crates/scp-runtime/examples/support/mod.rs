//! Shared mock providers for scp-runtime examples.
//!
//! These are minimal no-op implementations of the three provider traits
//! required by `ContextManager`. For real usage, see:
//! - `scp-runtime::crypto::mls::provider` for production MLS crypto
//! - `scp-transport` for production relay transport
//! - `scp-event-log` for production Merkle event log

#![allow(dead_code)]

use scp_protocol::context::builder::{ContextCreationError, ContextCryptoProvider};
use scp_protocol::context::{ContextError, ContextParams};
use scp_runtime::context::builder::{ContextEventLogProvider, ContextTransportProvider};

/// Mock crypto provider — all operations succeed with dummy data.
pub struct MockCrypto;

impl ContextCryptoProvider for MockCrypto {
    fn validate_creator_identity(&self) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn create_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn generate_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn init_broadcast_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_mls_group(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_sender_key(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn validate_key_package(
        &self,
        _owner_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<(), ContextError> {
        Ok(())
    }
    fn encrypt_message(
        &self,
        _id: &[u8; 32],
        _sender_did: &str,
        payload: &[u8],
        _epoch: u64,
        _sequence: u64,
    ) -> Result<Vec<u8>, ContextError> {
        // Return payload as-is (no real encryption in mock).
        Ok(payload.to_vec())
    }
    fn add_member(
        &self,
        _id: &[u8; 32],
        _member_did: &str,
        _key_package_bytes: Option<&[u8]>,
    ) -> Result<scp_protocol::context::builder::AddMemberOutput, ContextError> {
        Ok(scp_protocol::context::builder::AddMemberOutput::default())
    }
    fn remove_member(&self, _id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> {
        Ok(())
    }
    fn distribute_sender_key(&self, _id: &[u8; 32], _member_did: &str) -> Result<(), ContextError> {
        Ok(())
    }
    fn remove_member_sender_key(
        &self,
        _id: &[u8; 32],
        _member_did: &str,
    ) -> Result<(), ContextError> {
        Ok(())
    }
}

/// Mock transport provider — reports connected, all sends succeed silently.
pub struct MockTransport;

impl ContextTransportProvider for MockTransport {
    fn is_connected(&self) -> bool {
        true
    }
    fn publish_context(
        &self,
        _id: &[u8; 32],
        _params: &ContextParams,
    ) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn delete_published(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn send_message(&self, _id: &[u8; 32], _encrypted_payload: &[u8]) -> Result<(), ContextError> {
        Ok(())
    }
}

/// Mock event log provider — all operations succeed with no persistence.
pub struct MockEventLog;

impl ContextEventLogProvider for MockEventLog {
    fn init_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn append_event(&self, _id: &[u8; 32], _event: &str) -> Result<(), ContextCreationError> {
        Ok(())
    }
    fn destroy_event_log(&self, _id: &[u8; 32]) -> Result<(), ContextCreationError> {
        Ok(())
    }
}
