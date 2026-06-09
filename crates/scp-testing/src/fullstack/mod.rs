//! Full-stack end-to-end testing infrastructure.
//!
//! Bridges the gap between:
//! - **Crypto+Transport** tests (`encrypted_relay_roundtrip.rs`): real MLS + sender keys + relay, but bypasses `ContextManager`
//! - **Application** tests (`e2e_context_manager.rs`): real `ContextManager`, but mock crypto/transport
//!
//! This module provides [`E2eCryptoProvider`] (real MLS through `ContextManager`) and
//! [`FullStackNetwork`] (multi-node test harness with shared relay and key exchange).
//!
//! # Architecture
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────┐
//! │                    FullStackNetwork                        │
//! │                                                           │
//! │  ┌─────────────┐  Arc<Mutex<InMemoryRelay>>  ┌──────────┐│
//! │  │  Alice Node  │◄──────────────────────────►│ Bob Node  ││
//! │  │              │                             │           ││
//! │  │CtxManager    │  Arc<Mutex<KeyExchange>>   │CtxManager ││
//! │  │ ├─E2eCrypto──│◄──────────────────────────►│──E2eCrypto││
//! │  │ │ Provider   │  (Welcome, sender keys)    │  Provider ││
//! │  │ ├─Relay      │                             │ ├─Relay   ││
//! │  │ │ Transport  │                             │ │Transport││
//! │  │ └─Merkle     │                             │ └─Merkle  ││
//! │  │   EventLog   │                             │   EventLog││
//! │  └─────────────┘                             └──────────┘│
//! └───────────────────────────────────────────────────────────┘
//! ```

mod crypto;
mod exchange;
mod network;
mod node;

pub use crypto::E2eCryptoProvider;
pub use exchange::KeyExchange;
pub use network::FullStackNetwork;
pub use node::FullStackNode;
