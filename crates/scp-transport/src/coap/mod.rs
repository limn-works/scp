//! CoAP-over-DTLS transport adapter for `IoT` interoperability.
//!
//! This module implements the CoAP-based constrained device transport per spec
//! section 10.16.2. CoAP (RFC 7252) provides the framing layer over DTLS,
//! enabling integration with existing `IoT` infrastructure (CoAP proxies, `LwM2M`,
//! etc.).
//!
//! # Operation Mapping (section 10.16.2 point 1)
//!
//! SCP operations map to CoAP methods:
//!
//! | SCP operation | CoAP method | URI pattern |
//! |---------------|-------------|-------------|
//! | PUBLISH | `POST /scp/{hex(routing_id)}` | Blob as payload |
//! | QUERY | `GET /scp/{hex(routing_id)}?since=&limit=` | Query params |
//! | DELETE | `DELETE /scp/{hex(routing_id)}/{blob_id}` | Path segments |
//!
//! # CoAP Observe (section 10.16.2 point 2)
//!
//! RFC 7641 Observe provides lightweight best-effort subscription: the client
//! registers an observation on a resource and the server pushes new blobs as
//! notifications. This is best-effort -- the server MAY stop notifying at any
//! time, and the client must re-register.
//!
//! # Content Format
//!
//! All SCP blobs use `application/msgpack` (content-format 112) per the CoAP
//! content-format registry. This aligns with ADR-004's `MessagePack` wire format.
//!
//! # Authentication (section 10.16.2 point 5)
//!
//! CoAP endpoints are unauthenticated, consistent with the native relay model
//! (ADR-004): relays do not authenticate clients. DTLS provides transport-layer
//! encryption; participant identity is authenticated inside the MLS-encrypted
//! envelope (section 9.13).
//!
//! See ADR-037 in `.docs/adrs/phase-2.md` for the transport binding design.

pub mod adapter;
pub mod message;

pub use adapter::{CoapAdapter, DEFAULT_BLOCK_SZX, RECOMMENDED_MAX_BLOB_SIZE};
pub use message::{
    BlockOption, CoapContentFormat, CoapMethod, CoapRequestBuilder, CoapResponseParser,
    OBSERVE_OPTION, SCP_COAP_URI_PREFIX,
};
