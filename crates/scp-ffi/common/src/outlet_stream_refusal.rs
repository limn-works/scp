//! The bridge-side rendering of a §5.4.5 chunk-signature refusal, shared by the
//! three native FFI bridges (`PyO3`, napi-rs, `UniFFI`) so their wording and
//! their error code cannot drift.
//!
//! # What the runtime hands a bridge
//!
//! A streaming `poll_next` drains an
//! [`mpsc::Receiver<OutletStreamItem>`](scp_core::context::outlets::OutletStreamItem),
//! and `OutletStreamItem` is
//! `Result<OutletStreamChunk, ChunkSignatureRefused>`. The dispatch pump sends
//! `Err(ChunkSignatureRefused)` when the operator key refused a stream chunk AND
//! refused the terminal `Error` chunk the pump then attempted in order to report
//! that first refusal under a valid signature (§5.4.5 "Signature refusal", step
//! 2). The pump sends that item and returns, so a refusal is the last item the
//! channel yields and the receiver reads `None` after it.
//!
//! A bridge surfaces the refusal as its own typed error carrying
//! [`SIGNATURE_REFUSED_CODE`], never as the channel-closed sentinel. `None`
//! after a terminal chunk means the stream completed; a bridge that returned the
//! sentinel for both would leave a caller unable to tell a completed stream from
//! an operator that withheld output it refused to sign, which is the ambiguity
//! §5.4.5 step 2 requires the implementation to remove.
//!
//! # What the message states, and what it withholds
//!
//! [`signature_refused_message`] renders each of the two refusals through
//! `bounded_reason`, which returns `&'static str`. That return type is the
//! mechanism, not a convention: no byte of the operator's chunk payload, of the
//! signing preimage, or of a custody backend's error text can reach the string
//! this module builds.
//!
//! [`StreamSignerError::Custody`] already carries only a bounded
//! [`StreamSignerCustodyCategory`](scp_core::context::outlets::StreamSignerCustodyCategory),
//! whose `as_str` is a compile-time constant, so this module forwards it.
//! [`StreamSignerError::Jcs`] carries the canonicalizer's message, which the
//! canonicalizer derived from the executor's chunk payload, so this module drops
//! that message and names the failure kind instead. §5.4.5 forbids the terminal
//! `Error` chunk from carrying "text derived from the refused payload"; the
//! bridge error message reaches a caller's exception text and that caller's
//! logs, so this module applies the same rule to it. The operator keeps the
//! detail: the dispatch pump writes the full [`StreamSignerError`] `Display` —
//! the canonicalizer message included — through `tracing::error!` next to the
//! stream's `request_id`, on the node that ran the executor.

use scp_core::context::outlets::error_codes::CODE_EXECUTION_SIGNING_REFUSED;
use scp_core::context::outlets::{ChunkSignatureRefused, StreamSignerError};

/// The §5.4.4 code every bridge attaches to a surfaced signature refusal:
/// `SCP-OUTLET-6137`, class `Execution`, default slug
/// `execution.signing-refused`, default retry `WithBackoff` `1s..30s`.
pub const SIGNATURE_REFUSED_CODE: &str = CODE_EXECUTION_SIGNING_REFUSED;

/// Builds the human-readable half of the error a bridge raises for a
/// [`ChunkSignatureRefused`].
///
/// The caller pairs this message with [`SIGNATURE_REFUSED_CODE`] in that
/// bridge's own error type. The message names both signing attempts the operator
/// key refused and states that the stream carries no terminal chunk, so a reader
/// learns why the stream stopped without reading the chunk sequence.
#[must_use]
pub fn signature_refused_message(refusal: &ChunkSignatureRefused) -> String {
    format!(
        "the outlet operator's key refused this stream's chunk ({chunk}) and refused the \
         terminal error chunk that would have reported that refusal ({terminal}), so the pump \
         withheld the chunk and closed the stream with no terminal chunk (§5.4.5 \"Signature \
         refusal\")",
        chunk = bounded_reason(&refusal.refused_chunk),
        terminal = bounded_reason(&refusal.refused_terminal),
    )
}

/// Names the kind of a single signing refusal without quoting dynamic text.
///
/// The `&'static str` return type carries the guarantee: a variant that holds a
/// `String` cannot widen this function's output, so the string
/// [`signature_refused_message`] builds contains only text this crate and the
/// runtime's category table wrote at compile time.
const fn bounded_reason(err: &StreamSignerError) -> &'static str {
    match err {
        // `as_str` returns one compile-time constant per category. Carrying the
        // category rather than the backend's error string is what the category
        // type exists for (ADR-006 custody isolation / ADR-061 error-detail
        // sanitization), so forwarding it leaks nothing.
        StreamSignerError::Custody { category } => category.as_str(),
        // The canonicalizer built its message from the executor's chunk payload,
        // so the bridge names the failure and drops the text (module doc,
        // "What the message states, and what it withholds").
        StreamSignerError::Jcs(_) => "chunk payload canonicalization failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use scp_core::context::outlets::StreamSignerCustodyCategory;
    use scp_core::context::outlets::error_codes::{
        SLUG_EXECUTION_SIGNING_REFUSED, error_code_to_class, error_code_to_default_slug,
    };
    use scp_core::context::outlets::errors::OutletErrorClass;

    /// The constant the bridges attach resolves through the §5.4.4 registry to
    /// the Execution class and the `execution.signing-refused` slug.
    #[test]
    fn code_resolves_through_the_section_5_4_4_registry() {
        assert_eq!(
            error_code_to_class(SIGNATURE_REFUSED_CODE),
            Some(OutletErrorClass::Execution)
        );
        assert_eq!(
            error_code_to_default_slug(SIGNATURE_REFUSED_CODE),
            Some(SLUG_EXECUTION_SIGNING_REFUSED)
        );
    }

    /// A custody refusal renders its bounded category on both halves.
    #[test]
    fn custody_refusal_names_both_categories() {
        let message = signature_refused_message(&ChunkSignatureRefused {
            refused_chunk: StreamSignerError::Custody {
                category: StreamSignerCustodyCategory::KeyNotFound,
            },
            refused_terminal: StreamSignerError::Custody {
                category: StreamSignerCustodyCategory::BackendFault,
            },
        });
        assert!(
            message.contains(StreamSignerCustodyCategory::KeyNotFound.as_str()),
            "the refused chunk's category appears in the message: {message}"
        );
        assert!(
            message.contains(StreamSignerCustodyCategory::BackendFault.as_str()),
            "the refused terminal's category appears in the message: {message}"
        );
    }

    /// The canonicalizer's message describes the executor's payload, so the
    /// bridge message states the failure kind and drops the text.
    #[test]
    fn jcs_refusal_drops_the_canonicalizer_detail() {
        let secret = "outlet-payload-fragment-9f2c";
        let message = signature_refused_message(&ChunkSignatureRefused {
            refused_chunk: StreamSignerError::Jcs(format!("key must be a string: {secret}")),
            refused_terminal: StreamSignerError::Jcs(format!("key must be a string: {secret}")),
        });
        assert!(
            !message.contains(secret),
            "no payload-derived canonicalizer text reaches the bridge message: {message}"
        );
        assert!(
            message.contains("chunk payload canonicalization failed"),
            "the message still names the failure kind: {message}"
        );
    }

    /// A mixed refusal names each half by its own kind, so a reader can tell
    /// which attempt failed for which reason.
    #[test]
    fn mixed_refusal_names_each_half_separately() {
        let message = signature_refused_message(&ChunkSignatureRefused {
            refused_chunk: StreamSignerError::Jcs("non-finite float".to_owned()),
            refused_terminal: StreamSignerError::Custody {
                category: StreamSignerCustodyCategory::Unsupported,
            },
        });
        assert!(
            message.contains("chunk payload canonicalization failed"),
            "the chunk half names the canonicalization failure: {message}"
        );
        assert!(
            message.contains(StreamSignerCustodyCategory::Unsupported.as_str()),
            "the terminal half names the custody category: {message}"
        );
        assert!(
            !message.contains("non-finite float"),
            "the canonicalizer's text stays out of the message: {message}"
        );
    }
}
