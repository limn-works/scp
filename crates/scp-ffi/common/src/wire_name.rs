//! One wire name per fieldless protocol enum that a bridge sends to an SDK.
//!
//! Each function matches every variant with no wildcard arm, so a variant
//! added in `scp-protocol` stops this crate from compiling until someone names
//! it. A bridge never renders these values with `format!("{x:?}")`: `Debug`
//! output is a diagnostic format that a derive change, a payload, or a
//! redacting impl can alter with no compile error.
//!
//! Each name equals its Rust variant name, which is what every bridge sent
//! before these functions existed, so no SDK parser changes.

use scp_protocol::context::params::MemoryScope;
use scp_protocol::envelope::inner::MessageType;
use scp_protocol::provenance::SourceType;

/// Returns a caller-facing wire name for an inner-envelope `MessageType`.
///
/// `send_signaling` returns this name as `message_type`; TypeScript's
/// `SendSignalingResult.messageType` and Python's media helpers document it as
/// `"Signaling"`.
#[must_use]
pub const fn message_type_name(message_type: MessageType) -> &'static str {
    match message_type {
        MessageType::Content => "Content",
        MessageType::Signaling => "Signaling",
        MessageType::KeyDistribution => "KeyDistribution",
        MessageType::Recovery => "Recovery",
        MessageType::ConsistencyCheckpoint => "ConsistencyCheckpoint",
        MessageType::Heartbeat => "Heartbeat",
    }
}

/// Returns a caller-facing wire name for a provenance `SourceType`.
///
/// TypeScript's `parseProvenance` stores this string as `sourceType`.
#[must_use]
pub const fn source_type_name(source_type: SourceType) -> &'static str {
    match source_type {
        SourceType::Persistent => "Persistent",
        SourceType::Ephemeral => "Ephemeral",
        SourceType::Summary => "Summary",
    }
}

/// Returns a caller-facing wire name for a context `MemoryScope`.
///
/// TypeScript's `parseProvenance` stores this string as `memoryScope`.
#[must_use]
pub const fn memory_scope_name(memory_scope: MemoryScope) -> &'static str {
    match memory_scope {
        MemoryScope::Ephemeral => "Ephemeral",
        MemoryScope::Summary => "Summary",
        MemoryScope::Full => "Full",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins every `MessageType` name. `Debug` and these names agree today;
    /// a derive change or custom `Debug` impl would split them, and this test
    /// keeps a wire name fixed when that happens.
    #[test]
    fn message_type_names_are_pinned() {
        let rows = [
            (MessageType::Content, "Content"),
            (MessageType::Signaling, "Signaling"),
            (MessageType::KeyDistribution, "KeyDistribution"),
            (MessageType::Recovery, "Recovery"),
            (MessageType::ConsistencyCheckpoint, "ConsistencyCheckpoint"),
            (MessageType::Heartbeat, "Heartbeat"),
        ];
        for (value, name) in rows {
            assert_eq!(message_type_name(value), name);
        }
    }

    #[test]
    fn source_type_names_are_pinned() {
        assert_eq!(source_type_name(SourceType::Persistent), "Persistent");
        assert_eq!(source_type_name(SourceType::Ephemeral), "Ephemeral");
        assert_eq!(source_type_name(SourceType::Summary), "Summary");
    }

    #[test]
    fn memory_scope_names_are_pinned() {
        assert_eq!(memory_scope_name(MemoryScope::Ephemeral), "Ephemeral");
        assert_eq!(memory_scope_name(MemoryScope::Summary), "Summary");
        assert_eq!(memory_scope_name(MemoryScope::Full), "Full");
    }
}
