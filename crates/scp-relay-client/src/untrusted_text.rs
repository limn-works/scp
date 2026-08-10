//! Rendering an untrusted relay's own words safe to log, wrap in an error, or
//! surface through an SDK.
//!
//! Lives beside [`RelayMessage`](crate::RelayMessage) on purpose. `msg` on
//! `RelayMessage::Err` is a string an UNTRUSTED party wrote (relays are
//! untrusted -- see the encryption-as-access-control tenet), and every consumer
//! of that type needs the same treatment: the native adapters, the QUIC / UDP /
//! WebTransport / CoAP adapters, and the in-browser participant driver
//! (`scp-client`) alike. Putting the helper in `scp-transport` made it a
//! per-module convention that other transports in the same crate -- and the
//! browser client in another crate -- silently did not follow. This crate is the
//! wasm-safe leaf both sides already depend on, so it is the one place the rule
//! can be stated once.

/// The longest sanitized string any single relay message may contribute.
///
/// `MAX_MESSAGE_SIZE` bounds a relay frame at 1 MiB, so without a cap here one
/// rejection could put a megabyte of attacker-chosen text into an operator log
/// line or an SDK error string, repeatedly.
const MAX_LEN: usize = 512;

/// Renders relay-supplied text safe to put in a log line, a transport error, or
/// an SDK-visible message.
///
/// # Why a positive whitelist and not an escape-the-bad-ones denylist
///
/// The obvious spelling, `char::is_control()`, is Unicode general category `Cc`
/// ONLY. It does not cover U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR --
/// which a large fraction of log viewers and every ECMAScript-based log pipeline
/// treat as line terminators, so a hostile relay could still forge a whole log
/// line -- nor U+202E RIGHT-TO-LEFT OVERRIDE, which re-renders the surrounding
/// text (including the `relay_url` field naming WHICH relay is misbehaving) as
/// attacker-chosen output, inverting the very finding the log exists to deliver.
/// Chasing those categories one at a time is an unbounded denylist. Permitting
/// printable ASCII plus space and escaping everything else is closed by
/// construction: no future Unicode addition can widen it.
///
/// `\` is deliberately OUTSIDE the permitted set and is escaped to `\\`. It is
/// `is_ascii_graphic()`, so permitting it would let a relay send the two literal
/// characters `\` and `n` and produce output byte-identical to a real newline's
/// escape -- making a genuine control character indistinguishable from honest
/// text, and vice versa. Escaping it keeps the rendering unambiguous.
///
/// Escaped rather than stripped so the original stays legible, and truncated so
/// one rejection cannot flood the sink. The `…` marker is itself outside the
/// permitted set, so a relay cannot forge it: a literal `…` in the output
/// unambiguously means truncation.
#[must_use]
pub fn sanitize_relay_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_LEN));
    for c in text.chars() {
        if out.len() >= MAX_LEN {
            out.push('…');
            break;
        }
        if c == '\\' {
            out.push_str("\\\\");
        } else if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.extend(c.escape_default());
        }
    }
    out
}

/// The one way a relay's `RelayMessage::Err { code, msg }` becomes a Rust
/// string.
///
/// `code` is a `u16` and needs no escaping; `msg` is attacker-controlled free
/// text and goes through [`sanitize_relay_text`]. Every consumer of a relay
/// error -- in any transport, in any crate -- calls this rather than formatting
/// `msg` directly, so no transport can be more trusting than another.
#[must_use]
pub fn relay_error_text(code: u16, msg: &str) -> String {
    format!("relay error {code}: {}", sanitize_relay_text(msg))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// The line-forging characters that are NOT Unicode category `Cc`, so a
    /// `char::is_control()` filter lets every one of them through.
    #[test]
    fn non_cc_line_forging_characters_do_not_survive() {
        for (label, hostile) in [
            ("U+2028 LINE SEPARATOR", '\u{2028}'),
            ("U+2029 PARAGRAPH SEPARATOR", '\u{2029}'),
            ("U+202E RIGHT-TO-LEFT OVERRIDE", '\u{202E}'),
            ("U+2066 LEFT-TO-RIGHT ISOLATE", '\u{2066}'),
            ("U+200B ZERO WIDTH SPACE", '\u{200B}'),
            ("U+FEFF BYTE ORDER MARK", '\u{FEFF}'),
            ("U+0085 NEXT LINE", '\u{0085}'),
        ] {
            let sanitized = sanitize_relay_text(&format!("rejected{hostile}FORGED LINE"));
            assert!(
                !sanitized.contains(hostile),
                "{label} survived sanitization: {sanitized:?}"
            );
            assert!(
                sanitized.contains("FORGED LINE"),
                "{label}: the text stays legible, just inert: {sanitized:?}"
            );
        }
    }

    /// Classic ASCII control characters stay handled.
    #[test]
    fn ascii_control_characters_cannot_forge_a_log_line() {
        let forged = sanitize_relay_text(
            "rejected\n2026-08-10T00:00:00Z  WARN scp: all relays healthy\r\u{7}",
        );
        assert!(
            !forged.contains('\n') && !forged.contains('\r') && !forged.contains('\u{7}'),
            "control characters must not survive into a log line: {forged}"
        );
        assert!(
            forged.contains("all relays healthy"),
            "the original text stays legible, just inert: {forged}"
        );
    }

    /// The permitted set is a positive whitelist, so it is checked directly.
    #[test]
    fn permits_exactly_printable_ascii_and_space_except_backslash() {
        let printable: String = (0x20u8..=0x7Eu8)
            .map(char::from)
            .filter(|c| *c != '\\')
            .collect();
        assert_eq!(
            sanitize_relay_text(&printable),
            printable,
            "printable ASCII + space (minus backslash) must pass through unchanged"
        );
        for c in ['\u{0}', '\u{1F}', '\u{7F}', '\u{9F}', 'é', '→', '🙂'] {
            let out = sanitize_relay_text(&c.to_string());
            assert_ne!(out, c.to_string(), "{c:?} must be escaped, got {out:?}");
        }
    }

    /// A relay cannot make honest text look like it contained a control
    /// character, nor hide one behind a literal escape sequence.
    #[test]
    fn backslash_is_escaped_so_escapes_are_unambiguous() {
        assert_eq!(sanitize_relay_text("a\\nb"), "a\\\\nb");
        assert_eq!(sanitize_relay_text("a\nb"), "a\\nb");
        assert_ne!(
            sanitize_relay_text("a\\nb"),
            sanitize_relay_text("a\nb"),
            "a literal backslash-n must not render identically to a real newline"
        );
    }

    /// One rejection cannot flood a log or an SDK error string, and the bound
    /// holds even when every character takes the maximal escape expansion.
    #[test]
    fn output_is_bounded_even_for_maximal_escape_expansion() {
        let flood = sanitize_relay_text(&"x".repeat(10_000));
        assert!(
            flood.len() <= MAX_LEN + 16,
            "plain flood exceeded the bound: {} bytes",
            flood.len()
        );

        // `\u{10ffff}` is the longest `escape_default` expansion (10 bytes). The
        // length check sits at the top of the loop, so the worst case is
        // MAX_LEN-1 bytes plus one maximal escape plus the 3-byte marker.
        let worst = sanitize_relay_text(&"\u{10FFFF}".repeat(10_000));
        assert!(
            worst.len() <= MAX_LEN + 13,
            "maximal-escape flood exceeded the bound: {} bytes",
            worst.len()
        );
        assert!(worst.ends_with('…'), "truncation is marked: {worst:?}");
    }

    /// Sanitizing already-sanitized text is stable, so a defence-in-depth double
    /// call at two layers cannot mangle the message.
    #[test]
    fn sanitization_is_idempotent_for_permitted_text() {
        let once = sanitize_relay_text("relay error 4001: blob too large");
        assert_eq!(sanitize_relay_text(&once), once);
    }

    #[test]
    fn relay_error_text_sanitizes_the_message_and_keeps_the_code() {
        let rendered = relay_error_text(4001, "bad\nrequest");
        assert_eq!(rendered, "relay error 4001: bad\\nrequest");
    }
}
