//! Structured broadcast content types for broadcast content delivery (SCP-287).
//!
//! Defines [`BroadcastContent`] as the canonical inner payload format for
//! broadcast messages — replacing opaque `Vec<u8>` with a versioned, structured
//! format. The outer [`BroadcastEnvelope`] is unchanged; relays see the same
//! opaque AES-256-GCM ciphertext blob they always have.
//!
//! # Wire Format
//!
//! ```text
//! BROADCAST_CONTENT_MAGIC (3 bytes: "SCP")
//! ++ version_u8 (1 byte)
//! ++ rmp_serde::to_vec(&BroadcastContent) (variable)
//! ```
//!
//! Then AES-256-GCM encrypted into `BroadcastEnvelope.encrypted_content`.
//!
//! # Version Detection
//!
//! After decryption, check first 3 bytes for [`BROADCAST_CONTENT_MAGIC`].
//! If matched, read 4th byte as version. If `version >= 1`, deserialize
//! remaining bytes as `MessagePack` [`BroadcastContent`]. Otherwise, return
//! error (caller falls back to legacy raw bytes). Zero false-positive rate —
//! legacy encrypted payloads will not start with "SCP" unless deliberately
//! crafted.
//!
//! See spec §18.11.9, ADR-042.
//!
//! [`BroadcastEnvelope`]: crate::crypto::sender_keys::BroadcastEnvelope

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic byte prefix for structured broadcast content: ASCII "SCP".
///
/// Inside AES-256-GCM ciphertext — relay never sees this. Used for version
/// detection after decryption. Zero false-positive rate for legacy payloads.
pub const BROADCAST_CONTENT_MAGIC: [u8; 3] = [0x53, 0x43, 0x50];

/// Current broadcast content format version.
pub const BROADCAST_CONTENT_VERSION: u8 = 1;

/// Maximum path length in bytes.
const MAX_PATH_BYTES: usize = 1024;

/// Maximum deploy ID length in bytes.
const MAX_DEPLOY_ID_BYTES: usize = 128;

/// Maximum body size in bytes (10 MiB).
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

// ---------------------------------------------------------------------------
// BroadcastContentError
// ---------------------------------------------------------------------------

/// Errors produced by broadcast content serialization, deserialization, and
/// validation.
#[derive(Debug, thiserror::Error)]
pub enum BroadcastContentError {
    /// Decrypted payload does not start with [`BROADCAST_CONTENT_MAGIC`].
    #[error("invalid broadcast content magic prefix")]
    InvalidMagic,

    /// Content format version is not supported by this implementation.
    #[error("unsupported broadcast content version: {0}")]
    UnsupportedVersion(u8),

    /// `MessagePack` deserialization of `BroadcastContent` failed.
    #[error("broadcast content deserialization failed: {0}")]
    DeserializationFailed(String),

    /// A [`ContentPath`] value failed validation.
    #[error("invalid content path: {0}")]
    InvalidContentPath(String),

    /// A [`MimeType`] value failed validation.
    #[error("invalid MIME type: {0}")]
    InvalidMimeType(String),

    /// A `deploy_id` value failed validation.
    #[error("invalid deploy ID: {0}")]
    InvalidDeployId(String),

    /// Body exceeds [`MAX_BODY_BYTES`].
    #[error("body too large: {0} bytes (max {MAX_BODY_BYTES})")]
    BodyTooLarge(usize),

    /// An `ETag` value has an invalid format (must be 64 lowercase hex chars).
    #[error("invalid etag format: {0}")]
    InvalidEtag(String),

    /// `ETag` verification failed: computed hash does not match declared `ETag`.
    #[error("etag mismatch: expected {expected}, actual {actual}")]
    EtagMismatch {
        /// The `ETag` declared in `ContentMetadata`.
        expected: String,
        /// The `ETag` computed from the body.
        actual: String,
    },
}

// ---------------------------------------------------------------------------
// ContentPath
// ---------------------------------------------------------------------------

/// Validated URL path newtype (§18.11.9).
///
/// Rejects: `..` segments, `.` segments (but `.hidden` ok), `//`, `\`, null
/// bytes, control chars (U+0000-U+001F, U+007F), non-ASCII whitespace
/// (U+00A0, U+2000-U+200F, U+FEFF), any `%`-encoded byte, query strings
/// (`?`), fragments (`#`). Enforces: leading `/`, max 1024 bytes, no trailing
/// slash (except root `/`). Case-sensitive. Backslashes rejected (not silently
/// normalized). NFC normalization applied on construction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ContentPath(String);

impl ContentPath {
    /// Creates a new validated `ContentPath`.
    ///
    /// Applies NFC normalization before validation.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastContentError::InvalidContentPath`] if validation
    /// fails.
    pub fn new(path: impl Into<String>) -> Result<Self, BroadcastContentError> {
        let raw: String = path.into();
        // NFC normalize first.
        let normalized: String = raw.nfc().collect();
        validate_content_path(&normalized)?;
        Ok(Self(normalized))
    }

    /// Returns the inner path string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<ContentPath> for String {
    fn from(p: ContentPath) -> Self {
        p.0
    }
}

impl TryFrom<String> for ContentPath {
    type Error = BroadcastContentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ContentPath {
    type Error = BroadcastContentError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl std::fmt::Display for ContentPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ContentPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// MimeType
// ---------------------------------------------------------------------------

/// Validated MIME type newtype (§18.11.9).
///
/// Must match `type/subtype` grammar per RFC 7231 §3.1.1.1. Rejects CRLF and
/// control characters (prevents HTTP response splitting). No parameters
/// allowed (rejects `;`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MimeType(String);

impl MimeType {
    /// Creates a new validated `MimeType`.
    ///
    /// # Errors
    ///
    /// Returns [`BroadcastContentError::InvalidMimeType`] if validation fails.
    pub fn new(value: impl Into<String>) -> Result<Self, BroadcastContentError> {
        let raw: String = value.into();
        validate_mime_type(&raw)?;
        Ok(Self(raw))
    }

    /// Returns the inner MIME type string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<MimeType> for String {
    fn from(m: MimeType) -> Self {
        m.0
    }
}

impl TryFrom<String> for MimeType {
    type Error = BroadcastContentError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for MimeType {
    type Error = BroadcastContentError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl std::fmt::Display for MimeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for MimeType {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// ContentMetadata
// ---------------------------------------------------------------------------

/// Metadata attached to a broadcast content payload (§18.11.9).
///
/// All fields are optional. A bare `BroadcastContent` with only a body and no
/// metadata is valid (equivalent to legacy opaque bytes with structured
/// framing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentMetadata {
    /// Validated URL path for path-based projection routing.
    pub path: Option<ContentPath>,
    /// Validated MIME type for `Content-Type` header.
    pub content_type: Option<MimeType>,
    /// Groups assets into atomic deploys. 1-128 bytes, ASCII alphanumeric
    /// plus `-` and `_`.
    pub deploy_id: Option<String>,
    /// SHA-256(body) hex-encoded. Used for cache validation (`ETag` header).
    pub etag: Option<String>,
    /// When true, the asset is content-hashed and can be served with
    /// `Cache-Control: public, immutable, max-age=31536000`.
    #[serde(default)]
    pub immutable: bool,
}

// ---------------------------------------------------------------------------
// BroadcastContent
// ---------------------------------------------------------------------------

/// Canonical inner payload of a broadcast message (§18.11.9).
///
/// Wire format: `BROADCAST_CONTENT_MAGIC ++ version_u8 ++ rmp_serde::to_vec(self)`.
/// Then AES-256-GCM encrypted into `BroadcastEnvelope.encrypted_content`.
///
/// The `version` field is the inner content format version (independent of the
/// outer `BroadcastEnvelope.version` protocol wire format version).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BroadcastContent {
    /// Inner content format version (currently 1). Independent lifecycle from
    /// the outer `BroadcastEnvelope.version` (protocol wire format).
    pub version: u8,
    /// Content metadata: path, MIME type, deploy ID, `ETag`, immutability.
    pub metadata: ContentMetadata,
    /// Raw content bytes (the actual file/page content).
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

// ---------------------------------------------------------------------------
// deploy_id validation
// ---------------------------------------------------------------------------

/// Validates a `deploy_id` string: 1-128 bytes, ASCII alphanumeric plus `-`
/// and `_`. Empty strings rejected.
///
/// # Errors
///
/// Returns [`BroadcastContentError::InvalidDeployId`] when the value is
/// empty, exceeds 128 bytes, or contains characters outside the allowed set.
pub fn validate_deploy_id(deploy_id: &str) -> Result<(), BroadcastContentError> {
    if deploy_id.is_empty() {
        return Err(BroadcastContentError::InvalidDeployId(
            "deploy_id must not be empty".to_owned(),
        ));
    }
    if deploy_id.len() > MAX_DEPLOY_ID_BYTES {
        return Err(BroadcastContentError::InvalidDeployId(format!(
            "deploy_id exceeds {MAX_DEPLOY_ID_BYTES} bytes: {} bytes",
            deploy_id.len()
        )));
    }
    if !deploy_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(BroadcastContentError::InvalidDeployId(
            "deploy_id must be ASCII alphanumeric, '-', or '_'".to_owned(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ETag computation
// ---------------------------------------------------------------------------

/// Computes the `ETag` for a content body: `SHA-256(body)` hex-encoded.
///
/// This is the canonical `ETag` algorithm for all SDKs. Used for cache
/// revalidation in HTTP projection responses.
#[must_use]
pub fn compute_etag(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

/// Verifies a `BroadcastContent`'s `ETag` against the computed body hash.
///
/// - If `etag` is `None`, returns `Ok(())` (caller should populate it).
/// - If `etag` is `Some` and matches, returns `Ok(())`.
/// - If `etag` is `Some` and mismatches, returns
///   [`BroadcastContentError::EtagMismatch`].
///
/// # Errors
///
/// Returns [`BroadcastContentError::EtagMismatch`] when the declared `ETag`
/// does not match `SHA-256(body)`.
pub fn verify_etag(content: &BroadcastContent) -> Result<(), BroadcastContentError> {
    if let Some(ref declared) = content.metadata.etag {
        let computed = compute_etag(&content.body);
        if *declared != computed {
            return Err(BroadcastContentError::EtagMismatch {
                expected: declared.clone(),
                actual: computed,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------

/// Serializes a [`BroadcastContent`] into the wire format:
/// `BROADCAST_CONTENT_MAGIC ++ version_u8 ++ rmp_serde::to_vec(content)`.
///
/// Validates `deploy_id` before serialization.
///
/// # Errors
///
/// - [`BroadcastContentError::InvalidDeployId`] if `deploy_id` is present
///   but invalid.
/// - [`BroadcastContentError::DeserializationFailed`] if `MessagePack`
///   serialization fails (should not happen with valid types).
pub fn serialize_broadcast_content(
    content: &BroadcastContent,
) -> Result<Vec<u8>, BroadcastContentError> {
    // Body size limit — reject oversized payloads before serialization.
    if content.body.len() > MAX_BODY_BYTES {
        return Err(BroadcastContentError::BodyTooLarge(content.body.len()));
    }

    // Validate deploy_id before serialization.
    if let Some(ref id) = content.metadata.deploy_id {
        validate_deploy_id(id)?;
    }

    let msgpack = rmp_serde::to_vec_named(content).map_err(|_| {
        BroadcastContentError::DeserializationFailed(
            "broadcast content serialization failed".to_owned(),
        )
    })?;
    let mut buf = Vec::with_capacity(4 + msgpack.len());
    buf.extend_from_slice(&BROADCAST_CONTENT_MAGIC);
    buf.push(content.version);
    buf.extend_from_slice(&msgpack);
    Ok(buf)
}

/// Deserializes bytes into a [`BroadcastContent`], checking the magic prefix
/// and version byte first.
///
/// # Version Detection Algorithm
///
/// 1. Check first 3 bytes for `BROADCAST_CONTENT_MAGIC` ("SCP").
/// 2. If matched, read 4th byte as version.
/// 3. If `version >= 1`, deserialize remaining bytes as `MessagePack`.
/// 4. If magic absent, return [`BroadcastContentError::InvalidMagic`].
/// 5. If version is 0, return [`BroadcastContentError::UnsupportedVersion`].
///
/// Validates `deploy_id` after deserialization.
///
/// # Errors
///
/// - [`BroadcastContentError::InvalidMagic`] if the magic prefix is absent.
/// - [`BroadcastContentError::UnsupportedVersion`] if version is 0.
/// - [`BroadcastContentError::DeserializationFailed`] if `MessagePack` parsing
///   fails.
/// - [`BroadcastContentError::InvalidDeployId`] if `deploy_id` is present but
///   invalid.
pub fn deserialize_broadcast_content(
    bytes: &[u8],
) -> Result<BroadcastContent, BroadcastContentError> {
    if bytes.len() < 4 {
        return Err(BroadcastContentError::InvalidMagic);
    }
    if bytes[0..3] != BROADCAST_CONTENT_MAGIC {
        return Err(BroadcastContentError::InvalidMagic);
    }
    let header_version = bytes[3];
    if header_version == 0 {
        return Err(BroadcastContentError::UnsupportedVersion(0));
    }
    let mut content: BroadcastContent = rmp_serde::from_slice(&bytes[4..]).map_err(|_| {
        BroadcastContentError::DeserializationFailed("malformed broadcast content".to_owned())
    })?;

    // Fix #1: Override inner version with header version to prevent divergence
    // where header says v2 but body says v1.
    content.version = header_version;

    // Fix #3: Body size limit.
    if content.body.len() > MAX_BODY_BYTES {
        return Err(BroadcastContentError::BodyTooLarge(content.body.len()));
    }

    // Post-deserialization validation: deploy_id may have been crafted.
    if let Some(ref id) = content.metadata.deploy_id {
        validate_deploy_id(id)?;
    }

    // Fix #6: Validate etag format if present.
    if let Some(ref etag) = content.metadata.etag {
        validate_etag_format(etag)?;
    }

    Ok(content)
}

// ---------------------------------------------------------------------------
// ETag format validation
// ---------------------------------------------------------------------------

/// Validates that an etag string is exactly 64 lowercase hex digits (SHA-256 hex).
fn validate_etag_format(etag: &str) -> Result<(), BroadcastContentError> {
    if etag.len() != 64 {
        return Err(BroadcastContentError::InvalidEtag(format!(
            "etag must be exactly 64 hex chars, got {}",
            etag.len()
        )));
    }
    if !etag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(BroadcastContentError::InvalidEtag(
            "etag must contain only lowercase hex digits [0-9a-f]".to_owned(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unicode formatting character detection
// ---------------------------------------------------------------------------

/// Returns `true` for Unicode formatting and invisible characters that should
/// be rejected in content paths. Covers zero-width chars, bidi controls,
/// word joiners, invisible operators, BOM, and non-characters.
fn is_unicode_formatting(ch: char) -> bool {
    let cp = u32::from(ch);
    matches!(
        cp,
        // Zero-width chars (U+200B-U+200F): ZWSP, ZWNJ, ZWJ, LRM, RLM
        0x200B..=0x200F
        // Line/paragraph separators
        | 0x2028..=0x2029
        // Bidi embedding controls (LRE, RLE, PDF, LRO, RLO)
        | 0x202A..=0x202E
        // Medium mathematical space
        | 0x205F
        // Word joiner and invisible operators (U+2060-U+206F)
        | 0x2060..=0x206F
        // Ideographic space
        | 0x3000
        // BOM / ZWNBSP
        | 0xFEFF
        // Non-characters
        | 0xFFFE..=0xFFFF
    )
}

// ---------------------------------------------------------------------------
// ContentPath validation (private helpers)
// ---------------------------------------------------------------------------

/// Validates a content path string against all rejection rules.
fn validate_content_path(path: &str) -> Result<(), BroadcastContentError> {
    let err = |msg: &str| BroadcastContentError::InvalidContentPath(msg.to_owned());

    // Must start with '/'
    if !path.starts_with('/') {
        return Err(err("path must start with '/'"));
    }

    // Max length
    if path.len() > MAX_PATH_BYTES {
        return Err(err(&format!(
            "path exceeds {MAX_PATH_BYTES} bytes: {} bytes",
            path.len()
        )));
    }

    // Reject backslashes
    if path.contains('\\') {
        return Err(err("path must not contain backslashes"));
    }

    // Reject percent-encoded bytes
    if path.contains('%') {
        return Err(err("path must not contain percent-encoded bytes"));
    }

    // Reject query strings
    if path.contains('?') {
        return Err(err("path must not contain query strings"));
    }

    // Reject fragments
    if path.contains('#') {
        return Err(err("path must not contain fragments"));
    }

    // Reject null bytes, control characters (U+0000-U+001F, U+007F)
    for ch in path.chars() {
        if ch == '\0' {
            return Err(err("path must not contain null bytes"));
        }
        if ('\u{0000}'..='\u{001F}').contains(&ch) {
            return Err(err(&format!(
                "path must not contain control character U+{:04X}",
                u32::from(ch),
            )));
        }
        if ch == '\u{007F}' {
            return Err(err("path must not contain DEL (U+007F)"));
        }
    }

    // Reject non-ASCII whitespace, control, and formatting characters.
    // Covers: NBSP (U+00A0), general punctuation spaces (U+2000-U+200F),
    // line/paragraph separators (U+2028-U+2029), bidi embedding controls
    // (U+202A-U+202E), medium mathematical space (U+205F), word joiner and
    // invisible operators (U+2060-U+206F), ideographic space (U+3000),
    // BOM/ZWNBSP (U+FEFF), and non-characters (U+FFFE, U+FFFF).
    for ch in path.chars() {
        if !ch.is_ascii() && (ch.is_whitespace() || ch.is_control() || is_unicode_formatting(ch)) {
            return Err(err(&format!(
                "path must not contain non-ASCII whitespace/formatting U+{:04X}",
                u32::from(ch),
            )));
        }
    }

    // Reject double slashes
    if path.contains("//") {
        return Err(err("path must not contain '//'"));
    }

    // No trailing slash except root
    if path.len() > 1 && path.ends_with('/') {
        return Err(err("path must not have trailing slash (except root '/')"));
    }

    // Reject '.' and '..' segments (skip leading empty from leading '/')
    for segment in path.split('/').skip(1) {
        if segment == "." {
            return Err(err("path must not contain '.' segments"));
        }
        if segment == ".." {
            return Err(err(
                "path must not contain '..' segments (directory traversal)",
            ));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// MimeType validation (private helpers)
// ---------------------------------------------------------------------------

/// Validates a MIME type string: `type/subtype`, no parameters, no control chars.
///
/// Token characters per RFC 7230 §3.2.6: ALPHA, DIGIT, `!`, `#`, `$`, `&`,
/// `'`, `*`, `+`, `-`, `.`, `^`, `_`, `` ` ``, `|`, `~`.
/// `%` intentionally excluded (not a tchar).
fn validate_mime_type(value: &str) -> Result<(), BroadcastContentError> {
    let err = |msg: &str| BroadcastContentError::InvalidMimeType(msg.to_owned());

    if value.is_empty() {
        return Err(err("MIME type must not be empty"));
    }

    // Reject control characters (including \r, \n)
    for ch in value.chars() {
        if ch.is_control() {
            return Err(err(&format!(
                "MIME type must not contain control character U+{:04X}",
                u32::from(ch),
            )));
        }
    }

    // Reject parameters
    if value.contains(';') {
        return Err(err(
            "MIME type must not contain parameters (';' not allowed)",
        ));
    }

    // Must have exactly one '/'
    let slash_count = value.chars().filter(|&c| c == '/').count();
    if slash_count != 1 {
        return Err(err("MIME type must be 'type/subtype' (exactly one '/')"));
    }

    // Both parts must be non-empty and consist of valid token characters.
    let (type_part, subtype_part) = value
        .split_once('/')
        .ok_or_else(|| err("MIME type must be 'type/subtype'"))?;

    if type_part.is_empty() || subtype_part.is_empty() {
        return Err(err("MIME type and subtype must both be non-empty"));
    }

    // RFC 7230 §3.2.6 tchar set: ALPHA / DIGIT / "!" / "#" / "$" / "&" /
    // "'" / "*" / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
    // Note: "%" is intentionally excluded — it is not a tchar per RFC 7230,
    // and allowing it would enable encoded-character injection.
    let is_token_char = |c: char| c.is_ascii_alphanumeric() || "!#$&'*+-.^_`|~".contains(c);

    if !type_part.chars().all(is_token_char) {
        return Err(err("MIME type part contains invalid characters"));
    }
    if !subtype_part.chars().all(is_token_char) {
        return Err(err("MIME subtype part contains invalid characters"));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- Helper --

    fn sample_content() -> BroadcastContent {
        BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: Some(ContentPath::new("/index.html").unwrap()),
                content_type: Some(MimeType::new("text/html").unwrap()),
                deploy_id: Some("deploy-001".to_owned()),
                etag: Some(compute_etag(b"<html>hello</html>")),
                immutable: false,
            },
            body: b"<html>hello</html>".to_vec(),
        }
    }

    // -----------------------------------------------------------------------
    // BroadcastContent round-trip serialization
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_broadcast_content() {
        let content = sample_content();
        let bytes = serialize_broadcast_content(&content).unwrap();
        let deserialized = deserialize_broadcast_content(&bytes).unwrap();
        assert_eq!(content, deserialized);
    }

    #[test]
    fn round_trip_empty_body() {
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: None,
                immutable: false,
            },
            body: Vec::new(),
        };
        let bytes = serialize_broadcast_content(&content).unwrap();
        let deserialized = deserialize_broadcast_content(&bytes).unwrap();
        assert_eq!(content, deserialized);
    }

    #[test]
    fn round_trip_immutable_flag() {
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: Some(ContentPath::new("/assets/style.a1b2c3.css").unwrap()),
                content_type: Some(MimeType::new("text/css").unwrap()),
                deploy_id: None,
                etag: None,
                immutable: true,
            },
            body: b"body { color: red; }".to_vec(),
        };
        let bytes = serialize_broadcast_content(&content).unwrap();
        let deserialized = deserialize_broadcast_content(&bytes).unwrap();
        assert!(deserialized.metadata.immutable);
    }

    #[test]
    fn wire_format_prefix() {
        let content = sample_content();
        let bytes = serialize_broadcast_content(&content).unwrap();
        assert_eq!(&bytes[..3], &BROADCAST_CONTENT_MAGIC);
        assert_eq!(bytes[3], BROADCAST_CONTENT_VERSION);
    }

    // -----------------------------------------------------------------------
    // Version detection
    // -----------------------------------------------------------------------

    #[test]
    fn legacy_bytes_no_magic_returns_error() {
        let raw = b"just some random bytes without magic";
        let result = deserialize_broadcast_content(raw);
        assert!(matches!(result, Err(BroadcastContentError::InvalidMagic)));
    }

    #[test]
    fn too_short_returns_error() {
        let result = deserialize_broadcast_content(b"SC");
        assert!(matches!(result, Err(BroadcastContentError::InvalidMagic)));
    }

    #[test]
    fn empty_returns_error() {
        let result = deserialize_broadcast_content(b"");
        assert!(matches!(result, Err(BroadcastContentError::InvalidMagic)));
    }

    #[test]
    fn wrong_magic_returns_error() {
        let result = deserialize_broadcast_content(b"XYZ\x01rest");
        assert!(matches!(result, Err(BroadcastContentError::InvalidMagic)));
    }

    #[test]
    fn version_zero_returns_error() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BROADCAST_CONTENT_MAGIC);
        bytes.push(0); // version 0
        bytes.extend_from_slice(b"payload");
        let result = deserialize_broadcast_content(&bytes);
        assert!(matches!(
            result,
            Err(BroadcastContentError::UnsupportedVersion(0))
        ));
    }

    #[test]
    fn version_one_success() {
        let content = BroadcastContent {
            version: 1,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: None,
                immutable: false,
            },
            body: b"hello".to_vec(),
        };
        let bytes = serialize_broadcast_content(&content).unwrap();
        assert_eq!(bytes[0..3], BROADCAST_CONTENT_MAGIC);
        assert_eq!(bytes[3], 1);
        let result = deserialize_broadcast_content(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn future_version_accepted_and_header_overrides_inner() {
        // Build a valid v1 payload, then change the header version byte to 2.
        // The MessagePack payload is still v1-shaped, so deserialization
        // succeeds (forward-compatible framing). The inner version field must
        // be overridden by the header version (fix #1: version reconciliation).
        let content = sample_content();
        let mut bytes = serialize_broadcast_content(&content).unwrap();
        bytes[3] = 2;
        let result = deserialize_broadcast_content(&bytes).unwrap();
        assert_eq!(result.version, 2, "inner version must match header version");
    }

    // -----------------------------------------------------------------------
    // ContentPath — valid cases
    // -----------------------------------------------------------------------

    #[test]
    fn content_path_root() {
        assert!(ContentPath::new("/").is_ok());
    }

    #[test]
    fn content_path_simple() {
        let p = ContentPath::new("/about").unwrap();
        assert_eq!(p.as_str(), "/about");
    }

    #[test]
    fn content_path_nested() {
        assert!(ContentPath::new("/assets/style.css").is_ok());
    }

    #[test]
    fn content_path_hidden_file() {
        assert!(ContentPath::new("/foo/.hidden").is_ok());
    }

    #[test]
    fn content_path_dot_in_filename() {
        assert!(ContentPath::new("/assets/style.min.css").is_ok());
    }

    #[test]
    fn content_path_display_and_as_ref() {
        let p = ContentPath::new("/test").unwrap();
        assert_eq!(format!("{p}"), "/test");
        assert_eq!(p.as_ref(), "/test");
    }

    #[test]
    fn content_path_max_length_ok() {
        // 1024 bytes exactly: '/' + 1023 'a' chars
        let path = format!("/{}", "a".repeat(MAX_PATH_BYTES - 1));
        assert_eq!(path.len(), MAX_PATH_BYTES);
        assert!(ContentPath::new(path).is_ok());
    }

    // -----------------------------------------------------------------------
    // ContentPath — rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn content_path_rejects_empty() {
        assert!(ContentPath::new("").is_err());
    }

    #[test]
    fn content_path_rejects_no_leading_slash() {
        let r = ContentPath::new("about");
        assert!(matches!(
            r,
            Err(BroadcastContentError::InvalidContentPath(_))
        ));
    }

    #[test]
    fn content_path_rejects_dotdot_traversal() {
        assert!(ContentPath::new("/foo/../bar").is_err());
        assert!(ContentPath::new("/..").is_err());
    }

    #[test]
    fn content_path_rejects_dot_segment() {
        assert!(ContentPath::new("/foo/./bar").is_err());
        assert!(ContentPath::new("/.").is_err());
    }

    #[test]
    fn content_path_rejects_double_slash() {
        assert!(ContentPath::new("/foo//bar").is_err());
    }

    #[test]
    fn content_path_rejects_backslash() {
        assert!(ContentPath::new("/foo\\bar").is_err());
    }

    #[test]
    fn content_path_rejects_null_byte() {
        assert!(ContentPath::new("/foo\0bar").is_err());
    }

    #[test]
    fn content_path_rejects_control_chars() {
        // Tab
        assert!(ContentPath::new("/foo\tbar").is_err());
        // Newline
        assert!(ContentPath::new("/foo\nbar").is_err());
        // Carriage return
        assert!(ContentPath::new("/foo\rbar").is_err());
        // DEL (U+007F)
        assert!(ContentPath::new("/foo\x7Fbar").is_err());
    }

    #[test]
    fn content_path_rejects_non_ascii_whitespace() {
        // U+00A0 (NBSP)
        assert!(ContentPath::new("/foo\u{00A0}bar").is_err());
        // U+2000 (EN QUAD)
        assert!(ContentPath::new("/foo\u{2000}bar").is_err());
        // U+200B (ZERO WIDTH SPACE)
        assert!(ContentPath::new("/foo\u{200B}bar").is_err());
        // U+FEFF (BOM)
        assert!(ContentPath::new("/foo\u{FEFF}bar").is_err());
    }

    #[test]
    fn content_path_rejects_percent_encoding() {
        assert!(ContentPath::new("/foo%2Fbar").is_err());
    }

    #[test]
    fn content_path_rejects_percent_encoded_traversal() {
        assert!(ContentPath::new("/foo/%2e%2e/bar").is_err());
    }

    #[test]
    fn content_path_rejects_query_string() {
        assert!(ContentPath::new("/foo?bar=baz").is_err());
    }

    #[test]
    fn content_path_rejects_fragment() {
        assert!(ContentPath::new("/foo#section").is_err());
    }

    #[test]
    fn content_path_rejects_trailing_slash() {
        assert!(ContentPath::new("/foo/").is_err());
        assert!(ContentPath::new("/foo/bar/").is_err());
    }

    #[test]
    fn content_path_rejects_too_long() {
        let long_path = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        assert!(ContentPath::new(long_path).is_err());
    }

    #[test]
    fn content_path_nfc_normalization() {
        // U+00E9 (e-acute precomposed) vs U+0065 U+0301 (e + combining acute)
        let decomposed = "/caf\u{0065}\u{0301}";
        let precomposed = "/caf\u{00E9}";
        let p = ContentPath::new(decomposed).unwrap();
        assert_eq!(p.as_str(), precomposed);
    }

    #[test]
    fn content_path_serde_json_roundtrip() {
        let p = ContentPath::new("/foo/bar").unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let deserialized: ContentPath = serde_json::from_str(&json).unwrap();
        assert_eq!(p, deserialized);
    }

    #[test]
    fn content_path_serde_json_rejects_invalid() {
        let json = "\"foo/bar\""; // no leading slash
        let result: Result<ContentPath, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // MimeType — valid cases
    // -----------------------------------------------------------------------

    #[test]
    fn mime_type_text_html() {
        assert!(MimeType::new("text/html").is_ok());
    }

    #[test]
    fn mime_type_application_json() {
        let m = MimeType::new("application/json").unwrap();
        assert_eq!(m.as_str(), "application/json");
    }

    #[test]
    fn mime_type_image_png() {
        assert!(MimeType::new("image/png").is_ok());
    }

    #[test]
    fn mime_type_with_plus() {
        assert!(MimeType::new("application/vnd.api+json").is_ok());
    }

    #[test]
    fn mime_type_display_and_as_ref() {
        let m = MimeType::new("text/plain").unwrap();
        assert_eq!(format!("{m}"), "text/plain");
        assert_eq!(m.as_ref(), "text/plain");
    }

    // -----------------------------------------------------------------------
    // MimeType — rejection cases
    // -----------------------------------------------------------------------

    #[test]
    fn mime_type_rejects_empty() {
        assert!(matches!(
            MimeType::new(""),
            Err(BroadcastContentError::InvalidMimeType(_))
        ));
    }

    #[test]
    fn mime_type_rejects_no_slash() {
        assert!(matches!(
            MimeType::new("texthtml"),
            Err(BroadcastContentError::InvalidMimeType(_))
        ));
    }

    #[test]
    fn mime_type_rejects_double_slash() {
        assert!(matches!(
            MimeType::new("text/html/extra"),
            Err(BroadcastContentError::InvalidMimeType(_))
        ));
    }

    #[test]
    fn mime_type_rejects_parameters() {
        assert!(matches!(
            MimeType::new("text/html; charset=utf-8"),
            Err(BroadcastContentError::InvalidMimeType(_))
        ));
    }

    #[test]
    fn mime_type_rejects_cr() {
        assert!(MimeType::new("text/html\r").is_err());
    }

    #[test]
    fn mime_type_rejects_lf() {
        assert!(MimeType::new("text/html\n").is_err());
    }

    #[test]
    fn mime_type_rejects_crlf() {
        assert!(MimeType::new("text/html\r\nX-Injected: true").is_err());
    }

    #[test]
    fn mime_type_rejects_control_char() {
        assert!(MimeType::new("text/\x00html").is_err());
        assert!(MimeType::new("text/\x01html").is_err());
        assert!(MimeType::new("text/html\x7F").is_err());
    }

    #[test]
    fn mime_type_rejects_empty_type() {
        assert!(MimeType::new("/html").is_err());
    }

    #[test]
    fn mime_type_rejects_empty_subtype() {
        assert!(MimeType::new("text/").is_err());
    }

    #[test]
    fn mime_type_rejects_spaces() {
        assert!(MimeType::new("text /html").is_err());
        assert!(MimeType::new("text/ html").is_err());
    }

    #[test]
    fn mime_type_serde_json_roundtrip() {
        let m = MimeType::new("text/html").unwrap();
        let json = serde_json::to_string(&m).unwrap();
        let deserialized: MimeType = serde_json::from_str(&json).unwrap();
        assert_eq!(m, deserialized);
    }

    #[test]
    fn mime_type_serde_json_rejects_invalid() {
        let json = "\"not_a_mime\""; // no slash
        let result: Result<MimeType, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // deploy_id validation
    // -----------------------------------------------------------------------

    #[test]
    fn deploy_id_valid() {
        assert!(validate_deploy_id("deploy-001").is_ok());
        assert!(validate_deploy_id("abc_123-XYZ").is_ok());
        assert!(validate_deploy_id("a").is_ok());
    }

    #[test]
    fn deploy_id_max_length_ok() {
        assert!(validate_deploy_id(&"a".repeat(MAX_DEPLOY_ID_BYTES)).is_ok());
    }

    #[test]
    fn deploy_id_rejects_empty() {
        assert!(matches!(
            validate_deploy_id(""),
            Err(BroadcastContentError::InvalidDeployId(_))
        ));
    }

    #[test]
    fn deploy_id_rejects_too_long() {
        assert!(matches!(
            validate_deploy_id(&"a".repeat(MAX_DEPLOY_ID_BYTES + 1)),
            Err(BroadcastContentError::InvalidDeployId(_))
        ));
    }

    #[test]
    fn deploy_id_rejects_spaces() {
        assert!(validate_deploy_id("deploy 001").is_err());
    }

    #[test]
    fn deploy_id_rejects_special_chars() {
        assert!(validate_deploy_id("deploy!001").is_err());
        assert!(validate_deploy_id("deploy/001").is_err());
        assert!(validate_deploy_id("deploy.001").is_err());
        assert!(validate_deploy_id("deploy@001").is_err());
    }

    // -----------------------------------------------------------------------
    // Serialization validates deploy_id
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_rejects_invalid_deploy_id() {
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: Some(String::new()), // empty
                etag: None,
                immutable: false,
            },
            body: vec![],
        };
        assert!(serialize_broadcast_content(&content).is_err());
    }

    #[test]
    fn deserialize_rejects_invalid_deploy_id() {
        // Build a valid-looking payload with an invalid deploy_id baked in
        // via direct MessagePack serialization (bypassing our validation).
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: Some("has spaces".to_owned()),
                etag: None,
                immutable: false,
            },
            body: vec![],
        };
        let msgpack = rmp_serde::to_vec_named(&content).unwrap();
        let mut bytes = Vec::with_capacity(4 + msgpack.len());
        bytes.extend_from_slice(&BROADCAST_CONTENT_MAGIC);
        bytes.push(BROADCAST_CONTENT_VERSION);
        bytes.extend_from_slice(&msgpack);

        let result = deserialize_broadcast_content(&bytes);
        assert!(matches!(
            result,
            Err(BroadcastContentError::InvalidDeployId(_))
        ));
    }

    // -----------------------------------------------------------------------
    // ETag computation and verification
    // -----------------------------------------------------------------------

    #[test]
    fn etag_computation_deterministic() {
        let body = b"hello world";
        let e1 = compute_etag(body);
        let e2 = compute_etag(body);
        assert_eq!(e1, e2);
        assert_eq!(
            e1,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn etag_empty_body() {
        let etag = compute_etag(b"");
        assert_eq!(
            etag,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn verify_etag_match() {
        let body = b"test body";
        let etag = compute_etag(body);
        let content = BroadcastContent {
            version: 1,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: Some(etag),
                immutable: false,
            },
            body: body.to_vec(),
        };
        assert!(verify_etag(&content).is_ok());
    }

    #[test]
    fn verify_etag_mismatch() {
        let content = BroadcastContent {
            version: 1,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: Some("wrong_hash".to_owned()),
                immutable: false,
            },
            body: b"test body".to_vec(),
        };
        assert!(matches!(
            verify_etag(&content),
            Err(BroadcastContentError::EtagMismatch { .. })
        ));
    }

    #[test]
    fn verify_etag_none_is_ok() {
        let content = BroadcastContent {
            version: 1,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: None,
                immutable: false,
            },
            body: b"test body".to_vec(),
        };
        assert!(verify_etag(&content).is_ok());
    }

    // -----------------------------------------------------------------------
    // Body too large
    // -----------------------------------------------------------------------

    #[test]
    fn deserialize_rejects_body_too_large() {
        // Build a payload with a body exceeding MAX_BODY_BYTES (10 MiB).
        let big_body = vec![0xAA; MAX_BODY_BYTES + 1];
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: None,
                immutable: false,
            },
            body: big_body,
        };
        // Bypass serialize_broadcast_content (which also checks body size)
        // and build the wire format directly to test the deserialization guard.
        let msgpack = rmp_serde::to_vec_named(&content).unwrap();
        let mut bytes = Vec::with_capacity(4 + msgpack.len());
        bytes.extend_from_slice(&BROADCAST_CONTENT_MAGIC);
        bytes.push(BROADCAST_CONTENT_VERSION);
        bytes.extend_from_slice(&msgpack);

        let result = deserialize_broadcast_content(&bytes);
        assert!(
            matches!(result, Err(BroadcastContentError::BodyTooLarge(sz)) if sz == MAX_BODY_BYTES + 1)
        );
    }

    // -----------------------------------------------------------------------
    // ETag format validation
    // -----------------------------------------------------------------------

    #[test]
    fn etag_valid_64_hex() {
        // A valid SHA-256 hex string.
        let valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(validate_etag_format(valid).is_ok());
    }

    #[test]
    fn etag_rejects_wrong_length() {
        assert!(matches!(
            validate_etag_format("abcd"),
            Err(BroadcastContentError::InvalidEtag(_))
        ));
        // 63 chars
        assert!(matches!(
            validate_etag_format(&"a".repeat(63)),
            Err(BroadcastContentError::InvalidEtag(_))
        ));
        // 65 chars
        assert!(matches!(
            validate_etag_format(&"a".repeat(65)),
            Err(BroadcastContentError::InvalidEtag(_))
        ));
    }

    #[test]
    fn etag_rejects_uppercase() {
        let upper = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert!(matches!(
            validate_etag_format(upper),
            Err(BroadcastContentError::InvalidEtag(_))
        ));
    }

    #[test]
    fn etag_rejects_non_hex() {
        // 64 chars but contains 'g'
        let bad = format!("{}g", "a".repeat(63));
        assert!(matches!(
            validate_etag_format(&bad),
            Err(BroadcastContentError::InvalidEtag(_))
        ));
    }

    #[test]
    fn deserialize_rejects_invalid_etag_format() {
        // Build a payload with an etag that is not 64 lowercase hex.
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: Some("not-a-valid-etag".to_owned()),
                immutable: false,
            },
            body: vec![],
        };
        // Bypass serialize and build wire format directly so the bad etag
        // is embedded in the msgpack payload.
        let msgpack = rmp_serde::to_vec_named(&content).unwrap();
        let mut bytes = Vec::with_capacity(4 + msgpack.len());
        bytes.extend_from_slice(&BROADCAST_CONTENT_MAGIC);
        bytes.push(BROADCAST_CONTENT_VERSION);
        bytes.extend_from_slice(&msgpack);

        let result = deserialize_broadcast_content(&bytes);
        assert!(matches!(result, Err(BroadcastContentError::InvalidEtag(_))));
    }

    // -----------------------------------------------------------------------
    // Named encoding round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn named_encoding_round_trip() {
        // Verify that to_vec_named encoding round-trips correctly.
        let content = sample_content();
        let bytes = serialize_broadcast_content(&content).unwrap();
        let deserialized = deserialize_broadcast_content(&bytes).unwrap();
        assert_eq!(content.body, deserialized.body);
        assert_eq!(content.metadata, deserialized.metadata);
        assert_eq!(content.version, deserialized.version);
    }

    // -----------------------------------------------------------------------
    // Extended non-ASCII whitespace rejection
    // -----------------------------------------------------------------------

    #[test]
    fn content_path_rejects_extended_unicode_formatting() {
        // U+2028 LINE SEPARATOR
        assert!(ContentPath::new("/foo\u{2028}bar").is_err());
        // U+2029 PARAGRAPH SEPARATOR
        assert!(ContentPath::new("/foo\u{2029}bar").is_err());
        // U+202A LEFT-TO-RIGHT EMBEDDING (bidi control)
        assert!(ContentPath::new("/foo\u{202A}bar").is_err());
        // U+202E RIGHT-TO-LEFT OVERRIDE (bidi control)
        assert!(ContentPath::new("/foo\u{202E}bar").is_err());
        // U+205F MEDIUM MATHEMATICAL SPACE
        assert!(ContentPath::new("/foo\u{205F}bar").is_err());
        // U+2060 WORD JOINER
        assert!(ContentPath::new("/foo\u{2060}bar").is_err());
        // U+3000 IDEOGRAPHIC SPACE
        assert!(ContentPath::new("/foo\u{3000}bar").is_err());
        // U+FFFE non-character
        assert!(ContentPath::new("/foo\u{FFFE}bar").is_err());
        // U+FFFF non-character
        assert!(ContentPath::new("/foo\u{FFFF}bar").is_err());
    }

    // -----------------------------------------------------------------------
    // MimeType extended tchar
    // -----------------------------------------------------------------------

    #[test]
    fn mime_type_accepts_full_tchar_set() {
        // Type and subtype with all RFC 7230 tchar specials.
        assert!(MimeType::new("application/vnd.x-test+foo").is_ok());
        assert!(MimeType::new("x-type!/sub*type").is_ok());
        assert!(MimeType::new("x/y~z").is_ok());
        assert!(MimeType::new("x/y|z").is_ok());
        assert!(MimeType::new("x/y`z").is_ok());
        assert!(MimeType::new("x/y'z").is_ok());
    }

    // -----------------------------------------------------------------------
    // Error string sanitization
    // -----------------------------------------------------------------------

    #[test]
    fn deserialization_error_does_not_leak_internals() {
        // Feed invalid msgpack after a valid header. The error message
        // must be generic, not the raw rmp_serde error.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&BROADCAST_CONTENT_MAGIC);
        bytes.push(BROADCAST_CONTENT_VERSION);
        bytes.extend_from_slice(b"not valid msgpack");

        let result = deserialize_broadcast_content(&bytes);
        match result {
            Err(BroadcastContentError::DeserializationFailed(msg)) => {
                assert_eq!(msg, "malformed broadcast content");
            }
            other => panic!("expected DeserializationFailed, got: {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Error display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_messages() {
        let err = BroadcastContentError::InvalidMagic;
        assert!(format!("{err}").contains("magic"));

        let err = BroadcastContentError::UnsupportedVersion(42);
        assert!(format!("{err}").contains("42"));

        let err = BroadcastContentError::InvalidContentPath("bad".into());
        assert!(format!("{err}").contains("bad"));

        let err = BroadcastContentError::InvalidMimeType("bad".into());
        assert!(format!("{err}").contains("bad"));

        let err = BroadcastContentError::InvalidDeployId("bad".into());
        assert!(format!("{err}").contains("bad"));

        let err = BroadcastContentError::DeserializationFailed("oops".into());
        assert!(format!("{err}").contains("oops"));

        let err = BroadcastContentError::EtagMismatch {
            expected: "aaa".into(),
            actual: "bbb".into(),
        };
        assert!(format!("{err}").contains("aaa"));
        assert!(format!("{err}").contains("bbb"));
    }

    // -----------------------------------------------------------------------
    // Body size validation on serialization (fix #3)
    // -----------------------------------------------------------------------

    #[test]
    fn serialize_rejects_body_too_large() {
        let big_body = vec![0xBB; MAX_BODY_BYTES + 1];
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: None,
                immutable: false,
            },
            body: big_body,
        };
        let result = serialize_broadcast_content(&content);
        assert!(
            matches!(result, Err(BroadcastContentError::BodyTooLarge(sz)) if sz == MAX_BODY_BYTES + 1)
        );
    }

    #[test]
    fn serialize_accepts_body_at_max() {
        let body = vec![0xCC; MAX_BODY_BYTES];
        let content = BroadcastContent {
            version: BROADCAST_CONTENT_VERSION,
            metadata: ContentMetadata {
                path: None,
                content_type: None,
                deploy_id: None,
                etag: None,
                immutable: false,
            },
            body,
        };
        assert!(serialize_broadcast_content(&content).is_ok());
    }
}
