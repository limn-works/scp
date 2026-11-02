//! The `NodeListRecord`, its entries, and the `0x06` frame it travels in.
//!
//! Sources: `09-security-model.md` §9.6.3 "The record", "The entry", "The fetch";
//! §9.10.12; §9.18.2 `"SCP-NODE-LIST-V1:"` and `"scp:nls:"`; spec 25 §25.27
//! Vector 49.
//!
//! The governor's `#active` signs
//!
//! ```text
//! SHA-256("SCP-NODE-LIST-V1:" ‖ BE32(len(context_id)) ‖ context_id ‖ BE64(sequence)
//!         ‖ governor ‖ signing_key_state_head ‖ SHA-256(JCS(entries)))
//! ```
//!
//! `context_id` is the one variable-length field and carries its BE32 length;
//! the rest are fixed width. A party stores and forwards the record as its
//! RFC 8785 canonical JSON, in which every byte field is lowercase hex.
//!
//! **`sequence` is a decimal string in the JSON.** §9.6.3 types it `u64`, and
//! `crate::jcs` refuses a JSON number above 2^53 (I-JSON), so a numeric
//! encoding could not carry every `u64`. The workspace rule for such a field
//! is a string encoding, as `economy::types::Amount` takes. The signature
//! member is `signature`. §9.6.3 fixes neither choice.

use scp_crypto::p256::{P256Error, P256PublicKey, SIGNATURE_LEN, verify_prehash_strict};
use scp_did::{Identifier, NodeId, NodeUrl};
use scp_kel::{NodeKeyError, node_list_routing_id};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::binding::{NODE_KEY_LEN, NodeBinding, NodeBindingError, node_url_hash};
use crate::crypto::canonical::{CanonicalError, CanonicalField, canonical_hash};
use crate::envelope::did_record::MAX_BLOB_SIZE;

/// The §9.18.2 separator of the record preimage.
pub const NODE_LIST_SEPARATOR: &str = "SCP-NODE-LIST-V1:";

/// The `version` byte of a node-list record frame (§9.10.12).
pub const NODE_LIST_FRAME_VERSION: u8 = 6;

/// The frame's fixed prefix: `version` (1) and `governor` (32).
pub const NODE_LIST_FRAME_PREFIX_LEN: usize = 33;

/// The longest `value` a frame carries: `Max blob size − 33` (§9.10.12).
pub const MAX_NODE_LIST_VALUE_LEN: usize = MAX_BLOB_SIZE - NODE_LIST_FRAME_PREFIX_LEN;

/// One listed node (§9.6.3 "The entry").
///
/// Its name is the `NodeId` of
/// `binding.node_key` and its operator is `binding.operator`; it carries no
/// operator or key field of its own, so no two fields can disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeListEntry {
    /// The binding of the node key to its operator.
    pub binding: NodeBinding,
    /// The node's canonical URL.
    pub url: NodeUrl,
    /// True where the node charges nothing for basic protocol operation. No
    /// rule reads it.
    pub free: bool,
}

impl NodeListEntry {
    /// The entry's name, the `NodeId` of `binding.node_key`.
    ///
    /// # Errors
    ///
    /// [`NodeKeyError`] when the node key is not a point on P-256.
    pub fn node_id(&self) -> Result<NodeId, NodeKeyError> {
        self.binding.node_id()
    }

    /// Verifies the binding under `operator_active` and checks that
    /// `binding.url_hash` is the SHA-256 of `url`, so a binding signed for one
    /// URL cannot be listed under another. A party treats an entry that fails
    /// as void (§9.6.3 acceptance step 3).
    ///
    /// # Errors
    ///
    /// [`NodeBindingError::UrlHashMismatch`] or the binding's own error.
    pub fn verify(&self, operator_active: &P256PublicKey) -> Result<(), NodeBindingError> {
        if node_url_hash(&self.url) != self.binding.url_hash {
            return Err(NodeBindingError::UrlHashMismatch);
        }
        self.binding.verify(operator_active)
    }
}

/// One governor-signed node list (§9.6.3 "The record").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeListRecord {
    /// The node-list context's identifier.
    pub context_id: String,
    /// 1 on the first record, one higher on each later record.
    pub sequence: u64,
    /// The governor that signed.
    pub governor: Identifier,
    /// The §9.5.1 preimage digest of the governor's latest state-carrying
    /// event at or before the moment it signed.
    pub signing_key_state_head: [u8; 32],
    /// The entries in the governor's order.
    pub entries: Vec<NodeListEntry>,
    /// The governor's `#active` signature over the preimage.
    pub signature: [u8; SIGNATURE_LEN],
}

/// Why a record, or its canonical JSON, is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeListError {
    /// The bytes are not the JSON of a `NodeListRecord`.
    #[error("node-list record JSON: {0}")]
    Json(String),
    /// The bytes parse, but they are not the record's RFC 8785 canonical
    /// form: whitespace, member order, uppercase hex, a leading zero, or a
    /// non-canonical URL.
    #[error("node-list record is not in RFC 8785 canonical form")]
    NotCanonical,
    /// A hex member has the wrong length or a non-hex character.
    #[error("node-list record member {0} is not lowercase hex of the right length")]
    BadHex(&'static str),
    /// `sequence` is not a decimal `u64`.
    #[error("node-list record sequence is not a decimal u64")]
    BadSequence,
    /// `sequence` is 0; the first record carries 1.
    #[error("node-list record sequence is 0")]
    ZeroSequence,
    /// `context_id` is empty.
    #[error("node-list record context_id is empty")]
    EmptyContextId,
    /// An entry's `url` has no canonical form ending in `/scp/v1`.
    #[error("node-list entry URL: {0}")]
    BadUrl(String),
    /// The canonical JSON is longer than a frame's `value` can carry.
    #[error("node-list record JSON is {0} bytes, more than a frame carries")]
    TooLarge(usize),
    /// The preimage could not be encoded.
    #[error("node-list record preimage: {0}")]
    Preimage(#[from] CanonicalError),
    /// The governor signature does not verify.
    #[error("node-list record signature: {0}")]
    Signature(P256Error),
}

// The JSON shape. Member order here is irrelevant: `crate::jcs` sorts members
// by RFC 8785's rule.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireBinding {
    operator: String,
    node_key: String,
    url_hash: String,
    key_state_head: String,
    operator_sig: String,
    possession_sig: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEntry {
    binding: WireBinding,
    url: String,
    free: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRecord {
    context_id: String,
    sequence: String,
    governor: String,
    signing_key_state_head: String,
    entries: Vec<WireEntry>,
    signature: String,
}

fn wire_entry(entry: &NodeListEntry) -> WireEntry {
    let b = &entry.binding;
    WireEntry {
        binding: WireBinding {
            operator: hex::encode(b.operator.as_bytes()),
            node_key: hex::encode(b.node_key),
            url_hash: hex::encode(b.url_hash),
            key_state_head: hex::encode(b.key_state_head),
            operator_sig: hex::encode(b.operator_sig),
            possession_sig: hex::encode(b.possession_sig),
        },
        url: entry.url.as_str().to_owned(),
        free: entry.free,
    }
}

fn from_hex<const N: usize>(member: &'static str, s: &str) -> Result<[u8; N], NodeListError> {
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| NodeListError::BadHex(member))?;
    Ok(out)
}

fn entry_from_wire(wire: WireEntry) -> Result<NodeListEntry, NodeListError> {
    let b = wire.binding;
    Ok(NodeListEntry {
        binding: NodeBinding {
            operator: Identifier::from_bytes(from_hex("operator", &b.operator)?),
            node_key: from_hex::<NODE_KEY_LEN>("node_key", &b.node_key)?,
            url_hash: from_hex("url_hash", &b.url_hash)?,
            key_state_head: from_hex("key_state_head", &b.key_state_head)?,
            operator_sig: from_hex("operator_sig", &b.operator_sig)?,
            possession_sig: from_hex("possession_sig", &b.possession_sig)?,
        },
        url: NodeUrl::new(&wire.url).map_err(|e| NodeListError::BadUrl(e.to_string()))?,
        free: wire.free,
    })
}

/// The RFC 8785 canonical JSON of an entry array, whose SHA-256 the record
/// preimage carries.
///
/// # Errors
///
/// [`NodeListError::Json`] when serialization fails.
pub fn entries_canonical_json(entries: &[NodeListEntry]) -> Result<Vec<u8>, NodeListError> {
    let wire: Vec<WireEntry> = entries.iter().map(wire_entry).collect();
    crate::jcs::to_vec(&wire).map_err(NodeListError::Json)
}

impl NodeListRecord {
    /// The digest the governor's `#active` signs.
    ///
    /// # Errors
    ///
    /// [`NodeListError::Json`] when the entries do not serialize, or
    /// [`NodeListError::Preimage`] when `context_id` exceeds a BE32 length.
    pub fn signing_digest(
        context_id: &str,
        sequence: u64,
        governor: &Identifier,
        signing_key_state_head: &[u8; 32],
        entries: &[NodeListEntry],
    ) -> Result<[u8; 32], NodeListError> {
        let entries_digest: [u8; 32] = Sha256::digest(entries_canonical_json(entries)?).into();
        Ok(canonical_hash(
            NODE_LIST_SEPARATOR,
            &[
                CanonicalField::VarBytes(context_id.as_bytes()),
                CanonicalField::U64(sequence),
                CanonicalField::Fixed32(governor.as_bytes()),
                CanonicalField::Fixed32(signing_key_state_head),
                CanonicalField::Fixed32(&entries_digest),
            ],
        )?)
    }

    /// The digest over this record's five fields.
    ///
    /// # Errors
    ///
    /// As [`Self::signing_digest`].
    pub fn digest(&self) -> Result<[u8; 32], NodeListError> {
        Self::signing_digest(
            &self.context_id,
            self.sequence,
            &self.governor,
            &self.signing_key_state_head,
            &self.entries,
        )
    }

    /// Verifies the governor signature strictly under `governor_active`.
    ///
    /// `governor_active` is the key the caller found for the governor: for
    /// standing, the key the governor's current key state lists `Current` in
    /// `#active`; for attribution, the `#active` at `signing_key_state_head`
    /// (§9.6.3, two classes). The caller resolves it, because both classes
    /// read key state this type does not hold. The record's entries are
    /// verified one by one with [`NodeListEntry::verify`].
    ///
    /// # Errors
    ///
    /// [`NodeListError::Signature`] when the signature fails, or a digest
    /// error.
    pub fn verify(&self, governor_active: &P256PublicKey) -> Result<(), NodeListError> {
        verify_prehash_strict(governor_active, &self.digest()?, &self.signature)
            .map_err(NodeListError::Signature)
    }

    /// The record's RFC 8785 canonical JSON, the form a party stores and
    /// forwards and `FallbackConfirmation.list_record` carries (§9.7.1).
    ///
    /// # Errors
    ///
    /// [`NodeListError::Json`] when serialization fails, or
    /// [`NodeListError::TooLarge`] when the JSON exceeds a frame's `value`.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, NodeListError> {
        let wire = WireRecord {
            context_id: self.context_id.clone(),
            sequence: self.sequence.to_string(),
            governor: hex::encode(self.governor.as_bytes()),
            signing_key_state_head: hex::encode(self.signing_key_state_head),
            entries: self.entries.iter().map(wire_entry).collect(),
            signature: hex::encode(self.signature),
        };
        let bytes = crate::jcs::to_vec(&wire).map_err(NodeListError::Json)?;
        if bytes.len() > MAX_NODE_LIST_VALUE_LEN {
            return Err(NodeListError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// Reads a record from its canonical JSON and refuses any other spelling
    /// of it: the bytes must equal the canonical JSON of the record they
    /// parse to. This checks the form only; [`Self::verify`] checks the
    /// signature.
    ///
    /// # Errors
    ///
    /// [`NodeListError`] for oversized input, a parse failure, a bad member,
    /// a zero sequence or an empty `context_id`, or a non-canonical spelling.
    pub fn from_canonical_json(bytes: &[u8]) -> Result<Self, NodeListError> {
        if bytes.len() > MAX_NODE_LIST_VALUE_LEN {
            return Err(NodeListError::TooLarge(bytes.len()));
        }
        let wire: WireRecord =
            serde_json::from_slice(bytes).map_err(|e| NodeListError::Json(e.to_string()))?;
        if wire.context_id.is_empty() {
            return Err(NodeListError::EmptyContextId);
        }
        let sequence: u64 = wire
            .sequence
            .parse()
            .map_err(|_| NodeListError::BadSequence)?;
        if sequence == 0 {
            return Err(NodeListError::ZeroSequence);
        }
        let record = Self {
            context_id: wire.context_id,
            sequence,
            governor: Identifier::from_bytes(from_hex("governor", &wire.governor)?),
            signing_key_state_head: from_hex(
                "signing_key_state_head",
                &wire.signing_key_state_head,
            )?,
            entries: wire
                .entries
                .into_iter()
                .map(entry_from_wire)
                .collect::<Result<_, _>>()?,
            signature: from_hex("signature", &wire.signature)?,
        };
        if record.to_canonical_json()? != bytes {
            return Err(NodeListError::NotCanonical);
        }
        Ok(record)
    }
}

/// Why a node-list frame, or a PUBLISH carrying one, is refused (§9.10.12).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NodeListFrameError {
    /// The first byte is not `0x06`; it is read before any other byte.
    #[error("node-list frame version {0}, expected 6")]
    WrongVersion(u8),
    /// The frame is shorter than its 33-byte fixed prefix.
    #[error("node-list frame is {0} bytes, shorter than the 33-byte prefix")]
    TooShort(usize),
    /// `value` is longer than `Max blob size − 33`.
    #[error("node-list frame value is {0} bytes, more than 262111")]
    ValueTooLarge(usize),
    /// `value` is not the canonical JSON of a `NodeListRecord`.
    #[error("node-list frame value: {0}")]
    Record(#[from] NodeListError),
    /// The frame's `governor` differs from the record's.
    #[error("node-list frame governor differs from the record's governor")]
    GovernorMismatch,
    /// A PUBLISH at `scp:nls:` without `retain`.
    #[error("node-list PUBLISH does not set retain")]
    RetainMissing,
    /// A PUBLISH carrying both `retain` and `blob_ttl`.
    #[error("node-list PUBLISH carries both retain and blob_ttl")]
    RetainWithTtl,
    /// The PUBLISH routing id is not `SHA-256("scp:nls:" ‖ context_id)` over
    /// the record's `context_id`.
    #[error("node-list PUBLISH routing id does not derive from the record's context_id")]
    RoutingIdMismatch,
}

/// The frame bytes: `0x06 ‖ governor ‖ canonical JSON`.
///
/// # Errors
///
/// [`NodeListFrameError::Record`] when the record does not encode or exceeds
/// a frame's `value`.
pub fn encode_node_list_frame(record: &NodeListRecord) -> Result<Vec<u8>, NodeListFrameError> {
    let value = record.to_canonical_json()?;
    let mut out = Vec::with_capacity(NODE_LIST_FRAME_PREFIX_LEN + value.len());
    out.push(NODE_LIST_FRAME_VERSION);
    out.extend_from_slice(record.governor.as_bytes());
    out.extend_from_slice(&value);
    Ok(out)
}

/// Decodes a frame under §9.10.12's rules.
///
/// The rules run in order: version first, then the 33-byte prefix, the `value` bound, the canonical record JSON, and the
/// `governor` agreement. The record's signature is not checked here.
///
/// # Errors
///
/// [`NodeListFrameError`] names the first rule the bytes break.
pub fn decode_node_list_frame(bytes: &[u8]) -> Result<NodeListRecord, NodeListFrameError> {
    match bytes.first() {
        Some(&NODE_LIST_FRAME_VERSION) => {}
        Some(&other) => return Err(NodeListFrameError::WrongVersion(other)),
        None => return Err(NodeListFrameError::TooShort(0)),
    }
    if bytes.len() < NODE_LIST_FRAME_PREFIX_LEN {
        return Err(NodeListFrameError::TooShort(bytes.len()));
    }
    let (prefix, value) = bytes.split_at(NODE_LIST_FRAME_PREFIX_LEN);
    if value.len() > MAX_NODE_LIST_VALUE_LEN {
        return Err(NodeListFrameError::ValueTooLarge(value.len()));
    }
    let record = NodeListRecord::from_canonical_json(value)?;
    if prefix[1..] != record.governor.as_bytes()[..] {
        return Err(NodeListFrameError::GovernorMismatch);
    }
    Ok(record)
}

/// The structural admission of a PUBLISH at a `scp:nls:` routing id (§9.10.12).
///
/// It checks that `retain` is set, `blob_ttl` is absent, the blob decodes as a
/// node-list frame, and `routing_id` derives from the record's `context_id`.
///
/// The node's remaining admission step, the governor signature under the
/// `#active` at `signing_key_state_head` in the governor key state the node
/// holds, reads key state this function does not hold; the caller runs
/// [`NodeListRecord::verify`] on the returned record.
///
/// # Errors
///
/// [`NodeListFrameError`] names the first rule the PUBLISH breaks.
pub fn check_node_list_publish(
    routing_id: &[u8; 32],
    retain: bool,
    blob_ttl: Option<u32>,
    blob: &[u8],
) -> Result<NodeListRecord, NodeListFrameError> {
    if !retain {
        return Err(NodeListFrameError::RetainMissing);
    }
    if blob_ttl.is_some() {
        return Err(NodeListFrameError::RetainWithTtl);
    }
    let record = decode_node_list_frame(blob)?;
    if node_list_routing_id(&record.context_id) != *routing_id {
        return Err(NodeListFrameError::RoutingIdMismatch);
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use scp_crypto::p256::{P256SecretKey, sign_prehash_rfc6979};

    use super::super::binding::tests::{key, signed_binding};
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn entry(node_seed: u8, url: &str, free: bool) -> TestResult<NodeListEntry> {
        let url = NodeUrl::new(url)?;
        Ok(NodeListEntry {
            binding: signed_binding(&key(1), &key(node_seed), &url)?,
            url,
            free,
        })
    }

    fn signed_record(governor_key: &P256SecretKey) -> TestResult<NodeListRecord> {
        let entries = vec![
            entry(2, "wss://a.example.com/scp/v1", true)?,
            entry(3, "wss://b.example.com/scp/v1", false)?,
        ];
        let governor = Identifier::from_bytes([0x33; 32]);
        let head = [0x44; 32];
        let digest = NodeListRecord::signing_digest("node-list", 1, &governor, &head, &entries)?;
        Ok(NodeListRecord {
            context_id: "node-list".to_owned(),
            sequence: 1,
            governor,
            signing_key_state_head: head,
            entries,
            signature: sign_prehash_rfc6979(governor_key, &digest)?,
        })
    }

    #[test]
    fn a_record_round_trips_through_canonical_json_and_verifies() -> TestResult {
        let governor = key(9);
        let record = signed_record(&governor)?;
        let json = record.to_canonical_json()?;
        let back = NodeListRecord::from_canonical_json(&json)?;
        assert_eq!(back, record);
        assert_eq!(back.verify(&governor.public_key()), Ok(()));
        for entry in &back.entries {
            assert_eq!(entry.verify(&key(1).public_key()), Ok(()));
        }
        let text = std::str::from_utf8(&json)?;
        assert!(text.starts_with(r#"{"context_id":"node-list","entries":[{"binding":{"#));
        assert!(text.contains(r#""sequence":"1""#));
        Ok(())
    }

    #[test]
    fn the_preimage_carries_the_context_id_length() -> TestResult {
        let record = signed_record(&key(9))?;
        let entries_digest: [u8; 32] =
            Sha256::digest(entries_canonical_json(&record.entries)?).into();
        let mut preimage = b"SCP-NODE-LIST-V1:".to_vec();
        preimage.extend_from_slice(&9u32.to_be_bytes());
        preimage.extend_from_slice(b"node-list");
        preimage.extend_from_slice(&1u64.to_be_bytes());
        preimage.extend_from_slice(&[0x33; 32]);
        preimage.extend_from_slice(&[0x44; 32]);
        preimage.extend_from_slice(&entries_digest);
        let expected: [u8; 32] = Sha256::digest(&preimage).into();
        assert_eq!(record.digest()?, expected);
        Ok(())
    }

    /// A change to each of the five signed fields, and to the signature,
    /// makes the governor signature refused.
    #[test]
    fn a_change_in_each_record_field_is_refused() -> TestResult {
        let governor = key(9);
        let active = governor.public_key();
        let good = signed_record(&governor)?;
        let refused =
            |r: &NodeListRecord| matches!(r.verify(&active), Err(NodeListError::Signature(_)));

        let mut r = good.clone();
        r.context_id.push('x');
        assert!(refused(&r), "context_id");

        let mut r = good.clone();
        r.sequence = 2;
        assert!(refused(&r), "sequence");

        let mut r = good.clone();
        let mut g = *r.governor.as_bytes();
        g[0] ^= 1;
        r.governor = Identifier::from_bytes(g);
        assert!(refused(&r), "governor");

        let mut r = good.clone();
        r.signing_key_state_head[0] ^= 1;
        assert!(refused(&r), "signing_key_state_head");

        let mut r = good.clone();
        r.entries[1].free = true;
        assert!(refused(&r), "entries");

        let mut r = good.clone();
        r.entries.swap(0, 1);
        assert!(refused(&r), "entry order");

        let mut r = good;
        r.signature[3] ^= 1;
        assert!(refused(&r), "signature");
        Ok(())
    }

    #[test]
    fn an_entry_listed_under_another_url_is_refused() -> TestResult {
        let mut e = entry(2, "wss://a.example.com/scp/v1", true)?;
        e.url = NodeUrl::new("wss://c.example.com/scp/v1")?;
        assert_eq!(
            e.verify(&key(1).public_key()),
            Err(NodeBindingError::UrlHashMismatch)
        );
        Ok(())
    }

    #[test]
    fn a_non_canonical_spelling_is_refused() -> TestResult {
        let json = signed_record(&key(9))?.to_canonical_json()?;
        let text = String::from_utf8(json)?;

        let spaced = text.replacen(':', ": ", 1);
        assert_eq!(
            NodeListRecord::from_canonical_json(spaced.as_bytes()),
            Err(NodeListError::NotCanonical)
        );
        let upper = text.replacen(r#""governor":"33"#, r#""governor":"3A"#, 1);
        assert!(NodeListRecord::from_canonical_json(upper.as_bytes()).is_err());
        let padded = text.replacen(r#""sequence":"1""#, r#""sequence":"01""#, 1);
        assert_eq!(
            NodeListRecord::from_canonical_json(padded.as_bytes()),
            Err(NodeListError::NotCanonical)
        );
        let numeric = text.replacen(r#""sequence":"1""#, r#""sequence":1"#, 1);
        assert!(matches!(
            NodeListRecord::from_canonical_json(numeric.as_bytes()),
            Err(NodeListError::Json(_))
        ));
        let zero = text.replacen(r#""sequence":"1""#, r#""sequence":"0""#, 1);
        assert_eq!(
            NodeListRecord::from_canonical_json(zero.as_bytes()),
            Err(NodeListError::ZeroSequence)
        );
        let extra = text.replacen('{', r#"{"a":1,"#, 1);
        assert!(matches!(
            NodeListRecord::from_canonical_json(extra.as_bytes()),
            Err(NodeListError::Json(_))
        ));
        Ok(())
    }

    #[test]
    fn a_sequence_above_two_to_the_53_round_trips() -> TestResult {
        let governor = key(9);
        let mut record = signed_record(&governor)?;
        record.sequence = u64::MAX;
        let json = record.to_canonical_json()?;
        assert_eq!(NodeListRecord::from_canonical_json(&json)?, record);
        Ok(())
    }

    // §9.10.12's rules for the 0x06 frame and its PUBLISH, one test each.

    fn frame() -> TestResult<(NodeListRecord, Vec<u8>)> {
        let record = signed_record(&key(9))?;
        let bytes = encode_node_list_frame(&record)?;
        Ok((record, bytes))
    }

    #[test]
    fn frame_round_trips() -> TestResult {
        let (record, bytes) = frame()?;
        assert_eq!(bytes[0], 6);
        assert_eq!(&bytes[1..33], record.governor.as_bytes());
        assert_eq!(decode_node_list_frame(&bytes)?, record);
        Ok(())
    }

    #[test]
    fn frame_rule_version_is_read_first() -> TestResult {
        let (_, mut bytes) = frame()?;
        bytes[0] = 0x02;
        assert_eq!(
            decode_node_list_frame(&bytes),
            Err(NodeListFrameError::WrongVersion(2))
        );
        // A one-byte frame of the wrong version fails on its version.
        assert_eq!(
            decode_node_list_frame(&[0x05]),
            Err(NodeListFrameError::WrongVersion(5))
        );
        Ok(())
    }

    #[test]
    fn frame_rule_shorter_than_the_prefix() -> TestResult {
        let (_, bytes) = frame()?;
        assert_eq!(
            decode_node_list_frame(&bytes[..32]),
            Err(NodeListFrameError::TooShort(32))
        );
        assert_eq!(
            decode_node_list_frame(&[]),
            Err(NodeListFrameError::TooShort(0))
        );
        Ok(())
    }

    #[test]
    fn frame_rule_value_longer_than_max_blob_size_minus_33() {
        let mut bytes = vec![6u8; MAX_BLOB_SIZE + 1];
        bytes[1..33].fill(0x33);
        assert_eq!(
            decode_node_list_frame(&bytes),
            Err(NodeListFrameError::ValueTooLarge(MAX_BLOB_SIZE + 1 - 33))
        );
    }

    #[test]
    fn frame_rule_value_is_not_canonical_record_json() -> TestResult {
        let (_, bytes) = frame()?;
        let mut spaced = bytes[..33].to_vec();
        spaced.extend_from_slice(b" ");
        spaced.extend_from_slice(&bytes[33..]);
        assert_eq!(
            decode_node_list_frame(&spaced),
            Err(NodeListFrameError::Record(NodeListError::NotCanonical))
        );
        assert!(matches!(
            decode_node_list_frame(&bytes[..33]),
            Err(NodeListFrameError::Record(NodeListError::Json(_)))
        ));
        Ok(())
    }

    #[test]
    fn frame_rule_governor_differs_from_the_json() -> TestResult {
        let (_, mut bytes) = frame()?;
        bytes[1] ^= 1;
        assert_eq!(
            decode_node_list_frame(&bytes),
            Err(NodeListFrameError::GovernorMismatch)
        );
        Ok(())
    }

    #[test]
    fn publish_rule_retain_is_required() -> TestResult {
        let (record, bytes) = frame()?;
        let routing = node_list_routing_id(&record.context_id);
        assert_eq!(
            check_node_list_publish(&routing, false, None, &bytes),
            Err(NodeListFrameError::RetainMissing)
        );
        assert_eq!(
            check_node_list_publish(&routing, true, None, &bytes)?,
            record
        );
        Ok(())
    }

    #[test]
    fn publish_rule_retain_with_blob_ttl_is_refused() -> TestResult {
        let (record, bytes) = frame()?;
        let routing = node_list_routing_id(&record.context_id);
        assert_eq!(
            check_node_list_publish(&routing, true, Some(60), &bytes),
            Err(NodeListFrameError::RetainWithTtl)
        );
        Ok(())
    }

    #[test]
    fn publish_rule_routing_id_derives_from_the_context_id() -> TestResult {
        let (_, bytes) = frame()?;
        assert_eq!(
            check_node_list_publish(&node_list_routing_id("other"), true, None, &bytes),
            Err(NodeListFrameError::RoutingIdMismatch)
        );
        Ok(())
    }
}
