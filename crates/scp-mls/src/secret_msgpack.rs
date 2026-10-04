//! `MessagePack` encoding for values that carry private key material.
//!
//! `rmp_serde::to_vec_named` starts from an empty `Vec` and grows it by
//! reallocation, and every buffer it abandons on the way is freed holding a
//! prefix of the encoding. In a shipped SCP artifact the wiping global
//! allocator zeroes each such buffer as it is freed (security model spec
//! §9.15, freed heap memory). In a Rust application that links this crate
//! without `scp-alloc` nothing does, and for a value that carries a private
//! key (the MLS signer, or a snapshot holding it and the provider's HPKE and
//! epoch secrets) those freed buffers are unwiped key copies, which the local
//! destruction of MLS state in §9.15 step 2 does not allow. [`encode_named`]
//! measures the encoding first, writes it once into a buffer allocated at
//! that exact size, and returns it in [`Zeroizing`], so exactly one buffer
//! ever holds the bytes and it is wiped when dropped, whichever global
//! allocator the application installs.
//!
//! That one-buffer guarantee covers the encodings SCP performs through this
//! function only. openmls's own `MemoryStorage`, the store inside every
//! [`crate::InMemoryMlsProvider`], encodes, copies, and decodes the secrets
//! it holds through `serde_json`; only the wiping global allocator wipes
//! those copies, and the [`crate::provider`] module lists what it does not
//! reach.
//!
//! # Precondition: every sequence and map has a known length
//!
//! The one-buffer guarantee holds only for bytes that no sequence or map of
//! unknown length encloses. A struct with a `#[serde(flatten)]` field, or any
//! `serialize_seq(None)` / `serialize_map(None)`, makes rmp-serde 1.3.1 encode
//! that compound's elements into a private growing `Vec`
//! (`UnknownLengthCompound`, `encode.rs:477-540`) and copy them out at the
//! end, so that `Vec` and every buffer it outgrew are freed outside the one
//! buffer whatever writer the caller passes, and only the wiping global
//! allocator wipes them. A secret must therefore never sit inside such a
//! compound. The signer, `ProviderSignerDump`, the scp-runtime crypto snapshot
//! and `ContextSnapshot`, and the scp-client persisted types derive no
//! `flatten` and write no unknown-length compound around their secret fields.

use serde::Serialize;
use zeroize::Zeroizing;

/// An `io::Write` that keeps no bytes and counts how many it was given.
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Encodes `value` as name-tagged `MessagePack` (the bytes
/// `rmp_serde::to_vec_named` produces) into one buffer that never reallocates.
///
/// `value` must give every sequence and map its length up front (no
/// `#[serde(flatten)]`, no `serialize_seq(None)`); otherwise rmp-serde copies
/// part of the encoding through its own growing buffer (see the module
/// precondition).
///
/// # Errors
///
/// Returns the `rmp_serde` encode error when `value` cannot be serialized, or
/// when the second pass does not produce exactly the byte count the first
/// pass measured.
pub fn encode_named<T: Serialize + ?Sized>(
    value: &T,
) -> Result<Zeroizing<Vec<u8>>, rmp_serde::encode::Error> {
    let mut counter = ByteCounter(0);
    rmp_serde::encode::write_named(&mut counter, value)?;
    encode_exact(value, counter.0)
}

/// Writes `value` into a zeroed buffer of exactly `len` bytes.
///
/// The writer is a `&mut [u8]`, which cannot grow: an encoding longer than
/// `len` fails with a write error instead of reallocating, and a shorter one
/// fails because bytes are left unwritten. Either way the buffer is wiped when
/// the `Zeroizing` drops on the error path.
fn encode_exact<T: Serialize + ?Sized>(
    value: &T,
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, rmp_serde::encode::Error> {
    let mut out = Zeroizing::new(vec![0u8; len]);
    let mut remaining: &mut [u8] = out.as_mut_slice();
    rmp_serde::encode::write_named(&mut remaining, value)?;
    if !remaining.is_empty() {
        return Err(rmp_serde::encode::Error::Syntax(format!(
            "secret encoding wrote {} of the {len} bytes it measured",
            len - remaining.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::group::SCP_CIPHERSUITE;
    use openmls_basic_credential::SignatureKeyPair;

    /// The signer's encoding lands in a buffer sized to it exactly: nothing
    /// was grown, so no earlier buffer holding part of the private key was
    /// freed. `to_vec_named` grows from empty and ends with spare capacity.
    /// The encoding matches `to_vec_named`'s byte for byte, so stored values
    /// decode unchanged.
    #[test]
    fn signer_encoding_fills_its_one_buffer_exactly() {
        let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm()).unwrap();
        let named = encode_named(&signer).unwrap();
        assert_eq!(named.capacity(), named.len());
        assert_eq!(*named, rmp_serde::to_vec_named(&signer).unwrap());
    }

    /// A buffer one byte short or one byte long is an error, never a grown or
    /// partly written buffer: the writer is a fixed slice, so the measured and
    /// written lengths must agree exactly.
    #[test]
    fn encoding_into_a_wrongly_sized_buffer_is_an_error() {
        let signer = SignatureKeyPair::new(SCP_CIPHERSUITE.signature_algorithm()).unwrap();
        let len = encode_named(&signer).unwrap().len();
        assert!(encode_exact(&signer, len - 1).is_err());
        assert!(matches!(
            encode_exact(&signer, len + 1),
            Err(rmp_serde::encode::Error::Syntax(_))
        ));
        assert_eq!(encode_exact(&signer, len).unwrap().len(), len);
    }
}
