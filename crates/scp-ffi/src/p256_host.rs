//! P-256 primitives a Python custody host calls so that it does not
//! re-implement the §9.10.4 scalar reduction or the §9.5 nonce.
//!
//! Each export wraps the function of the same name in
//! `scp_ffi_common::p256_host`, as the napi-rs and `UniFFI` exports do, so
//! the argument order, the checks and the error codes (`SCP-VALID-7005` for
//! a wrong length, `SCP-CRYPTO-4001` for an out-of-range scalar or a failed
//! reduction or signature) are the same in every binding.
//!
//! Wiping is best-effort: the Rust side wipes the seed and scalar `Vec`s it
//! extracts and its own copies (`Zeroizing`), and builds each returned
//! `bytes` straight from the wiped buffer. Python `bytes` are immutable and
//! never wiped; a host that must wipe passes a `bytearray` and clears it.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use scp_ffi_common::p256_host::{self as shared, P256HostError};
use zeroize::Zeroizing;

use crate::error::ScpPyError;

fn py_error(e: P256HostError) -> PyErr {
    let code = e.code().to_owned();
    PyErr::from(match e {
        P256HostError::Validation(message) => ScpPyError::ValidationError { message, code },
        P256HostError::Crypto(message) => ScpPyError::CryptoError { message, code },
    })
}

/// Maps a 32-byte seed to a P-256 private scalar in `[1, n − 1]` under `label`.
///
/// FIPS 186-5 A.2.1, §9.10.4: `HKDF-Expand(seed, label, 48) mod (n − 1) + 1`.
/// Returns the 32-byte big-endian scalar. For a pseudonym the label is
/// `b"SCP-PSEUDONYM-P256-V1"` and the seed the §9.10.4 `context_seed`.
///
/// # Errors
///
/// `SCP-VALID-7005` when `seed` is not 32 bytes; `SCP-CRYPTO-4001` if the
/// reduction fails (unreachable for a 32-byte seed).
#[pyfunction]
#[pyo3(name = "p256_seed_to_scalar")]
pub fn py_p256_seed_to_scalar(
    py: Python<'_>,
    label: Vec<u8>,
    seed: Vec<u8>,
) -> PyResult<Bound<'_, PyBytes>> {
    let seed = Zeroizing::new(seed);
    let scalar = shared::p256_seed_to_scalar(&label, &seed).map_err(py_error)?;
    Ok(PyBytes::new(py, scalar.as_slice()))
}

/// The 33-byte SEC1 compressed public key `d·G` of a 32-byte scalar.
///
/// # Errors
///
/// `SCP-VALID-7005` when `scalar` is not 32 bytes; `SCP-CRYPTO-4001` when it
/// is zero or not below `n`.
#[pyfunction]
#[pyo3(name = "p256_public_key")]
pub fn py_p256_public_key(py: Python<'_>, scalar: Vec<u8>) -> PyResult<Bound<'_, PyBytes>> {
    let scalar = Zeroizing::new(scalar);
    let point = shared::p256_public_key(&scalar).map_err(py_error)?;
    Ok(PyBytes::new(py, &point))
}

/// Signs a 32-byte digest with the scalar: RFC 6979 deterministic nonce
/// (`h1 = digest`), low-`s` normalized, returned as the 64-byte `r || s`
/// (§9.5).
///
/// # Errors
///
/// `SCP-VALID-7005` when `scalar` or `digest` is not 32 bytes;
/// `SCP-CRYPTO-4001` when the scalar is out of range or signing fails.
#[pyfunction]
#[pyo3(name = "p256_sign_prehash_rfc6979")]
pub fn py_p256_sign_prehash_rfc6979(
    py: Python<'_>,
    scalar: Vec<u8>,
    digest: Vec<u8>,
) -> PyResult<Bound<'_, PyBytes>> {
    let scalar = Zeroizing::new(scalar);
    let sig = shared::p256_sign_prehash_rfc6979(&scalar, &digest).map_err(py_error)?;
    Ok(PyBytes::new(py, &sig))
}

/// Registers the P-256 host helpers on the `_scp_core` module.
///
/// # Errors
///
/// Returns a `PyErr` if a function cannot be added to the module.
pub fn register_p256_host(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_p256_seed_to_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(py_p256_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_p256_sign_prehash_rfc6979, m)?)?;
    Ok(())
}
