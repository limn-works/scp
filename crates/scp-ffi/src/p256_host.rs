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
//! object straight from the wiped buffer. `p256_pseudonym_scalar` returns the
//! scalar as a `bytearray`, the one secret a host keeps, so the host can wipe
//! it when it destroys the key. The inputs accept `bytes` or `bytearray`; a
//! host that must wipe an input passes a `bytearray` and clears it.

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
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

/// Maps a 32-byte §9.10.4 `context_seed` (v1 or v2) to its P-256 pseudonym
/// scalar in `[1, n − 1]`.
///
/// FIPS 186-5 A.2.1, §9.10.4:
/// `HKDF-Expand(context_seed, b"SCP-PSEUDONYM-P256-V1", 48) mod (n − 1) + 1`,
/// with the label fixed inside the helper. Returns the 32-byte big-endian
/// scalar as a `bytearray`, which the host wipes when it destroys the key.
///
/// # Errors
///
/// `SCP-VALID-7005` when `context_seed` is not 32 bytes; `SCP-CRYPTO-4001` if
/// the reduction fails (unreachable for a 32-byte seed).
#[pyfunction]
#[pyo3(name = "p256_pseudonym_scalar")]
pub fn py_p256_pseudonym_scalar(
    py: Python<'_>,
    context_seed: Vec<u8>,
) -> PyResult<Bound<'_, PyByteArray>> {
    let context_seed = Zeroizing::new(context_seed);
    let scalar = shared::p256_pseudonym_scalar(&context_seed).map_err(py_error)?;
    Ok(PyByteArray::new(py, scalar.as_slice()))
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

/// The compressed pseudonym point of a §9.10.4 `context_seed`.
///
/// The 33-byte SEC1 point of a 32-byte `context_seed` (v1 or v2), for a
/// host that computes the seed itself. No
/// scalar reaches the host.
///
/// # Errors
///
/// `SCP-VALID-7005` when `context_seed` is not 32 bytes.
#[pyfunction]
#[pyo3(name = "p256_pseudonym_point")]
pub fn py_p256_pseudonym_point(
    py: Python<'_>,
    context_seed: Vec<u8>,
) -> PyResult<Bound<'_, PyBytes>> {
    let context_seed = Zeroizing::new(context_seed);
    let point = shared::p256_pseudonym_point(&context_seed).map_err(py_error)?;
    Ok(PyBytes::new(py, &point))
}

/// The compressed pseudonym point a software custody derives (§9.10.4.A).
///
/// From the 32-byte identity key material `ikm`: the v1 point for
/// `context_id` when `epoch` is `None`, the v2 point at `epoch` otherwise. No
/// scalar reaches the host.
///
/// # Errors
///
/// `SCP-VALID-7005` when `ikm` is not 32 bytes; `OverflowError` (raised by
/// `PyO3`) when `epoch` is negative or wider than 64 bits.
#[pyfunction]
#[pyo3(name = "p256_software_pseudonym_point", signature = (ikm, context_id, epoch = None))]
pub fn py_p256_software_pseudonym_point(
    py: Python<'_>,
    ikm: Vec<u8>,
    context_id: Vec<u8>,
    epoch: Option<u64>,
) -> PyResult<Bound<'_, PyBytes>> {
    let ikm = Zeroizing::new(ikm);
    let point =
        shared::p256_software_pseudonym_point(&ikm, &context_id, epoch).map_err(py_error)?;
    Ok(PyBytes::new(py, &point))
}

/// Registers the P-256 host helpers on the `_scp_core` module.
///
/// # Errors
///
/// Returns a `PyErr` if a function cannot be added to the module.
pub fn register_p256_host(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(py_p256_pseudonym_scalar, m)?)?;
    m.add_function(wrap_pyfunction!(py_p256_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(py_p256_sign_prehash_rfc6979, m)?)?;
    m.add_function(wrap_pyfunction!(py_p256_pseudonym_point, m)?)?;
    m.add_function(wrap_pyfunction!(py_p256_software_pseudonym_point, m)?)?;
    Ok(())
}
