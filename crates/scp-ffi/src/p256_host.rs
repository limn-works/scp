//! P-256 pseudonym point helpers a Python custody host calls so that it does
//! not re-implement the §9.10.4 derivation (§9.10.4.A).
//!
//! Each export wraps the function of the same name in
//! `scp_ffi_common::p256_host`, as the napi-rs and `UniFFI` exports do, so
//! the argument order, the checks and the error code (`SCP-VALID-7005` for a
//! wrong length) are the same in every binding. Each returns the 33-byte
//! compressed point as `bytes`: no scalar reaches the host.
//!
//! Wiping is best-effort: the Rust side wipes the seed and `ikm` `Vec`s it
//! extracts (`Zeroizing`). The inputs accept `bytes` or `bytearray`; a host
//! that must wipe an input passes a `bytearray` and clears it.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use scp_ffi_common::p256_host::{self as shared, P256HostError};
use zeroize::Zeroizing;

use crate::error::ScpPyError;

fn py_error(e: P256HostError) -> PyErr {
    let code = e.code().to_owned();
    PyErr::from(match e {
        P256HostError::Validation(message) => ScpPyError::ValidationError { message, code },
    })
}

/// The compressed pseudonym point of a §9.10.4 `context_seed`.
///
/// The 33-byte SEC1 point of a 32-byte `context_seed` (v1 or v2), for a
/// host that computes the seed itself. No scalar reaches the host.
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
    m.add_function(wrap_pyfunction!(py_p256_pseudonym_point, m)?)?;
    m.add_function(wrap_pyfunction!(py_p256_software_pseudonym_point, m)?)?;
    Ok(())
}
