"""Tests for the :mod:`scp_sdk.errors` exception hierarchy.

These are SDK-layer-only tests: they construct exception instances directly
and assert that the ``.code`` attribute round-trips unchanged. The goal is
to pin the contract that the Python SDK wrapper does NOT strip, rewrite,
or normalize the structured error code emitted by the PyO3 bridge.

The PyO3 bridge maps each ``PreRotationCustodyError`` variant to a typed
``IDENT_1047`` / ``IDENT_1048`` / ``IDENT_1049`` / ``IDENT_1050`` /
``IDENT_1051`` / ``IDENT_1052`` code (see the regression tests in
``crates/scp-ffi/src/error.rs``). The matching NAPI and UniFFI bridges
have byte-identical mappings (with their own co-located tests). These
tests verify that the Python SDK's :class:`IdentityError` class
preserves whichever code the bridge emits.

The constants are also referenced as string literals below so any future
rename of the bridge-layer code (e.g., a re-numbering) breaks here, not
at runtime inside a caller's ``except`` clause.
"""

from __future__ import annotations

import pytest

from scp_sdk.errors import (
    ContextError,
    CryptoError,
    IdentityError,
    ScpError,
    ToolError,
    TransportError,
    UcanPermissionError,
    ValidationError,
)

# ---------------------------------------------------------------------------
# Pre-rotation custody typed codes — one literal per bridge variant.
#
# These constants pin the wire-format contract. The PyO3 bridge generates
# them via the matching ``codes::IDENT_xxxx`` constants in
# ``crates/scp-ffi/src/error.rs``. If the bridge ever renames or
# re-numbers a code, this file must be updated in lockstep — that update
# is the canary that catches the SDK-layer fall-through bug.
# ---------------------------------------------------------------------------
PRE_ROTATION_HANDLE_NOT_FOUND_CODE = "SCP-IDENT-1047"
PRE_ROTATION_UNAVAILABLE_CODE = "SCP-IDENT-1048"
PRE_ROTATION_USER_DECLINED_CODE = "SCP-IDENT-1049"
PRE_ROTATION_STORAGE_CODE = "SCP-IDENT-1050"
PRE_ROTATION_INVALID_CALLBACK_CODE = "SCP-IDENT-1051"
PRE_ROTATION_COMMITMENT_MISMATCH_CODE = "SCP-IDENT-1052"
IDENTITY_GENERIC_CODE = "SCP-IDENT-1001"


class TestIdentityErrorCodePreservation:
    """Pin the SDK contract that ``IdentityError.code`` is never rewritten.

    Constructs each pre-rotation-typed error directly and verifies that
    the ``.code`` attribute round-trips through the SDK exception class
    unchanged. Mirrors the seven Rust-side regression tests at
    ``crates/scp-ffi/src/error.rs:697``.
    """

    @pytest.mark.parametrize(
        "code",
        [
            PRE_ROTATION_HANDLE_NOT_FOUND_CODE,
            PRE_ROTATION_UNAVAILABLE_CODE,
            PRE_ROTATION_USER_DECLINED_CODE,
            PRE_ROTATION_STORAGE_CODE,
            PRE_ROTATION_INVALID_CALLBACK_CODE,
            PRE_ROTATION_COMMITMENT_MISMATCH_CODE,
            IDENTITY_GENERIC_CODE,
        ],
    )
    def test_identity_error_preserves_code(self, code: str) -> None:
        """``IdentityError(msg, code)`` MUST surface ``.code == code``.

        The PyO3 bridge raises ``IdentityError`` with a precise typed
        code. The SDK wrapper must propagate that code verbatim — never
        rewrite, normalize, or strip it. A caller's ``except`` clause
        relies on ``.code`` to distinguish handle-not-found from
        commitment-mismatch (or any other pre-rotation failure mode)
        without string-matching the message body.
        """
        err = IdentityError("pre-rotation failure", code)
        assert err.code == code
        assert err.message == "pre-rotation failure"

    def test_identity_error_is_scperror_subclass(self) -> None:
        """``IdentityError`` MUST be catchable as a base ``ScpError``."""
        err = IdentityError("oops", PRE_ROTATION_HANDLE_NOT_FOUND_CODE)
        assert isinstance(err, ScpError)
        assert isinstance(err, IdentityError)

    def test_identity_error_str_includes_code(self) -> None:
        """``str(err)`` MUST include the bracketed code so log scrapers
        and ``assert ... in str(err)`` patterns can detect the typed
        variant without instance-checking.
        """
        err = IdentityError("pre-rotation failure", PRE_ROTATION_STORAGE_CODE)
        rendered = str(err)
        assert PRE_ROTATION_STORAGE_CODE in rendered
        assert "pre-rotation failure" in rendered

    def test_identity_error_default_code_when_omitted(self) -> None:
        """If a caller constructs ``IdentityError`` without an explicit
        code, the class-level default applies. Pinning this guards
        against accidental refactors that would silently change the
        fallback.
        """
        err = IdentityError("no code provided")
        assert err.code == "SCP-IDENT-1000"


class TestSiblingErrorClassCodePreservation:
    """Sibling exception classes must follow the same ``.code`` contract.

    Defense-in-depth: the bug would also be a bug for
    :class:`ContextError`, :class:`CryptoError`, etc. — pin them too so
    a regression in the base class is caught by multiple tests.
    """

    @pytest.mark.parametrize(
        ("cls", "code"),
        [
            (ContextError, "SCP-CTX-2001"),
            (UcanPermissionError, "SCP-PERM-3001"),
            (CryptoError, "SCP-CRYPTO-4001"),
            (TransportError, "SCP-TRANS-5001"),
            (ToolError, "SCP-TOOL-6001"),
            (ValidationError, "SCP-VALID-7001"),
        ],
    )
    def test_sibling_classes_preserve_code(self, cls: type[ScpError], code: str) -> None:
        err = cls("failure", code)
        assert err.code == code
        assert isinstance(err, ScpError)
