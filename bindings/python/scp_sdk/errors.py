"""SCP exception hierarchy.

All SCP SDK exceptions are rooted at :class:`ScpError`. Each subclass
corresponds to a specific error domain and carries a human-readable
``message`` and a machine-readable ``code`` following the format
``SCP-{CATEGORY}-{NUMBER}`` (see ``.docs/standards/sdk-common.md``).

The hierarchy wraps bridge-level ``ScpPyError`` variants from the
``_scp_core`` PyO3 extension when available, adding Pythonic ergonomics
and additional context.

Exception hierarchy::

    ScpError (root)
    +-- IdentityError         -- DID creation, resolution, key rotation
    +-- ContextError          -- Context lifecycle (create, join, leave, close)
    +-- UcanPermissionError   -- UCAN capability validation
    +-- CryptoError           -- Encryption, decryption, signature
    +-- TransportError        -- Network, relay, connection
    +-- ToolError             -- Tool registration, invocation, verification
    +-- ValidationError       -- Input validation, schema, parameters

Note: The permission error is named ``UcanPermissionError`` to avoid
shadowing Python's built-in ``PermissionError``.
"""

from __future__ import annotations


class ScpError(Exception):
    """Base exception for all SCP errors.

    Attributes:
        message: Human-readable description of the error.
        code: Machine-readable error code (format: ``SCP-{CATEGORY}-{NUMBER}``).
    """

    #: Default error code for the base class.
    _default_code: str = "SCP-ERR-0000"

    def __init__(self, message: str, code: str | None = None) -> None:
        self.message = message
        self.code = code if code is not None else self._default_code
        super().__init__(self.message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(message={self.message!r}, code={self.code!r})"

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class IdentityError(ScpError):
    """Identity creation, resolution, or key management failure."""

    _default_code: str = "SCP-IDENT-1000"


class ContextError(ScpError):
    """Context lifecycle errors (create, join, leave, close)."""

    _default_code: str = "SCP-CTX-2000"


class UcanPermissionError(ScpError):
    """UCAN capability validation failure.

    Named ``UcanPermissionError`` instead of ``PermissionError`` to avoid
    shadowing Python's built-in ``PermissionError``.
    """

    _default_code: str = "SCP-PERM-3000"


class CryptoError(ScpError):
    """Encryption, decryption, or signature failure.

    Error messages from this class never leak key material or internal
    crypto state.
    """

    _default_code: str = "SCP-CRYPTO-4000"


class TransportError(ScpError):
    """Network or relay communication failure."""

    _default_code: str = "SCP-TRANS-5000"


class ToolError(ScpError):
    """Tool registration, invocation, or verification failure."""

    _default_code: str = "SCP-TOOL-6000"


class ValidationError(ScpError):
    """Input validation failure (schema, parameters)."""

    _default_code: str = "SCP-VALID-7000"


# ---------------------------------------------------------------------------
# Mapping from bridge error variant names to SDK exceptions.
# ---------------------------------------------------------------------------

#: Maps ``ScpPyError`` variant names (from ``_scp_core``) to SDK exception
#: classes.  Used by bridge integration code to translate Rust-side errors
#: into the correct Python exception.
BRIDGE_ERROR_MAP: dict[str, type[ScpError]] = {
    "IdentityError": IdentityError,
    "ContextError": ContextError,
    "UcanError": UcanPermissionError,
    "CryptoError": CryptoError,
    "TransportError": TransportError,
    "ToolError": ToolError,
    "ValidationError": ValidationError,
}


__all__ = [
    "ScpError",
    "IdentityError",
    "ContextError",
    "UcanPermissionError",
    "CryptoError",
    "TransportError",
    "ToolError",
    "ValidationError",
    "BRIDGE_ERROR_MAP",
]
