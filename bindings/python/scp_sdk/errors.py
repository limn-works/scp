"""SCP exception hierarchy.

All SCP SDK exceptions are rooted at :class:`ScpError`. Each subclass
corresponds to a specific error domain and carries a human-readable
``message`` and a machine-readable ``code`` following the format
``SCP-{CATEGORY}-{NUMBER}`` (see ``.docs/standards/sdk-common.md``).

Exception hierarchy::

    ScpError (root)
    +-- IdentityError         -- DID creation, resolution, key rotation
    +-- ContextError          -- Context lifecycle (create, join, leave, close)
    +-- UcanPermissionError   -- UCAN capability validation
    +-- CryptoError           -- Encryption, decryption, signature
    +-- TransportError        -- Network, relay, connection
    +-- OutletError           -- Outlet registration, invocation, verification
    |   +-- OutletNotFoundError
    |   +-- OutletExecutionError
    +-- ValidationError       -- Input validation, schema, parameters

Note: The permission error is named ``UcanPermissionError`` to avoid
shadowing Python's built-in ``PermissionError``.

The error-code prefix ``SCP-TOOL-*`` is retained per §9.18 — error codes
are a registered namespace and renames would invalidate every logged
error and every error-code assertion in downstream consumers. Only the
class names use outlet vocabulary; the wire codes remain ``SCP-TOOL-*``.
"""

from __future__ import annotations


class ScpError(Exception):
    """Base exception for all SCP errors.

    Attributes:
        message: Human-readable description of the error.
        code: Machine-readable error code (format: ``SCP-{CATEGORY}-{NUMBER}``).
    """

    _default_code: str = "SCP-UNKNOWN-0000"

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
    """UCAN capability validation failure."""

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


class OutletError(ScpError):
    """Outlet registration, invocation, or verification failure.

    Error-code prefix remains ``SCP-TOOL-*`` — the wire namespace is a
    registered identifier (§9.18) and the rename is vocabulary-only at
    the class level.
    """

    _default_code: str = "SCP-TOOL-6000"


class OutletNotFoundError(OutletError):
    """Referenced outlet does not exist in the context's registry."""

    _default_code: str = "SCP-TOOL-6100"


class OutletExecutionError(OutletError):
    """Outlet invocation failed during execution."""

    _default_code: str = "SCP-TOOL-6200"


class ValidationError(ScpError):
    """Input validation failure (schema, parameters)."""

    _default_code: str = "SCP-VALID-7000"


# ---------------------------------------------------------------------------
# Mapping from bridge error variant names to SDK exceptions.
# ---------------------------------------------------------------------------

BRIDGE_ERROR_MAP: dict[str, type[ScpError]] = {
    "IdentityError": IdentityError,
    "ContextError": ContextError,
    "UcanError": UcanPermissionError,
    "CryptoError": CryptoError,
    "TransportError": TransportError,
    "ToolError": OutletError,
    "OutletError": OutletError,
    "ValidationError": ValidationError,
}


__all__ = [
    "BRIDGE_ERROR_MAP",
    "ContextError",
    "CryptoError",
    "IdentityError",
    "OutletError",
    "OutletExecutionError",
    "OutletNotFoundError",
    "ScpError",
    "TransportError",
    "UcanPermissionError",
    "ValidationError",
]
