"""SCP Python SDK -- Shareable Context Protocol.

This package provides Pythonic wrappers around the ``_scp_core`` PyO3
extension module, offering typed dataclasses, an exception hierarchy,
and shared enums for building agents and applications on top of SCP.

Usage::

    from scp_sdk import Message, ToolDefinition, ScpError

See ``.docs/adrs/phase-3.md`` ADR-014 for the full SDK design.
"""

from __future__ import annotations

from scp_sdk.errors import (
    BRIDGE_ERROR_MAP,
    ContextError,
    CryptoError,
    IdentityError,
    ScpError,
    ToolError,
    TransportError,
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.tools import TestVector, ToolDefinition
from scp_sdk.types import (
    Capability,
    DiscoveryMethod,
    MemoryScope,
    Message,
    Provenance,
    ProvenanceQuality,
    SourceType,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Errors
    "BRIDGE_ERROR_MAP",
    "ContextError",
    "CryptoError",
    "IdentityError",
    "ScpError",
    "ToolError",
    "TransportError",
    "UcanPermissionError",
    "ValidationError",
    # Types
    "Capability",
    "DiscoveryMethod",
    "MemoryScope",
    "Message",
    "Provenance",
    "ProvenanceQuality",
    "SourceType",
    # Tools
    "TestVector",
    "ToolDefinition",
]
