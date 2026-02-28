"""SCP Python SDK -- Shareable Context Protocol.

This package provides Pythonic wrappers around the ``_scp_core`` PyO3
extension module, offering typed dataclasses, an exception hierarchy,
and shared enums for building agents and applications on top of SCP.

Usage::

    import scp_sdk
    from scp_sdk import Identity, Context, ToolDefinition, evaluate_trust

    # Or via namespace alias:
    import scp_sdk as scp
    identity = await scp.Identity.create()

See ``.docs/adrs/phase-3.md`` ADR-014 for the full SDK design.
"""

from __future__ import annotations

from scp_sdk.context import Context, Membership
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
from scp_sdk.event_log import Checkpoint, Event, EventLog, Proof
from scp_sdk.identity import DIDDocument, Identity
from scp_sdk.mcp import (
    McpClient,
    McpProvenance,
    McpServer,
    McpToolDefinition,
    McpToolResult,
    configure_stdio_allowlist,
    disable_stdio_allowlist,
    get_stdio_allowlist,
    reset_stdio_allowlist,
    serve_mcp,
)
from scp_sdk.sync import run_sync
from scp_sdk.tools import TestVector, ToolDefinition
from scp_sdk.transport import TransportConfig, TransportStatus, connect_relay, relay_status
from scp_sdk.trust import (
    Attestation,
    BehavioralRecord,
    CapabilityValidation,
    ChallengeResult,
    Endorsement,
    TrustEvaluation,
    evaluate_trust,
)
from scp_sdk.types import (
    Capability,
    DiscoveryMethod,
    MemoryScope,
    Message,
    Provenance,
    ProvenanceQuality,
    SourceType,
)
from scp_sdk.ucan import UcanToken, delegate, mint, revoke, validate

__version__ = "0.1.0"

__all__ = [
    # Errors
    "BRIDGE_ERROR_MAP",
    # Trust
    "Attestation",
    "BehavioralRecord",
    # Types
    "Capability",
    "CapabilityValidation",
    "ChallengeResult",
    # Event log
    "Checkpoint",
    # Context
    "Context",
    "ContextError",
    "CryptoError",
    # Identity
    "DIDDocument",
    "DiscoveryMethod",
    "Endorsement",
    "Event",
    "EventLog",
    "Identity",
    "IdentityError",
    # MCP
    "McpClient",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "Membership",
    "MemoryScope",
    "Message",
    "Proof",
    "Provenance",
    "ProvenanceQuality",
    "ScpError",
    "SourceType",
    # Tools
    "TestVector",
    "ToolDefinition",
    "ToolError",
    # Transport
    "TransportConfig",
    "TransportError",
    "TransportStatus",
    "TrustEvaluation",
    "UcanPermissionError",
    # UCAN
    "UcanToken",
    "ValidationError",
    # Version
    "__version__",
    "configure_stdio_allowlist",
    "connect_relay",
    "delegate",
    "disable_stdio_allowlist",
    "evaluate_trust",
    "get_stdio_allowlist",
    "mint",
    "relay_status",
    "reset_stdio_allowlist",
    "revoke",
    # Sync
    "run_sync",
    "serve_mcp",
    "validate",
]
