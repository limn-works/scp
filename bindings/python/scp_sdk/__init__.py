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
from scp_sdk.mcp import McpClient, McpProvenance, McpServer, McpToolDefinition, McpToolResult, serve_mcp
from scp_sdk.ucan import UcanToken, delegate, mint, revoke, validate

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Context
    "Context",
    "Membership",
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
    # Event log
    "Checkpoint",
    "Event",
    "EventLog",
    "Proof",
    # Identity
    "DIDDocument",
    "Identity",
    # Sync
    "run_sync",
    # Tools
    "TestVector",
    "ToolDefinition",
    # Transport
    "TransportConfig",
    "TransportStatus",
    "connect_relay",
    "relay_status",
    # Trust
    "Attestation",
    "BehavioralRecord",
    "CapabilityValidation",
    "ChallengeResult",
    "Endorsement",
    "TrustEvaluation",
    "evaluate_trust",
    # Types
    "Capability",
    "DiscoveryMethod",
    "MemoryScope",
    "Message",
    "Provenance",
    "ProvenanceQuality",
    "SourceType",
    # MCP
    "McpClient",
    "McpProvenance",
    "McpServer",
    "McpToolDefinition",
    "McpToolResult",
    "serve_mcp",
    # UCAN
    "UcanToken",
    "delegate",
    "mint",
    "revoke",
    "validate",
]
