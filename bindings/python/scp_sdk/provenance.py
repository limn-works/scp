"""Provenance operations for the SCP Python SDK.

The three prior free functions (``evaluate_provenance_quality``, ``attach``,
``check_chain_depth``) moved onto :class:`scp_sdk.SCP` in Phase 4 PR 5
(#1549). Call them as ``await scp.evaluate_provenance_quality(...)``,
``await scp.provenance_attach(...)``, and
``await scp.provenance_check_chain_depth(...)``.

See spec section 24 (Provenance System) and ADR-019.
"""

from __future__ import annotations

__all__: list[str] = []
