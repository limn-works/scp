"""Outlet-related dataclasses and cross-context/session wrappers for the SCP Python SDK.

Contains :class:`OutletDefinition` and :class:`TestVector`, the two types
needed for outlet registration and verification within SCP contexts, plus
module-level async functions for cross-context outlet invocation and
stateful outlet sessions:

- :func:`invoke_cross_context` -- Invoke an outlet across context boundaries.
- :func:`session_create` -- Create a stateful outlet session.
- :func:`session_invoke` -- Invoke an outlet within an active session.
- :func:`session_close` -- Close a stateful outlet session.

See ``.docs/adrs/phase-3.md`` ADR-014 acceptance criterion 3,
``.docs/standards/python.md`` for conventions, and spec section 6.2 /
6.2.1 for cross-context invocation and stateful sessions.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from scp_sdk.errors import BRIDGE_ERROR_MAP, ContextError, ValidationError

if TYPE_CHECKING:
    from scp_sdk.identity import Identity
    from scp_sdk.scp import SCP

try:
    import _scp_core  # type: ignore[import-not-found]
except ImportError:
    _scp_core = None  # type: ignore[assignment]


def _resolve_bridge(scp: SCP) -> Any:
    """Return the effective bridge object for outlet operations.

    Tests patch ``scp_sdk.outlets._scp_core`` with a ``MagicMock`` whose
    ``outlet_*`` attributes stand in for the live bridge. In production
    those attributes do not exist on the real ``_scp_core`` module
    (Phase 4 PR 4 consolidated them onto :class:`SCP`), so we fall
    through to ``scp._native`` and dispatch on the SCP instance.
    """
    mod = _scp_core
    if mod is not None and hasattr(mod, "_mock_name"):
        return mod
    return scp._native


def _translate_bridge_error(exc: Exception) -> Exception:
    """Translate a ``_scp_core`` bridge exception to an SDK exception.

    Uses :data:`~scp_sdk.errors.BRIDGE_ERROR_MAP` to look up the SDK type
    by the bridge exception's class name.  Falls back to
    :class:`~scp_sdk.errors.ContextError` for unmapped types.
    """
    sdk_cls = BRIDGE_ERROR_MAP.get(type(exc).__name__, ContextError)
    return sdk_cls(str(exc))


# ---------------------------------------------------------------------------
# OutletKind — outlet semantic class (Query vs Action), §5.4.2.
# ---------------------------------------------------------------------------


class OutletKind(enum.Enum):
    """Outlet semantic class (§5.4.2).

    ``Query`` outlets are read-only and idempotent (UCAN stem
    ``outlet_query:{id}``); ``Action`` outlets may mutate state (UCAN stem
    ``outlet_call:{id}``).

    Required at the SDK surface across all 4 bindings. Crosses the bridge
    boundary as the lowercase string ``"query"`` / ``"action"`` matching the
    §5.4.2 wire vocabulary.
    """

    Query = "query"
    Action = "action"

    @classmethod
    def parse(cls, value: OutletKind | str) -> OutletKind:
        """Coerce ``value`` to an :class:`OutletKind` instance.

        Accepts an existing :class:`OutletKind` (returned unchanged) or
        the lowercase string ``"query"`` / ``"action"`` matching the
        §5.4.2 wire vocabulary. Other values raise
        :class:`~scp_sdk.errors.ValidationError` (code ``SCP-VALID-7050``).
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            try:
                return cls(value)
            except ValueError as exc:
                raise ValidationError(
                    f"OutletKind must be 'query' or 'action' (§5.4.2 wire vocabulary), "
                    f"got {value!r}",
                    code="SCP-VALID-7050",
                ) from exc
        raise ValidationError(
            f"OutletKind must be an OutletKind or str, got {type(value).__name__}",
            code="SCP-VALID-7050",
        )


@dataclass
class TestVector:
    """A single test vector for outlet verification.

    Test vectors define expected input/output pairs that an outlet
    implementation must satisfy.  They are used during outlet registration
    to verify that the implementation matches its declared behaviour.
    """

    #: Input data to feed the outlet (JSON-compatible dict).
    input: dict[str, Any]

    #: Expected output from the outlet (JSON-compatible dict).
    expected_output: dict[str, Any]

    #: Human-readable description of what this vector tests.
    description: str = ""


@dataclass
class OutletCost:
    """Per-invocation cost metadata for an outlet (spec section 5.4.1).

    All monetary values are in the smallest currency unit (e.g., cents
    for USD, satoshis for BTC).
    """

    #: Cost per invocation in the smallest currency unit.
    amount: int

    #: ISO 4217 or protocol-defined currency code.
    currency: str

    #: DID of the payment recipient.  May differ from the outlet operator.
    payee: str

    #: Optional pricing formula identifier for dynamic pricing (spec section 19.4).
    cost_formula: str | None = None


@dataclass(kw_only=True)
class OutletDefinition:
    """Definition of an outlet registered in an SCP context (§5.4.1).

    Mirrors ADR-014 acceptance criterion 3.  The ``operator`` field
    accepts either an ``Identity`` object (from ``scp_sdk.identity``,
    defined in a separate story) or a plain DID string.

    ``kind`` is REQUIRED — there is no default. All 4 SDKs surface
    :class:`OutletKind` as a required field; the dataclass is keyword-only,
    so omitting ``kind`` raises :class:`TypeError` from the dataclass
    machinery. It selects the outlet's UCAN capability stem
    (``outlet_query:{id}`` for :attr:`OutletKind.Query`,
    ``outlet_call:{id}`` for :attr:`OutletKind.Action`; §5.4.2).

    Example::

        outlet = OutletDefinition(
            name="recipe_search",
            description="Search recipes by ingredients",
            kind=OutletKind.Query,
            input_schema={"type": "object", "properties": {"query": {"type": "string"}}},
            output_schema={"type": "object", "properties": {"results": {"type": "array"}}},
            operator="did:dht:z6MkOperator",
        )
    """

    #: Unique outlet name within the context.
    name: str

    #: Human-readable description of the outlet's purpose.
    description: str

    #: Outlet semantic class (Query vs Action, §5.4.2). REQUIRED — selects the
    #: outlet's UCAN capability stem.
    kind: OutletKind

    #: JSON Schema describing the outlet's input.
    input_schema: dict[str, Any]

    #: JSON Schema describing the outlet's output.
    output_schema: dict[str, Any]

    #: DID string or :class:`~scp_sdk.identity.Identity` object of the
    #: outlet operator.
    operator: Identity | str | None

    #: Optional test vectors for verification.
    test_vectors: list[TestVector] | None = None

    #: Optional implementation hash for integrity verification.
    implementation_hash: bytes | None = None

    #: Optional per-invocation cost metadata (spec section 5.4.1).
    cost: OutletCost | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the registration dict the PyO3 bridge expects.

        Produces the exact key shape consumed by
        ``scp-ffi/src/outlets.rs::outlet_register_impl`` and its
        ``extract_*`` helpers:

        - ``name`` / ``description`` — strings.
        - ``kind`` — the lowercase §5.4.2 wire string (``self.kind.value``).
        - ``operator_did`` — the operator's DID: ``operator.did`` when
          ``operator`` is an :class:`~scp_sdk.identity.Identity`, otherwise
          the string itself.
        - ``schema`` — ``{"input_schema": …, "output_schema": …}``.
        - ``test_vectors`` — list of ``{input, expected_output, description}``
          dicts (present only when set).
        - ``implementation_hash`` — 64-char lowercase hex string (the bridge's
          ``extract_implementation_hash`` decodes hex, not raw bytes; present
          only when set).
        - ``cost`` — ``{amount, currency, payee, cost_formula}`` (present only
          when set).
        """
        operator = self.operator
        operator_did = operator.did if hasattr(operator, "did") else operator
        result: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "kind": self.kind.value,
            "operator_did": operator_did,
            "schema": {
                "input_schema": self.input_schema,
                "output_schema": self.output_schema,
            },
        }
        if self.test_vectors is not None:
            result["test_vectors"] = [
                {
                    "input": tv.input,
                    "expected_output": tv.expected_output,
                    "description": tv.description,
                }
                for tv in self.test_vectors
            ]
        if self.implementation_hash is not None:
            result["implementation_hash"] = self.implementation_hash.hex()
        if self.cost is not None:
            result["cost"] = {
                "amount": self.cost.amount,
                "currency": self.cost.currency,
                "payee": self.cost.payee,
                "cost_formula": self.cost.cost_formula,
            }
        return result


# ---------------------------------------------------------------------------
# Cross-context outlet invocation (spec section 6.2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SagaResult:
    """The committed terminal of a §6.2.4 cross-context outlet-invocation saga.

    Returned by :meth:`scp_sdk.SCP.outlet_invoke_cross_context_saga` only on a
    ``Committed`` terminal — every non-committed terminal raises a typed saga
    exception (:class:`~scp_sdk.errors.SagaAbortedError`,
    :class:`~scp_sdk.errors.SagaNeedsRepairError`, or
    :class:`~scp_sdk.errors.SagaBusyError`) instead.

    The fields are a faithful pass-through of the bridge result: ``receipt``
    and ``output`` are surfaced exactly as the bridge returns them (``None``
    when absent — never synthesized). See spec §6.2.4 and ADR-049 §3a.
    """

    #: The durable saga identifier (supervisor-minted, never a caller input).
    saga_id: str

    #: The target's signed ``CrossContextOutletReceipt`` bytes (JCS), or ``None``.
    receipt: bytes | None = None

    #: The captured outlet output bytes (the receipt's canonical ``output_jcs``),
    #: or ``None``.
    output: bytes | None = None


# ---------------------------------------------------------------------------
# Stateful outlet sessions (spec section 6.2.1)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Bidirectional consent protocol (spec section 6.2.0.1)
# ---------------------------------------------------------------------------


__all__ = [
    "OutletCost",
    "OutletDefinition",
    "OutletKind",
    "SagaResult",
    "TestVector",
]
