"""Tests for the SCP Python SDK outlet wrappers (SCP-OUT-006).

Covers:

- ``_translate_bridge_error`` mapping from bridge exceptions to SDK types.
- ``_scp_core is None`` guard — every OutletNamespace method raises
  :class:`ContextError` with code ``SCP-CTX-2001``.
- Keyword-only ``invoke_cross_context`` shape (API MAJOR 22).
- ``chain_depth`` boundary validation.
- ``ttl_seconds`` boundary validation in :meth:`OutletSessionsNamespace.open`.
- :class:`SessionId` construction, UUIDv7 validation, and timestamp skew window.
- Caveat builder helpers (spending_cap / time_bounded / rate_limited / for_target).
- :class:`InvocationHandle` dual consumption: ``await`` and ``async for``.
- ``__all__`` exports.

Tests mock ``scp_sdk.outlets._scp_core``; no Rust extension required.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from scp_sdk import caveats
from scp_sdk.errors import (
    ContextError,
    CryptoError,
    IdentityError,
    OutletError,
    OutletExecutionError,
    OutletNotFoundError,
    ScpError,
    TransportError,
    UcanPermissionError,
    ValidationError,
)
from scp_sdk.outlets import (
    Aggregate,
    InvocationCaveats,
    InvocationHandle,
    InvokeCrossContextOptions,
    OutletCost,  # noqa: F401 — re-export surface check
    OutletDefinition,
    OutletKind,
    OutletNamespace,
    OutletOffersNamespace,
    OutletSessionsNamespace,
    OutletStreamChunk,
    SessionId,  # noqa: F401 — re-export surface check
    TestVector,  # noqa: F401 — re-export surface check
    _translate_bridge_error,
    _validate_session_id,
    new_session_id,
)

_DUMMY_CTX_SRC = "ctx-source-001"
_DUMMY_CTX_TGT = "ctx-target-002"
_DUMMY_OUTLET = "calculator"
_DUMMY_DID = "did:dht:z6MkAlice"
_DUMMY_UCAN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.test"


# ---------------------------------------------------------------------------
# Bridge error translation.
# ---------------------------------------------------------------------------


class TestTranslateBridgeError:
    @pytest.mark.parametrize(
        ("bridge_name", "expected_sdk_cls"),
        [
            ("IdentityError", IdentityError),
            ("ContextError", ContextError),
            ("UcanError", UcanPermissionError),
            ("CryptoError", CryptoError),
            ("TransportError", TransportError),
            ("OutletError", OutletError),
            ("ToolError", OutletError),
            ("ValidationError", ValidationError),
        ],
    )
    def test_known_bridge_errors_map_to_sdk_types(
        self, bridge_name: str, expected_sdk_cls: type[ScpError]
    ) -> None:
        bridge_cls = type(bridge_name, (Exception,), {})
        bridge_exc = bridge_cls("something went wrong")
        result = _translate_bridge_error(bridge_exc)
        assert isinstance(result, expected_sdk_cls)
        assert result.message == "something went wrong"

    def test_not_found_maps_to_subclass(self) -> None:
        bridge_cls = type("ToolError", (Exception,), {})
        result = _translate_bridge_error(bridge_cls("outlet not found in context"))
        assert isinstance(result, OutletNotFoundError)

    def test_execution_failure_maps_to_subclass(self) -> None:
        bridge_cls = type("OutletError", (Exception,), {})
        result = _translate_bridge_error(bridge_cls("outlet execution failed: bad input"))
        assert isinstance(result, OutletExecutionError)

    def test_unknown_bridge_error_falls_back_to_context_error(self) -> None:
        bridge_cls = type("SomeUnknownBridgeError", (Exception,), {})
        bridge_exc = bridge_cls("unexpected failure")
        result = _translate_bridge_error(bridge_exc)
        assert isinstance(result, ContextError)


# ---------------------------------------------------------------------------
# _scp_core is None guard — every OutletNamespace method raises ContextError.
# ---------------------------------------------------------------------------


def _ns() -> OutletNamespace:
    return OutletNamespace(_DUMMY_CTX_SRC, _DUMMY_DID)


class TestBridgeGuard:
    async def test_register_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError) as exc_info:
                await _ns().register(
                    OutletDefinition(
                        name="n",
                        description="d",
                        kind=OutletKind.Action,
                        input_schema={},
                        output_schema={},
                        operator=_DUMMY_DID,
                    )
                )
            assert exc_info.value.code == "SCP-CTX-2001"

    async def test_invoke_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            handle = _ns().invoke(_DUMMY_OUTLET, {}, _DUMMY_UCAN)
            with pytest.raises(ContextError) as exc_info:
                await handle
            assert exc_info.value.code == "SCP-CTX-2001"

    async def test_update_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                await _ns().update(
                    _DUMMY_OUTLET,
                    OutletDefinition(
                        name="n",
                        description="d",
                        kind=OutletKind.Action,
                        input_schema={},
                        output_schema={},
                        operator=_DUMMY_DID,
                    ),
                )

    async def test_get_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                await _ns().get(_DUMMY_OUTLET)

    async def test_list_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                await _ns().list()

    async def test_verify_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                await _ns().verify(_DUMMY_OUTLET)

    async def test_deregister_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                await _ns().deregister(_DUMMY_OUTLET)

    async def test_invoke_cross_context_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                # SCP-DEFAULT-INSTANCE-OK: ns method, not deprecated free function
                await _ns().invoke_cross_context(
                    target=_DUMMY_CTX_TGT,
                    outlet_id=_DUMMY_OUTLET,
                    input={},
                    ucan=_DUMMY_UCAN,
                )

    async def test_session_open_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                await _ns().sessions.open(_DUMMY_OUTLET, _DUMMY_CTX_TGT)

    async def test_session_invoke_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            sid = new_session_id()
            with pytest.raises(ContextError):
                await _ns().sessions.invoke(sid, {}, _DUMMY_DID, _DUMMY_UCAN)

    async def test_session_close_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            sid = new_session_id()
            with pytest.raises(ContextError):
                await _ns().sessions.close(sid)

    async def test_offer_propose_without_bridge(self) -> None:
        with patch("scp_sdk.outlets._scp_core", None):
            with pytest.raises(ContextError):
                await _ns().offers.propose(_DUMMY_OUTLET, _DUMMY_CTX_TGT)


# ---------------------------------------------------------------------------
# invoke_cross_context — keyword-only shape (API MAJOR 22).
# ---------------------------------------------------------------------------


class TestInvokeCrossContext:
    async def test_keyword_shape_accepted(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.context_outlet_invoke_cross_context.return_value = {"ok": True}
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            # SCP-DEFAULT-INSTANCE-OK: ns method, not deprecated free function
            result = await _ns().invoke_cross_context(
                target=_DUMMY_CTX_TGT,
                outlet_id=_DUMMY_OUTLET,
                input={"op": "add"},
                ucan=_DUMMY_UCAN,
            )
        assert result == {"ok": True}

    async def test_options_dataclass_accepted(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.context_outlet_invoke_cross_context.return_value = {"ok": True}
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            opts = InvokeCrossContextOptions(
                target=_DUMMY_CTX_TGT,
                outlet_id=_DUMMY_OUTLET,
                input={"x": 1},
                ucan=_DUMMY_UCAN,
            )
            # SCP-DEFAULT-INSTANCE-OK: ns method, not deprecated free function
            result = await _ns().invoke_cross_context(opts)
        assert result == {"ok": True}

    async def test_missing_required_rejected(self) -> None:
        with pytest.raises(ValidationError):
            # SCP-DEFAULT-INSTANCE-OK: ns method, not deprecated free function
            await _ns().invoke_cross_context(
                target=_DUMMY_CTX_TGT,
                input={},
                ucan=_DUMMY_UCAN,
            )

    async def test_options_plus_kwargs_rejected(self) -> None:
        opts = InvokeCrossContextOptions(
            target=_DUMMY_CTX_TGT,
            outlet_id=_DUMMY_OUTLET,
            input={},
            ucan=_DUMMY_UCAN,
        )
        with pytest.raises(ValidationError):
            # SCP-DEFAULT-INSTANCE-OK: ns method, not deprecated free function
            await _ns().invoke_cross_context(opts, target=_DUMMY_CTX_TGT)

    @pytest.mark.parametrize("depth", [-1, 256, 1.5, True, False])
    async def test_chain_depth_boundary(self, depth: object) -> None:
        mock_bridge = MagicMock()
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            with pytest.raises(ValidationError):
                # SCP-DEFAULT-INSTANCE-OK: ns method, not deprecated free function
                await _ns().invoke_cross_context(
                    target=_DUMMY_CTX_TGT,
                    outlet_id=_DUMMY_OUTLET,
                    input={},
                    ucan=_DUMMY_UCAN,
                    chain_depth=depth,  # type: ignore[arg-type]
                )


# ---------------------------------------------------------------------------
# Sessions — ttl + SessionId type safety.
# ---------------------------------------------------------------------------


class TestSessionsNamespace:
    async def test_ttl_negative_rejected(self) -> None:
        ns = OutletSessionsNamespace(_DUMMY_CTX_SRC)
        with pytest.raises(ValidationError):
            await ns.open(_DUMMY_OUTLET, _DUMMY_CTX_TGT, ttl_seconds=-1)

    async def test_ttl_bool_rejected(self) -> None:
        ns = OutletSessionsNamespace(_DUMMY_CTX_SRC)
        with pytest.raises(ValidationError):
            await ns.open(
                _DUMMY_OUTLET,
                _DUMMY_CTX_TGT,
                ttl_seconds=True,  # type: ignore[arg-type]
            )

    async def test_invoke_rejects_non_string_session_id(self) -> None:
        ns = OutletSessionsNamespace(_DUMMY_CTX_SRC)
        with pytest.raises(ValidationError):
            await ns.invoke(
                12345,  # type: ignore[arg-type]
                {},
                _DUMMY_DID,
                _DUMMY_UCAN,
            )

    async def test_close_rejects_non_string_session_id(self) -> None:
        ns = OutletSessionsNamespace(_DUMMY_CTX_SRC)
        with pytest.raises(ValidationError):
            await ns.close(12345)  # type: ignore[arg-type]

    async def test_open_returns_session_id(self) -> None:
        mock_bridge = MagicMock()
        raw = new_session_id()
        mock_bridge.context_outlet_session_open.return_value = str(raw)
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            ns = OutletSessionsNamespace(_DUMMY_CTX_SRC)
            result = await ns.open(_DUMMY_OUTLET, _DUMMY_CTX_TGT)
        assert result == raw


# ---------------------------------------------------------------------------
# SessionId — UUIDv7 validation and CSPRNG independence.
# ---------------------------------------------------------------------------


class TestSessionId:
    def test_new_session_id_is_uuidv7(self) -> None:
        sid = new_session_id()
        _validate_session_id(sid)

    def test_new_session_id_format(self) -> None:
        sid = new_session_id()
        parts = sid.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8
        assert len(parts[1]) == 4
        assert parts[2][0] == "7"

    def test_non_uuid_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _validate_session_id("sess-abc")

    def test_uuidv4_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _validate_session_id("550e8400-e29b-41d4-a716-446655440000")

    def test_past_timestamp_rejected(self) -> None:
        sid = new_session_id()
        future_now = int(time.time() * 1000) + 20 * 60 * 1000
        with pytest.raises(ValidationError):
            _validate_session_id(sid, now_ms=future_now)

    def test_future_timestamp_rejected(self) -> None:
        sid = new_session_id()
        past_now = int(time.time() * 1000) - 20 * 60 * 1000
        with pytest.raises(ValidationError):
            _validate_session_id(sid, now_ms=past_now)

    def test_independent_csprng_sampling(self) -> None:
        a = new_session_id()
        b = new_session_id()
        assert a != b
        tail_a = a.rsplit("-", 1)[1][4:]
        tail_b = b.rsplit("-", 1)[1][4:]
        assert tail_a != tail_b


# ---------------------------------------------------------------------------
# Caveat builders.
# ---------------------------------------------------------------------------


class TestCaveatBuilders:
    def test_spending_cap_builds(self) -> None:
        c = caveats.spending_cap(per_call=100, cumulative=1000).build()
        assert isinstance(c, InvocationCaveats)
        assert c.amount_max_per_call == 100
        assert c.amount_max_cumulative == 1000

    def test_time_bounded_builds(self) -> None:
        c = caveats.time_bounded(valid_from=0, valid_until=999).build()
        assert c.valid_from == 0
        assert c.valid_until == 999

    def test_time_bounded_rejects_oversized_hours_mask(self) -> None:
        with pytest.raises(ValueError):
            caveats.time_bounded(hours_of_day=1 << 25)

    def test_rate_limited_builds(self) -> None:
        c = caveats.rate_limited(max_calls=10, rate_window=60).build()
        assert c.max_calls == 10
        assert c.rate_window == 60

    def test_for_target_builds(self) -> None:
        c = caveats.for_target(
            allowed_target_dids=["did:dht:a", "did:dht:b"],
            allowed_adapters=["native"],
        ).build()
        assert c.allowed_target_dids == ["did:dht:a", "did:dht:b"]
        assert c.allowed_adapters == ["native"]

    def test_chained_builder(self) -> None:
        c = (
            caveats.spending_cap(per_call=100)
            .time_bounded(valid_until=999)
            .rate_limited(max_calls=5)
            .for_target(allowed_target_dids=["did:dht:a"])
            .input_schema({"type": "object"})
            .origin_kind("Query")
            .build()
        )
        assert c.amount_max_per_call == 100
        assert c.valid_until == 999
        assert c.max_calls == 5
        assert c.allowed_target_dids == ["did:dht:a"]
        assert c.input_schema == {"type": "object"}
        assert c.origin_kind == "Query"

    def test_origin_kind_invalid_rejected(self) -> None:
        b = caveats.CaveatBuilder()
        with pytest.raises(ValueError):
            b.origin_kind("Other")


# ---------------------------------------------------------------------------
# InvocationHandle — dual consumption.
# ---------------------------------------------------------------------------


class TestInvocationHandle:
    async def test_await_returns_aggregate(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.context_outlet_invoke.return_value = {"result": 42}
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            handle = _ns().invoke(_DUMMY_OUTLET, {}, _DUMMY_UCAN)
            assert isinstance(handle, InvocationHandle)
            agg = await handle
        assert isinstance(agg, Aggregate)
        assert agg.value == {"result": 42}

    async def test_async_iter_yields_chunks(self) -> None:
        # OUT-038 AC14: iterator yields the End chunk (so 1 Data + End =
        # 2 chunks; 10 Data + End = 11). The non-streaming bridge
        # synthesizes a single End chunk via the SDK pump, so the
        # iterator yields exactly one chunk here.
        mock_bridge = MagicMock()
        mock_bridge.context_outlet_invoke.return_value = {"result": 42}
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            handle = _ns().invoke(_DUMMY_OUTLET, {}, _DUMMY_UCAN)
            chunks: list[OutletStreamChunk] = []
            async for chunk in handle:
                chunks.append(chunk)
        assert len(chunks) == 1
        assert chunks[0].payload_type == "end"
        assert chunks[0].aggregate == {"result": 42}

    async def test_double_consumption_rejected(self) -> None:
        mock_bridge = MagicMock()
        mock_bridge.context_outlet_invoke.return_value = {"r": 1}
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            handle = _ns().invoke(_DUMMY_OUTLET, {}, _DUMMY_UCAN)
            await handle
            with pytest.raises(ContextError):
                async for _chunk in handle:
                    pass


# ---------------------------------------------------------------------------
# Offers sub-namespace.
# ---------------------------------------------------------------------------


class TestOffersNamespace:
    def test_verbs_present(self) -> None:
        ns = OutletOffersNamespace(_DUMMY_CTX_SRC)
        for name in ("propose", "accept", "revoke", "list"):
            assert callable(getattr(ns, name))

    async def test_list_returns_empty_default(self) -> None:
        ns = OutletOffersNamespace(_DUMMY_CTX_SRC)
        assert await ns.list() == []


# ---------------------------------------------------------------------------
# OutletNamespace shape exposes the required verbs + sub-namespaces.
# ---------------------------------------------------------------------------


class TestOutletNamespaceShape:
    def test_all_verbs_present(self) -> None:
        ns = _ns()
        for name in (
            "register",
            "register_query",
            "register_action",
            "invoke",
            "update",
            "get",
            "list",
            "verify",
            "deregister",
            "invoke_cross_context",
        ):
            assert callable(getattr(ns, name)), name


# ---------------------------------------------------------------------------
# SCP-OUT-017 — OutletKind required + register_query / register_action.
# ---------------------------------------------------------------------------


class TestOutletKindRequired:
    """SCP-OUT-017 enforcement at the Python SDK surface."""

    def test_outlet_definition_without_kind_raises_typeerror(self) -> None:
        """The dataclass enforces `kind` at construction time."""
        with pytest.raises(TypeError):
            OutletDefinition(  # type: ignore[call-arg]
                name="n",
                description="d",
                input_schema={},
                output_schema={},
                operator=_DUMMY_DID,
            )

    async def test_register_keyword_form_without_kind_raises_validation(self) -> None:
        """Calling register() in keyword form without `kind` is rejected."""
        with pytest.raises(ValidationError):
            await _ns().register(  # type: ignore[call-arg]
                name="n",
                description="d",
                input_schema={},
                output_schema={},
                operator=_DUMMY_DID,
            )

    def test_outlet_kind_parse_round_trips_strings(self) -> None:
        assert OutletKind.parse("query") is OutletKind.Query
        assert OutletKind.parse("action") is OutletKind.Action
        assert OutletKind.parse(OutletKind.Query) is OutletKind.Query
        with pytest.raises(ValidationError):
            OutletKind.parse("mutation")
        with pytest.raises(ValidationError):
            OutletKind.parse(123)  # type: ignore[arg-type]

    async def test_register_query_sets_kind_query_on_wire(self) -> None:
        """register_query() sends `kind: "query"` to the bridge."""
        captured = {}

        def fake(_ctx_id: str, registration: dict[str, Any]) -> str:
            captured["kind"] = registration["kind"]
            return "tool-fake"

        mock_bridge = MagicMock()
        mock_bridge.context_outlet_register.side_effect = fake
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            outlet_id = await _ns().register_query(
                name="weather",
                description="lookup weather",
                input_schema={"type": "object"},
                output_schema={"type": "object"},
                operator=_DUMMY_DID,
            )
        assert outlet_id == "tool-fake"
        assert captured["kind"] == "query"

    async def test_register_action_sets_kind_action_on_wire(self) -> None:
        captured = {}

        def fake(_ctx_id: str, registration: dict[str, Any]) -> str:
            captured["kind"] = registration["kind"]
            return "tool-fake"

        mock_bridge = MagicMock()
        mock_bridge.context_outlet_register.side_effect = fake
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            outlet_id = await _ns().register_action(
                name="send-email",
                description="send a message",
                input_schema={"type": "object"},
                output_schema={"type": "object"},
                operator=_DUMMY_DID,
            )
        assert outlet_id == "tool-fake"
        assert captured["kind"] == "action"

    async def test_register_with_definition_threads_kind_to_bridge(self) -> None:
        captured = {}

        def fake(_ctx_id: str, registration: dict[str, Any]) -> str:
            captured["kind"] = registration["kind"]
            return "tool-fake"

        mock_bridge = MagicMock()
        mock_bridge.context_outlet_register.side_effect = fake
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            await _ns().register(
                OutletDefinition(
                    name="n",
                    description="d",
                    kind=OutletKind.Query,
                    input_schema={},
                    output_schema={},
                    operator=_DUMMY_DID,
                ),
            )
        assert captured["kind"] == "query"

    async def test_register_keyword_form_threads_kind_to_bridge(self) -> None:
        captured = {}

        def fake(_ctx_id: str, registration: dict[str, Any]) -> str:
            captured["kind"] = registration["kind"]
            return "tool-fake"

        mock_bridge = MagicMock()
        mock_bridge.context_outlet_register.side_effect = fake
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            await _ns().register(
                kind=OutletKind.Action,
                name="n",
                description="d",
                input_schema={},
                output_schema={},
                operator=_DUMMY_DID,
            )
        assert captured["kind"] == "action"

    async def test_register_kind_string_form_accepted(self) -> None:
        """The wire-format string `"query"` / `"action"` is also accepted."""
        captured = {}

        def fake(_ctx_id: str, registration: dict[str, Any]) -> str:
            captured["kind"] = registration["kind"]
            return "tool-fake"

        mock_bridge = MagicMock()
        mock_bridge.context_outlet_register.side_effect = fake
        with patch("scp_sdk.outlets._scp_core", mock_bridge):
            await _ns().register(
                kind="query",
                name="n",
                description="d",
                input_schema={},
                output_schema={},
                operator=_DUMMY_DID,
            )
        assert captured["kind"] == "query"

    async def test_register_definition_plus_kwargs_rejected(self) -> None:
        with pytest.raises(ValidationError):
            await _ns().register(
                OutletDefinition(
                    name="n",
                    description="d",
                    kind=OutletKind.Action,
                    input_schema={},
                    output_schema={},
                    operator=_DUMMY_DID,
                ),
                name="other",
            )

    def test_sub_namespaces_present(self) -> None:
        ns = _ns()
        assert isinstance(ns.sessions, OutletSessionsNamespace)
        assert isinstance(ns.offers, OutletOffersNamespace)


# ---------------------------------------------------------------------------
# __all__ exports.
# ---------------------------------------------------------------------------


class TestOutletsAllExports:
    @pytest.mark.parametrize(
        "name",
        [
            "Aggregate",
            "InvocationCaveats",
            "InvocationHandle",
            "InvokeCrossContextOptions",
            "OutletCost",
            "OutletDefinition",
            "OutletNamespace",
            "OutletOffersNamespace",
            "OutletSessionsNamespace",
            "OutletStreamChunk",
            "SessionId",
            "TestVector",
            "new_session_id",
        ],
    )
    def test_outlets_module_exports_symbol(self, name: str) -> None:
        from scp_sdk import outlets

        assert name in outlets.__all__

    def test_top_level_exports(self) -> None:
        import scp_sdk

        for name in (
            "OutletNamespace",
            "OutletSessionsNamespace",
            "OutletOffersNamespace",
            "InvocationHandle",
            "InvokeCrossContextOptions",
            "SessionId",
            "OutletDefinition",
            "OutletCost",
            "TestVector",
            "caveats",
        ):
            assert hasattr(scp_sdk, name), name
