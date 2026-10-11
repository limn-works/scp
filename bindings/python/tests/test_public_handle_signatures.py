"""Public ``SCP`` methods take the SDK's handle objects, never raw native handles.

ADR-052 gives every binding one shape: Swift and Kotlin take the
``ContextHandle`` and ``Identity`` objects, so the Python ``SCP`` methods take
the :class:`~scp_sdk.Context`, :class:`~scp_sdk.Identity`,
:class:`~scp_sdk.McpClient`, :class:`~scp_sdk.McpServer`, and
:class:`~scp_sdk.FullStackNode` objects the SDK returns. A caller never reaches
for the private ``_raw_handle``, and a raw native handle or any other type
raises ``ValidationError`` (SCP-VALID-7005).

These tests mock the native bridge; no Rust extension is required.
"""

from __future__ import annotations

import inspect
import typing
from collections.abc import Callable
from typing import Any
from unittest.mock import MagicMock

import pytest

import scp_sdk.scp as scp_module
from scp_sdk import SCP, Context, FullStackNode, Identity, McpClient, McpServer
from scp_sdk.errors import ValidationError

#: Parameter names that carry a handle on a public ``SCP`` method.
HANDLE_PARAMETER_NAMES = frozenset(
    {"handle", "context", "identity", "client", "server", "node", "node_a", "node_b"}
)


def _public_methods() -> list[tuple[str, Callable[..., Any]]]:
    return [
        (name, member)
        for name, member in inspect.getmembers(SCP, predicate=inspect.isfunction)
        if not name.startswith("_")
    ]


def _handle_parameter_violations() -> list[str]:
    """Return ``method(param: annotation)`` for each untyped or ``Any`` handle parameter.

    Annotations are strings under ``from __future__ import annotations``, so
    each handle parameter's annotation is evaluated in ``scp_sdk.scp``'s
    namespace. An annotation that names a type only imported under
    ``TYPE_CHECKING`` fails to evaluate and counts as a violation, because
    the method could not check the argument against it at runtime.
    """
    namespace = vars(scp_module)
    violations: list[str] = []
    for name, method in _public_methods():
        for param in inspect.signature(inspect.unwrap(method)).parameters.values():
            if param.name not in HANDLE_PARAMETER_NAMES:
                continue
            annotation = param.annotation
            if annotation is inspect.Parameter.empty:
                violations.append(f"{name}({param.name}: <unannotated>)")
                continue
            if isinstance(annotation, str):
                try:
                    annotation = eval(annotation, namespace)
                except NameError:
                    violations.append(f"{name}({param.name}: {param.annotation} unresolved)")
                    continue
            if annotation is Any or Any in typing.get_args(annotation):
                violations.append(f"{name}({param.name}: {param.annotation})")
    return violations


def test_no_public_scp_method_types_a_handle_parameter_as_any_or_leaves_it_unannotated() -> None:
    violations = _handle_parameter_violations()
    assert not violations, (
        "public SCP methods must type each handle parameter as the SDK object "
        "the SDK returns (Context, Identity, McpClient, McpServer, "
        f"FullStackNode), never Any or unannotated: {violations}"
    )


def test_the_signature_scan_reaches_the_known_handle_methods() -> None:
    """Positive control: the scan sees the methods it guards, typed as their wrappers."""
    hints = {
        name: inspect.signature(inspect.unwrap(method)).parameters
        for name, method in _public_methods()
    }
    assert hints["context_send"]["handle"].annotation == "Context"
    assert hints["identity_rotate_key"]["identity"].annotation == "Identity"
    assert hints["mcp_client_invoke"]["handle"].annotation == "McpClient"
    assert hints["mcp_server_stop"]["handle"].annotation == "McpServer"
    assert hints["fullstack_sync_sender_keys"]["node_a"].annotation == "FullStackNode"


def _scp_with_mock_native() -> SCP:
    scp = SCP.__new__(SCP)
    scp._native = MagicMock()
    return scp


class _RawNativeHandle:
    """Stands in for a native ``PyContextHandle`` / ``PyIdentity`` passed directly."""


# (method, argument builder, wrapper class, native method name)
_CASES: list[tuple[str, Callable[[object], tuple[Any, ...]], type, str]] = [
    ("context_send", lambda h: (h, "did:dht:z6MkAlice", b"hi"), Context, "context_send"),
    ("context_receive", lambda h: (h,), Context, "context_receive"),
    ("context_close", lambda h: (h, "did:dht:z6MkAlice"), Context, "context_close"),
    ("broadcast_publish", lambda h: (h, "did:dht:z6MkAlice", b"x"), Context, "broadcast_publish"),
    ("governance_list_proposals", lambda h: (h,), Context, "governance_list_proposals"),
    ("identity_rotate_key", lambda h: (h,), Identity, "identity_rotate_key"),
    ("identity_add_agent_key", lambda h: (h,), Identity, "identity_add_agent_key"),
    ("mcp_client_info", lambda h: (h,), McpClient, "py_mcp_client_info"),
    ("mcp_server_stop", lambda h: (h,), McpServer, "py_mcp_server_stop"),
    (
        "fullstack_join_from_welcome",
        lambda h: (h, "ctx"),
        FullStackNode,
        "fullstack_join_from_welcome",
    ),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args", "wrapper", "native"), _CASES)
async def test_the_sdk_object_reaches_the_bridge_as_its_native_handle(
    method: str, args: Callable[[object], tuple[Any, ...]], wrapper: type, native: str
) -> None:
    scp = _scp_with_mock_native()
    raw = _RawNativeHandle()
    await getattr(scp, method)(*args(wrapper(raw)))
    called = getattr(scp._native, native)
    called.assert_called_once()
    assert called.call_args.args[0] is raw


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "args", "wrapper", "native"), _CASES)
@pytest.mark.parametrize(
    "bad",
    [_RawNativeHandle(), "ctx-or-did-string", None],
    ids=["raw-native-handle", "string", "none"],
)
async def test_a_raw_handle_or_wrong_type_raises_valid_7005_before_the_bridge(
    method: str,
    args: Callable[[object], tuple[Any, ...]],
    wrapper: type,
    native: str,
    bad: object,
) -> None:
    scp = _scp_with_mock_native()
    with pytest.raises(ValidationError) as excinfo:
        await getattr(scp, method)(*args(bad))
    assert excinfo.value.code == "SCP-VALID-7005"
    assert wrapper.__name__ in str(excinfo.value)
    getattr(scp._native, native).assert_not_called()


@pytest.mark.asyncio
async def test_a_context_passed_where_an_identity_belongs_raises_valid_7005() -> None:
    scp = _scp_with_mock_native()
    with pytest.raises(ValidationError) as excinfo:
        await scp.identity_rotate_key(Context(_RawNativeHandle()))  # type: ignore[arg-type]
    assert excinfo.value.code == "SCP-VALID-7005"
    scp._native.identity_rotate_key.assert_not_called()


@pytest.mark.asyncio
async def test_fullstack_create_node_returns_a_full_stack_node() -> None:
    scp = _scp_with_mock_native()
    raw = MagicMock(did="did:dht:z6MkNode")
    scp._native.fullstack_create_node.return_value = raw
    node = await scp.fullstack_create_node("did:dht:z6MkNode")
    assert isinstance(node, FullStackNode)
    assert node.did == "did:dht:z6MkNode"
