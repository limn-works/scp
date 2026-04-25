"""Outlet capability stem parser conformance (SCP-OUT-014).

Loads ``tests/conformance/vectors/outlet_capability_parse.json`` and asserts
every positive vector parses to the expected variant and every negative
vector rejects to ``None``. The fixture is identical across bridges —
divergence between the Python wrapper and the Rust core would mean a
parser-differential authorization bug.

Spec references:
- .docs/specs/05-contexts.md §5.4.2.1 UCAN Capability Stem Parser
- .docs/adrs/ADR-049-outlet-redesign.md §1 Rename hard break, §2
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest


def _fixture_path() -> Path:
    here = Path(__file__).resolve()
    repo_root = here.parents[3]
    return repo_root / "tests" / "conformance" / "vectors" / "outlet_capability_parse.json"


# Python-side reference parser — mirrors scp_protocol::context::roles::Capability::new.
_OUTLET_SUFFIX_RE = re.compile(r"^[a-z0-9_-]{1,128}$")

_KNOWN_EXACT = {
    "messages:read": "MessagesRead",
    "messages:write": "MessagesWrite",
    "outlet:query:*": "OutletQueryAll",
    "outlet_query:*": "OutletQueryAll",
    "outlet:call:*": "OutletCallAll",
    "outlet_call:*": "OutletCallAll",
    "outlet:register": "OutletRegister",
    "member:invite": "MemberInvite",
    "member:remove": "MemberRemove",
    "role:assign": "RoleAssign",
    "governance:propose": "GovernancePropose",
    "governance:vote": "GovernanceVote",
    "context:close": "ContextClose",
    "context:child:create": "ChildContextCreate",
    "outlet:interface": "OutletInterface",
    "bridging": "Bridging",
    "media:voice": "MediaVoice",
    "media:video": "MediaVideo",
    "media:screen_share": "MediaScreenShare",
    "member:ban": "MemberBan",
    "metadata:edit": "MetadataEdit",
}


def parse_capability(name: str):
    """Reference Python implementation of ``Capability::new`` from the Rust core.

    Returns ``(kind, payload)`` where ``payload`` is the inner id/name for
    parameterised variants, or ``None`` for hard-break / parse-failure cases.
    """
    if name.startswith("outlet:invoke:") or name.startswith("outlet_invoke:"):
        return None
    if name in ("outlet:invoke:*", "outlet_invoke:*"):
        return None
    if name.startswith("tool:invoke:") or name.startswith("tool_invoke:"):
        return None
    if name in ("tool:register", "tool:interface", "tool_register", "tool_interface"):
        return None

    if name in _KNOWN_EXACT:
        return (_KNOWN_EXACT[name], None)

    for prefix, kind in (
        ("outlet:query:", "OutletQuery"),
        ("outlet_query:", "OutletQuery"),
        ("outlet:call:", "OutletCall"),
        ("outlet_call:", "OutletCall"),
    ):
        if name.startswith(prefix):
            suffix = name[len(prefix) :]
            if not _OUTLET_SUFFIX_RE.match(suffix):
                return None
            return (kind, suffix)

    if name.startswith("custom:"):
        return ("Custom", name[len("custom:") :])
    return ("Custom", name)


@pytest.fixture(scope="module")
def fixture():
    path = _fixture_path()
    with path.open() as f:
        return json.load(f)


def test_fixture_loads(fixture):
    assert fixture["story"] == "SCP-OUT-014"
    assert len(fixture["positive"]) >= 20
    assert len(fixture["negative"]) >= 20


def test_positive_vectors(fixture):
    for v in fixture["positive"]:
        actual = parse_capability(v["input"])
        expected = v["expected"]
        assert actual is not None, f"positive vector failed: {v['input']!r}"
        kind, payload = actual
        assert kind == expected["kind"], (
            f"kind mismatch for {v['input']!r}: got {kind}, expected {expected['kind']}"
        )
        if "id" in expected:
            assert payload == expected["id"], (
                f"id mismatch for {v['input']!r}: got {payload}, expected {expected['id']}"
            )
        if "name" in expected:
            assert payload == expected["name"], (
                f"name mismatch for {v['input']!r}: got {payload}, expected {expected['name']}"
            )


def test_negative_vectors(fixture):
    for v in fixture["negative"]:
        actual = parse_capability(v["input"])
        assert actual is None, (
            f"negative vector must reject: {v['input']!r} ({v['reason']}) but parsed to {actual}"
        )


def test_python_capability_helpers_round_trip():
    """Python helpers ``Capability.outlet_query`` / ``outlet_call`` must produce
    strings that round-trip through the parser to the same variant."""
    from scp_sdk.types import Capability

    assert parse_capability(Capability.OUTLET_QUERY_ALL.value) == ("OutletQueryAll", None)
    assert parse_capability(Capability.OUTLET_CALL_ALL.value) == ("OutletCallAll", None)
    assert parse_capability(Capability.outlet_query("my-tool")) == ("OutletQuery", "my-tool")
    assert parse_capability(Capability.outlet_call("send_log")) == ("OutletCall", "send_log")


def test_no_legacy_tool_invoke_in_python_capability():
    """Python ``Capability`` enum must not expose the pre-rename TOOL_INVOKE /
    TOOL_REGISTER members — SCP-OUT-014 / ADR-049 §1 hard-break."""
    from scp_sdk.types import Capability

    member_names = {m.name for m in Capability}
    assert "TOOL_INVOKE_ALL" not in member_names
    assert "TOOL_REGISTER" not in member_names
    assert "TOOL_INTERFACE" not in member_names
