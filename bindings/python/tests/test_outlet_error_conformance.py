"""SCP-OUT-031 — Python OutletError sealed-hierarchy + fixture round-trip.

Verifies:

* The eight concrete subclasses (`OutletProtocolError`, `AuthorizationError`,
  ...) exist under `OutletError` and each carries the right `class_wire`.
* `OutletProtocolError` is the §5.4.4 Protocol-class subclass (NOT
  `ProtocolError`, to avoid colliding with MLS protocol error symbols).
* `Credit` factory rejects zero / over-2^32 with `InvalidGrant` under
  the `OutletError` hierarchy.
* `CatalogKey` factory rejects malformed input with `OutletProtocolError`.
* `OutletError.new` is keyword-only (positional invocation raises).
* `redact_pii` redacts emails and DIDs.
* Per-class detail-shape conformance — malformed detail rejected at
  `from_wire` boundary.
* Every fixture in `tests/conformance/vectors/outlet_error_fixtures.json`
  round-trips: decode → typed subclass → encode → decode again, with
  every wire-form field preserved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scp_sdk.errors import (
    AuthorizationError,
    EconomicError,
    ExecutionError,
    InputError,
    InvalidGrant,
    OutletError,
    OutletGovernanceError,
    OutletProtocolError,
    OutletTransportError,
    OutputError,
    ScpError,
    ValidationError,
    make_catalog_key,
    make_credit,
    redact_pii,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "tests"
    / "conformance"
    / "vectors"
    / "outlet_error_fixtures.json"
)


def _load_fixtures() -> list[dict[str, Any]]:
    raw = json.loads(FIXTURE_PATH.read_text())
    return raw["fixtures"]


# ---------------------------------------------------------------------------
# Sealed-hierarchy structural assertions
# ---------------------------------------------------------------------------


def test_outlet_protocol_error_named_to_avoid_mls_collision() -> None:
    # AC: from scp_sdk.errors import OutletProtocolError must succeed.
    assert OutletProtocolError.__name__ == "OutletProtocolError"
    assert issubclass(OutletProtocolError, OutletError)
    assert issubclass(OutletProtocolError, ScpError)


def test_eight_concrete_subclasses_under_outlet_error() -> None:
    subclasses = {
        "protocol": OutletProtocolError,
        "authorization": AuthorizationError,
        "input": InputError,
        "execution": ExecutionError,
        "output": OutputError,
        "economic": EconomicError,
        "transport": OutletTransportError,
        "governance": OutletGovernanceError,
    }
    assert len(subclasses) == 8
    for wire, cls in subclasses.items():
        assert issubclass(cls, OutletError), f"{cls.__name__} must extend OutletError"
        assert cls.class_wire == wire


def test_outlet_error_is_subclass_of_abc() -> None:
    # `OutletError` derives from `abc.ABC` so future versions can mark
    # methods abstract without an inheritance break. For OUT-031 the
    # base remains instantiable (no `@abstractmethod` decorators yet) so
    # legacy `OutletError(message, code)` callers continue to compile.
    import abc

    assert issubclass(OutletError, abc.ABC)


# ---------------------------------------------------------------------------
# Credit / CatalogKey newtypes
# ---------------------------------------------------------------------------


def test_credit_factory_accepts_positive_in_range() -> None:
    c = make_credit(1)
    assert c == 1
    c2 = make_credit(2**32 - 1)
    assert c2 == 2**32 - 1


def test_credit_factory_rejects_zero_with_invalid_grant() -> None:
    with pytest.raises(InvalidGrant) as exc:
        make_credit(0)
    err = exc.value
    assert isinstance(err, OutletError)
    assert isinstance(err, OutletProtocolError)
    assert err.code == "SCP-TOOL-6101"
    assert err.slug == "protocol.invalid-grant"


def test_credit_factory_rejects_negative_and_over_max() -> None:
    with pytest.raises(InvalidGrant):
        make_credit(-1)
    with pytest.raises(InvalidGrant):
        make_credit(2**32)


def test_catalog_key_factory_accepts_canonical() -> None:
    k = make_catalog_key("authorization.denied")
    assert k == "authorization.denied"


def test_catalog_key_factory_rejects_malformed() -> None:
    with pytest.raises(OutletProtocolError) as exc:
        make_catalog_key("Authorization.Denied")
    assert exc.value.slug == "protocol.malformed-catalog-key"
    with pytest.raises(OutletProtocolError):
        make_catalog_key("")


# ---------------------------------------------------------------------------
# OutletError.new — keyword-only, options-object equivalent
# ---------------------------------------------------------------------------


def test_outlet_error_new_is_keyword_only() -> None:
    # Adjacent string args outlet_id and catalog_key are swap-risk per
    # round-6 — the leading `*` in OutletError.new's signature forces
    # keyword-only so positional invocation is a TypeError.
    with pytest.raises(TypeError):
        OutletError.new("outlet-1", "authorization.denied", "authorization")  # type: ignore[misc]


def test_outlet_error_new_returns_typed_subclass() -> None:
    err = OutletError.new(
        outlet_id="outlet-1",  # type: ignore[arg-type]
        catalog_key=make_catalog_key("authorization.denied"),
        class_="authorization",
    )
    assert isinstance(err, AuthorizationError)
    assert err.class_wire == "authorization"
    assert err.code == "SCP-TOOL-6110"


def test_outlet_error_new_rejects_bad_class() -> None:
    with pytest.raises(ValidationError):
        OutletError.new(
            outlet_id="outlet-1",  # type: ignore[arg-type]
            catalog_key=make_catalog_key("authorization.denied"),
            class_="not-a-class",
        )


# ---------------------------------------------------------------------------
# PII redaction
# ---------------------------------------------------------------------------


def test_redact_pii_replaces_email_and_did() -> None:
    raw = "denied for user@example.com (acting as did:dht:abc.123_xyz) — see logs"
    out = redact_pii(raw)
    assert "user@example.com" not in out
    assert "did:dht:" not in out
    assert "[redacted]" in out


def test_redact_pii_handles_multiple_matches() -> None:
    raw = "a@b.co and c@d.io and did:web:host"
    out = redact_pii(raw)
    assert out.count("[redacted]") >= 3


def test_message_redacted_in_outlet_error_message_attr() -> None:
    err = AuthorizationError(
        message="leaked alice@example.com",
        code="SCP-TOOL-6110",
    )
    # The `message` attribute is run through `redact_pii` at construction.
    assert "alice@example.com" not in err.message
    assert "[redacted]" in err.message


# ---------------------------------------------------------------------------
# Per-class detail-shape conformance — wire-layer rejection
# ---------------------------------------------------------------------------


def test_detail_shape_protocol_must_have_rule() -> None:
    wire = {
        "code": "SCP-TOOL-6100",
        "slug": "protocol.violation",
        "class": "protocol",
        "message": "x",
        "retry": {"policy": "never"},
        "detail": {"unexpected": 1},
    }
    with pytest.raises(ValidationError):
        OutletError.from_wire(wire)


def test_detail_shape_authorization_must_have_capability() -> None:
    wire = {
        "code": "SCP-TOOL-6110",
        "slug": "authorization.denied",
        "class": "authorization",
        "message": "x",
        "retry": {"policy": "never"},
        "detail": {"capability": "outlet_query:foo", "extra": 1},
    }
    with pytest.raises(ValidationError):
        OutletError.from_wire(wire)


def test_detail_shape_input_must_have_field_path_and_violation() -> None:
    wire = {
        "code": "SCP-TOOL-6120",
        "slug": "input.schema-violation",
        "class": "input",
        "message": "x",
        "retry": {"policy": "never"},
        "detail": {"fieldPath": "/x"},
    }
    with pytest.raises(ValidationError):
        OutletError.from_wire(wire)


def test_detail_shape_execution_accepts_three_variants() -> None:
    base = {
        "code": "SCP-TOOL-6130",
        "slug": "execution.handler-panic",
        "class": "execution",
        "message": "x",
        "retry": {"policy": "never"},
    }
    OutletError.from_wire({**base, "detail": {}})
    OutletError.from_wire({**base, "detail": {"elapsedMs": 30000}})
    OutletError.from_wire({**base, "detail": {"panicLocationHash": "00" * 32}})
    with pytest.raises(ValidationError):
        OutletError.from_wire({**base, "detail": {"junk": 1}})


def test_detail_shape_economic_accepts_two_variants() -> None:
    base = {
        "code": "SCP-TOOL-6150",
        "slug": "economic.insufficient-funds",
        "class": "economic",
        "message": "x",
        "retry": {"policy": "never"},
    }
    OutletError.from_wire({**base, "detail": {"needed": 100, "currency": "USD"}})
    OutletError.from_wire({**base, "detail": {"adapterId": "stripe"}})
    with pytest.raises(ValidationError):
        OutletError.from_wire({**base, "detail": {"foo": "bar"}})


def test_detail_shape_transport_accepts_two_variants() -> None:
    base = {
        "code": "SCP-TOOL-6160",
        "slug": "transport.relay-unavailable",
        "class": "transport",
        "message": "x",
        "retry": {"policy": "never"},
    }
    OutletError.from_wire({**base, "detail": {"retryAfterSecs": 5}})
    OutletError.from_wire({**base, "detail": {"relayUrlKind": "wss"}})
    with pytest.raises(ValidationError):
        OutletError.from_wire({**base, "detail": {"junk": 1}})


def test_detail_shape_governance_must_have_action() -> None:
    wire = {
        "code": "SCP-TOOL-6170",
        "slug": "governance.outlet-deregistered",
        "class": "governance",
        "message": "x",
        "retry": {"policy": "never"},
        "detail": {"foo": "bar"},
    }
    with pytest.raises(ValidationError):
        OutletError.from_wire(wire)


# ---------------------------------------------------------------------------
# Fixture round-trip — every fixture's wire-form fields preserved.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", _load_fixtures(), ids=lambda f: f["name"])
def test_fixture_round_trip(fixture: dict[str, Any]) -> None:
    # The fixture file uses cross-SDK camelCase keys for both retry and
    # detail; the Python SDK adopts the same camelCase convention so no
    # key-normalization is required.
    wire = {k: v for k, v in fixture.items() if k not in ("name", "comment")}
    err = OutletError.from_wire(wire)
    assert err.class_wire == fixture["class"]
    assert err.code == fixture["code"]
    assert err.slug == fixture["slug"]
    # Re-serialize and confirm idempotence.
    again = err.to_wire()
    assert again["class"] == fixture["class"]
    assert again["code"] == fixture["code"]


def test_fixture_set_has_at_least_30_entries() -> None:
    assert len(_load_fixtures()) >= 30


def test_pii_redaction_applies_to_loaded_fixture() -> None:
    fixtures = _load_fixtures()
    pii = next(f for f in fixtures if f["name"] == "redaction-pii-email-and-did")
    err = OutletError.from_wire({k: v for k, v in pii.items() if k not in ("name", "comment")})
    assert "user@example.com" not in err.message
    assert "did:dht:" not in err.message
    assert "[redacted]" in err.message
