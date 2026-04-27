"""SCP-OUT-041d — Python SDK unit tests for OutletError.new options-object
form and the catalog-rotation dwell-time validator.

These tests focus on the SDK-side wrappers: argument validation, FFI
delegation behavior, and the typed error surfacing path. They do NOT
require a live FFI extension (the FFI path is exercised end-to-end by
the conformance fixture and the e2e integration tests).
"""

from __future__ import annotations

import time

import pytest

from scp_sdk.errors import (
    AuthorizationError,
    OutletError,
    OutletProtocolError,
    RetryPolicy,
    ValidationError,
)
from scp_sdk.outlets import outlet_catalog_rotation_validator


def test_new_keyword_only_accepts_valid_args() -> None:
    """OutletError.new constructs a typed subclass for valid inputs."""
    err = OutletError.new(
        outlet_id="outlet-test",
        catalog_key="authorization.denied",
        class_="authorization",
    )
    assert isinstance(err, AuthorizationError)
    assert err.class_wire == "authorization"


def test_new_rejects_invalid_catalog_key() -> None:
    """Malformed catalog keys raise OutletProtocolError."""
    with pytest.raises(OutletProtocolError):
        OutletError.new(
            outlet_id="outlet-test",
            catalog_key="INVALID UPPER",
            class_="authorization",
        )


def test_new_rejects_unknown_class() -> None:
    with pytest.raises(ValidationError):
        OutletError.new(
            outlet_id="outlet-test",
            catalog_key="authorization.denied",
            class_="not-a-real-class",
        )


def test_new_rejects_empty_outlet_id() -> None:
    with pytest.raises(ValidationError):
        OutletError.new(
            outlet_id="",
            catalog_key="authorization.denied",
            class_="authorization",
        )


def test_new_keyword_only_blocks_positional() -> None:
    """The leading * forces keyword-only invocation."""
    with pytest.raises(TypeError):
        # type: ignore[misc] — intentionally wrong call shape for the test.
        OutletError.new("outlet", "authorization.denied", "authorization")  # type: ignore[arg-type]


def test_new_retry_default_is_never() -> None:
    err = OutletError.new(
        outlet_id="outlet-test",
        catalog_key="authorization.denied",
        class_="authorization",
    )
    assert err.retry == RetryPolicy.never()


def test_outlet_catalog_rotation_validator_silent_when_unchanged() -> None:
    """SCP-OUT-041c: catalog unchanged is exempt from the dwell rule.

    Skipped when the FFI extension is not loadable (test_outlet_error_new
    does not require maturin develop to run, but the validator does).
    """
    pytest.importorskip("_scp_core")
    same_catalog = [{"key": "authorization.denied", "template": "denied"}]
    # Even at delta=0, identical catalog short-circuits to Ok.
    outlet_catalog_rotation_validator(
        prior_catalog=same_catalog,
        new_catalog=same_catalog,
        prior_append_time_secs=int(time.time()),
        new_append_time_secs=int(time.time()),
    )


def test_outlet_catalog_rotation_validator_rejects_within_24h() -> None:
    pytest.importorskip("_scp_core")
    prior = [{"key": "authorization.denied", "template": "denied"}]
    new = [{"key": "authorization.expired", "template": "expired"}]
    t0 = int(time.time())
    # 23.99 hours
    t_inside = t0 + 86_400 - 60
    with pytest.raises(OutletError) as excinfo:
        outlet_catalog_rotation_validator(
            prior_catalog=prior,
            new_catalog=new,
            prior_append_time_secs=t0,
            new_append_time_secs=t_inside,
        )
    err = excinfo.value
    assert err.class_wire == "protocol"
    assert err.code == "SCP-TOOL-6100"


def test_outlet_catalog_rotation_validator_accepts_after_24h() -> None:
    pytest.importorskip("_scp_core")
    prior = [{"key": "authorization.denied", "template": "denied"}]
    new = [{"key": "authorization.expired", "template": "expired"}]
    t0 = int(time.time())
    t_after = t0 + 86_400 + 60
    outlet_catalog_rotation_validator(
        prior_catalog=prior,
        new_catalog=new,
        prior_append_time_secs=t0,
        new_append_time_secs=t_after,
    )
