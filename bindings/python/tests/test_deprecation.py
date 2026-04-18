"""Tests for the default-instance deprecation scaffold (#1549 Phase 4 PR 1).

These tests verify two contracts:

1. Free-function façade calls that implicitly use the default bridge
   instance emit :class:`DeprecationWarning` on their *first* call per
   function, and stay silent on subsequent calls.
2. Using the explicit :class:`scp_sdk.SCP` class emits NO deprecation
   warnings — it is the non-deprecated entry point callers are being
   directed toward.

See ADR-048 for the full sunset rationale and removal timeline.
"""

from __future__ import annotations

import warnings

import pytest

try:
    from scp_sdk import _scp_core  # noqa: F401
except (ImportError, AttributeError):
    pytest.skip(
        "Native _scp_core extension not available — run maturin develop first",
        allow_module_level=True,
    )

import scp_sdk
from scp_sdk._deprecation import _reset_emitted_for_tests


def _policy_free_json() -> str:
    """Return a valid 'free' economic policy JSON string.

    Using an empty string or ``"null"`` is the documented way to signal
    a free (no-cost) context to the economy bridge functions.
    """
    return ""


def test_free_function_emits_deprecation_warning_on_first_call() -> None:
    """First invocation of a decorated free function emits one DeprecationWarning.

    Picks :func:`scp_sdk.policy_requires_payment` because it is:
    - Decorated with ``@deprecated_default_instance``.
    - Pure — doesn't require a live bridge instance, no identity setup.
    - Side-effect-free — safe to call repeatedly in tests.
    """
    _reset_emitted_for_tests()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        scp_sdk.policy_requires_payment(_policy_free_json())

    matching = [
        w
        for w in captured
        if issubclass(w.category, DeprecationWarning) and "scp_sdk" in str(w.message)
    ]
    assert len(matching) == 1, (
        f"expected exactly one DeprecationWarning, got {len(matching)}: "
        f"{[str(w.message) for w in captured]}"
    )
    assert "default bridge instance" in str(matching[0].message)
    assert "SCP(" in str(matching[0].message)
    assert "ADR-048" in str(matching[0].message)


def test_free_function_does_not_re_emit_on_subsequent_calls() -> None:
    """Only the first call emits — subsequent calls are silent.

    The one-time-per-function contract is what keeps long-running
    processes from drowning in repeated deprecation warnings.
    """
    _reset_emitted_for_tests()

    # Prime the warning.
    scp_sdk.policy_requires_payment(_policy_free_json())

    # Subsequent calls: no DeprecationWarning for THIS function.
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        scp_sdk.policy_requires_payment(_policy_free_json())
        scp_sdk.policy_requires_payment(_policy_free_json())

    matching = [
        w
        for w in captured
        if issubclass(w.category, DeprecationWarning)
        and "policy_requires_payment" in str(w.message)
    ]
    assert matching == [], (
        "DeprecationWarning for policy_requires_payment re-emitted after first call; "
        f"got {[str(w.message) for w in matching]}"
    )


def test_distinct_functions_each_emit_once() -> None:
    """Different decorated functions each get their own one-time warning.

    The `_emitted` tracker keys on fully-qualified function names, not
    the decorator instance, so warnings for `auto_accept_blocked` and
    `policy_requires_payment` are independent.
    """
    _reset_emitted_for_tests()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        scp_sdk.policy_requires_payment(_policy_free_json())
        scp_sdk.auto_accept_blocked(_policy_free_json())

    names_seen = {
        # Use the name fragment that uniquely identifies the function in
        # the warning message.
        "policy_requires_payment"
        if "policy_requires_payment" in str(w.message)
        else "auto_accept_blocked"
        if "auto_accept_blocked" in str(w.message)
        else ""
        for w in captured
        if issubclass(w.category, DeprecationWarning)
    }
    assert "policy_requires_payment" in names_seen
    assert "auto_accept_blocked" in names_seen


def test_scp_class_construction_emits_no_deprecation() -> None:
    """Constructing :class:`scp_sdk.SCP` emits no DeprecationWarning.

    :class:`SCP` is the non-deprecated entry point — using it must be
    silent for callers who have already migrated off the façade.
    """
    _reset_emitted_for_tests()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        scp = scp_sdk.SCP()
        _ = scp.instance_id  # Touch the getter too.
        # Don't shutdown here — tokio runtime block_on inside pytest's
        # own event loop has historically interacted poorly. The shutdown
        # test lives in test_scp_class.py.

    deprecation_warnings = [w for w in captured if issubclass(w.category, DeprecationWarning)]
    assert deprecation_warnings == [], (
        f"SCP() unexpectedly emitted DeprecationWarning(s): "
        f"{[str(w.message) for w in deprecation_warnings]}"
    )


def test_scp_class_default_emits_no_deprecation() -> None:
    """:meth:`SCP.default` is allowed in transitional code and is silent.

    The façade is deprecated; the explicit default-instance accessor on
    the class is not — callers who genuinely want the shared default
    can reach for it without warnings. The sunset target is the façade
    itself, not the underlying default instance (see ADR-048).
    """
    _reset_emitted_for_tests()

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        default = scp_sdk.SCP.default()
        _ = default.instance_id

    deprecation_warnings = [w for w in captured if issubclass(w.category, DeprecationWarning)]
    assert deprecation_warnings == [], (
        f"SCP.default() emitted DeprecationWarning(s): "
        f"{[str(w.message) for w in deprecation_warnings]}"
    )


def test_scp_wrapper_instance_id_matches_native() -> None:
    """The SDK wrapper's ``instance_id`` matches the native's."""
    scp = scp_sdk.SCP()
    # Native uses a property; SDK wrapper forwards through.
    assert scp.instance_id == int(scp._native.instance_id)
    assert scp.instance_id > 0


def test_scp_context_manager_shuts_down_on_exit() -> None:
    """Using :class:`SCP` as a context manager calls shutdown on exit."""
    with scp_sdk.SCP() as scp:
        original_id = scp.instance_id
    # After exit, shutdown() has been called with the 5-second default.
    # There's no observable "was shut down" flag at the SDK layer; the
    # contract is that shutdown is idempotent and must not raise. A
    # second call confirms the lifecycle completed cleanly.
    scp.shutdown(1.0)
    assert original_id > 0


def test_scp_repr_is_informative() -> None:
    """``repr(SCP())`` must surface the instance id for debugging."""
    scp = scp_sdk.SCP()
    assert str(scp.instance_id) in repr(scp)
    assert "SCP" in repr(scp)
