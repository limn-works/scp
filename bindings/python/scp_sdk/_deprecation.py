"""One-time deprecation warnings for the default-bridge free-function façade.

See ADR-048 ("SCP multi-instance bridge + check-handle-affinity gate").

Every free function in the SDK that implicitly operates on the process-wide
default :class:`scp_sdk.SCP` instance is wrapped with
:func:`deprecated_default_instance`. The wrapper emits a
:class:`DeprecationWarning` the first time each wrapped function is called
(per interpreter session), and is silent thereafter — this keeps noise
manageable while still guaranteeing that external callers see the signal at
least once.

Removal target for the free-function façade: two release cycles after the
Phase 4 PR 1 merge. See #1549 Phase 4 remainder detail and ADR-048.
"""

from __future__ import annotations

import functools
import warnings
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar, cast

if TYPE_CHECKING:
    import _scp_core

_F = TypeVar("_F", bound=Callable[..., Any])


def resolve_scp(scp: _scp_core.SCP | None) -> _scp_core.SCP:
    """Return *scp* when provided, otherwise the process-wide default instance.

    Called by every SDK function that was previously routed through a free
    ``_scp_core.py_*`` call. Accepting an optional :class:`_scp_core.SCP`
    parameter and defaulting to ``SCP.default_instance()`` keeps the
    existing back-compat surface working while letting new code thread
    caller-owned instances end-to-end (ADR-048, #1549 Phase 4 PR 4).

    The lookup imports ``_scp_core`` lazily so SDK modules can be imported
    in pure-Python environments (e.g. the documentation build) that do not
    link the native extension. Resolution failures surface as the same
    ``ScpError`` / ``ImportError`` that the :class:`scp_sdk.SCP` wrapper
    would raise.

    :param scp: An explicit :class:`_scp_core.SCP` instance, or ``None``.
    :returns: The resolved instance (caller-provided or the shared default).
    """
    if scp is not None:
        return scp
    import _scp_core

    return _scp_core.SCP.default_instance()


# Fully-qualified function names (``module.qualname``) that have already
# emitted their one-time DeprecationWarning in this interpreter. Keyed by
# qualname rather than the function object so decorator identity and
# pickling don't interfere.
_emitted: set[str] = set()


def deprecated_default_instance(func: _F) -> _F:
    """Decorator that emits a one-time :class:`DeprecationWarning` per call site.

    The wrapped function continues to delegate to the process-wide default
    :class:`scp_sdk.SCP` instance. The warning points callers at the
    :class:`scp_sdk.SCP` class (the non-deprecated entry point) and at
    ADR-048 for the full sunset rationale and removal timeline.

    The warning is emitted at most once per fully-qualified function name
    for the lifetime of the interpreter. This keeps log noise manageable in
    long-running processes while still making the deprecation impossible to
    miss the first time an external caller hits it.

    :param func: The free-function-level SDK entry point to wrap. Must
        implicitly delegate to the default bridge instance.
    :returns: A wrapped callable with identical signature and behavior,
        plus a one-time warning side effect.
    """
    name = f"{func.__module__}.{func.__qualname__}"

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if name not in _emitted:
            _emitted.add(name)
            warnings.warn(
                (
                    f"scp_sdk.{func.__name__} uses the default bridge instance "
                    "and is deprecated; construct an explicit scp_sdk.SCP(...) "
                    "and call methods on it instead. Removal target: two "
                    "release cycles after Phase 4 merge (ADR-048)."
                ),
                DeprecationWarning,
                stacklevel=2,
            )
        return func(*args, **kwargs)

    return cast("_F", wrapper)


def _reset_emitted_for_tests() -> None:
    """Test-only helper: clear the one-time-warning tracker.

    Exposed so tests can exercise the "first call emits, second is silent"
    contract repeatedly within a single pytest session without leaking
    state across tests.
    """
    _emitted.clear()
