"""Tell an absent ``_scp_core`` extension apart from one that failed to load.

Python raises ``ImportError`` for both causes, so the exception type decides
nothing: a missing extension and a present ``.so`` whose ``dlopen`` failed —
an undefined symbol, a libpython the module was not built against, a missing
transitive shared library — both arrive here as ``ImportError``. The
extension file's presence on the import path is what separates them, and
:func:`importlib.util.find_spec` locates that file without executing it.

:func:`reject_load_failure` applies the separation. ``scp_sdk/__init__.py``
swallows an absent extension, which lets a pure-Python environment import the
package, and raises :class:`~scp_sdk.errors.ScpError` carrying
``SCP-UNKNOWN-0002`` for a load failure. That error is not an ``ImportError``,
so every ``except ImportError: pytest.skip(...)`` guard in
``bindings/python/tests`` lets it through and the job fails instead of exiting
0 over zero executed assertions.
"""

from __future__ import annotations

import importlib.util
from typing import Any

from scp_sdk.errors import ScpError

#: Import path maturin installs the compiled extension at (see pyproject.toml
#: ``module-name``).
EXTENSION_MODULE = "scp_sdk._scp_core"


def extension_is_installed() -> bool:
    """Report whether the compiled extension file sits on the import path."""
    try:
        return importlib.util.find_spec(EXTENSION_MODULE) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def reject_load_failure(exc: ImportError) -> None:
    """Raise when ``exc`` came from a present extension, return when it came from none.

    Args:
        exc: The ``ImportError`` that importing the extension raised.

    Raises:
        ScpError: ``SCP-UNKNOWN-0002`` when :func:`extension_is_installed`
            reports the file is on the import path, which makes ``exc`` a load
            failure rather than an absence.
    """
    if not extension_is_installed():
        return
    raise ScpError(
        f"The {EXTENSION_MODULE} extension module is installed but failed to "
        f"load: {exc}. Rebuild it for this interpreter with "
        f"`maturin develop --release` from bindings/python.",
        code="SCP-UNKNOWN-0002",
    ) from exc


def native_module() -> Any:
    """Return the ``_scp_core`` extension module, imported lazily.

    Raised at call time, not at import time, so a pure-Python environment can
    import :mod:`scp_sdk` and reach a meaningful error the first time it uses
    the bridge.

    Raises:
        ScpError: ``SCP-UNKNOWN-0001`` when the extension is not installed,
            ``SCP-UNKNOWN-0002`` when the extension is installed and failed to
            load. The two codes differ because the ``scp`` fixture in
            ``bindings/python/tests/conftest.py`` skips on the first and fails
            on the second.
    """
    try:
        import _scp_core  # type: ignore[import-not-found]
    except ImportError as exc:
        reject_load_failure(exc)
        raise ScpError(
            "The _scp_core extension module is not installed. "
            "Install scp-python with: pip install scp-python",
            code="SCP-UNKNOWN-0001",
        ) from exc
    return _scp_core
