"""Tell an absent ``_scp_core`` extension apart from one that failed to load.

Python raises ``ImportError`` for both causes, so the exception type decides
nothing: a missing extension and a present ``.so`` whose ``dlopen`` failed —
an undefined symbol, a libpython the module was not built against, a missing
transitive shared library — both arrive here as ``ImportError``. The
extension file's presence is what separates them, and
:func:`extension_is_installed` reports that presence without executing the
file.

The probe asks two questions, because neither one alone finds every present
file. :func:`importlib.util.find_spec` locates a file the running interpreter
would import, which is a file whose name ends in one of
``importlib.machinery.EXTENSION_SUFFIXES``. A module built by a different
interpreter carries that interpreter's tag —
``_scp_core.cpython-311-x86_64-linux-gnu.so`` — which matches none of this
interpreter's suffixes, so ``find_spec`` reports absence while the file sits
in the package directory. :func:`extension_file_on_disk` reads that directory
and answers for such a file.

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
import os
from typing import Any

from scp_sdk.errors import ScpError

#: Import path maturin installs the compiled extension at (see pyproject.toml
#: ``module-name``).
EXTENSION_MODULE = "scp_sdk._scp_core"

#: Dynamic-library suffixes a compiled CPython extension file ends in, across
#: the platforms this SDK ships wheels for: ``.so`` on Linux and macOS,
#: ``.pyd`` on Windows, ``.dylib`` for a macOS build that names its output that
#: way. This list is deliberately not ``importlib.machinery.EXTENSION_SUFFIXES``
#: — that list holds the suffixes the *running* interpreter imports, and a file
#: built by another interpreter is exactly the file this module must still see.
_EXTENSION_FILE_SUFFIXES = (".so", ".pyd", ".dylib")


def extension_file_on_disk() -> bool:
    """Report whether an extension file for :data:`EXTENSION_MODULE` sits in the package.

    CRITERION: the directory holding this module also holds a file whose name
    is the extension module's leaf name, then a ``.``, then any interpreter
    tag, then a dynamic-library suffix — the name CPython gives every compiled
    extension it installs. ``_scp_core.so`` and
    ``_scp_core.cpython-311-x86_64-linux-gnu.so`` both satisfy it;
    ``_scp_core_helper.so``, ``_scp_core.py`` and ``scp.py`` do not.

    maturin installs the extension into that directory, because
    ``pyproject.toml`` names the module ``scp_sdk._scp_core`` and this module
    is ``scp_sdk._extension``.
    """
    leaf = EXTENSION_MODULE.rpartition(".")[2]
    try:
        names = os.listdir(os.path.dirname(os.path.abspath(__file__)))
    except OSError:
        return False
    return any(
        name.startswith(f"{leaf}.") and name.endswith(_EXTENSION_FILE_SUFFIXES) for name in names
    )


def extension_is_installed() -> bool:
    """Report whether a compiled extension file for this SDK is present.

    Returns ``True`` when :func:`importlib.util.find_spec` locates a module
    this interpreter would import, and ``True`` when
    :func:`extension_file_on_disk` finds a file this interpreter would not
    import — a module another interpreter built. Both are present files, and a
    present file makes an ``ImportError`` a load failure rather than an
    absence.
    """
    try:
        if importlib.util.find_spec(EXTENSION_MODULE) is not None:
            return True
    except (ImportError, AttributeError, ValueError):
        pass
    return extension_file_on_disk()


def reject_load_failure(exc: ImportError) -> None:
    """Raise when ``exc`` came from a present extension, return when it came from none.

    Args:
        exc: The ``ImportError`` that importing the extension raised.

    Raises:
        ScpError: ``SCP-UNKNOWN-0002`` when :func:`extension_is_installed`
            reports the extension file is present, which makes ``exc`` a load
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
