#!/usr/bin/env python3
"""Keep actions/setup-python, setup-node and setup-java on the runner image's tool cache.

`action.yml` beside this file runs `guard.py before <tool> <versions>`, then the upstream
setup action, then `guard.py after <tool>`.

WHY. None of the three checks what it downloads. setup-python unpacks the
actions/python-versions archive tool-cache's downloadTool fetched with no digest
comparison (src/install-python.ts:133-139 at v5), setup-node does the same with the
nodejs.org archive (src/distributions/base-distribution.ts:146, then 261-275 at v4), and
setup-java with the JDK archive (src/distributions/temurin/installer.ts:80-87 at v4).
Each looks in $RUNNER_TOOL_CACHE first and downloads only on a miss
(setup-python src/find-python.ts:80-99, setup-node base-distribution.ts:36,
setup-java src/distributions/base-installer.ts:49-50). The runner image provisions that
cache, so a hit installs nothing from the network.

`before` fails, naming the tool and version, when the cache holds no complete install
matching a requested version; the action would download one. `after` fails when the
action left an install in the cache that `before` did not see, which catches a version
match this script and the action resolve differently. A version no runner image caches
(CPython 3.10) is installed first by `.github/actions/pinned-tool`, which checks the
archive's digest.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# The tool-cache directory each setup action reads (setup-java:
# base-installer.ts:80-81, `Java_${distribution}_${packageType}`; the workflows use
# distribution temurin, whose toolcache name is Temurin-Hotspot).
TOOL_DIRS = {"python": "Python", "node": "node", "java": "Java_Temurin-Hotspot_jdk"}


class GuardError(Exception):
    pass


def tool_root(tool: str) -> Path:
    if tool not in TOOL_DIRS:
        raise GuardError(f"unknown tool {tool!r}; expected one of {sorted(TOOL_DIRS)}")
    return Path(os.environ["RUNNER_TOOL_CACHE"], TOOL_DIRS[tool])


def arch() -> str:
    return os.environ["RUNNER_ARCH"].lower()


def complete_installs(tool: str) -> list[str]:
    """Each `<version>` directory under the tool's cache that holds `<arch>.complete`."""
    root = tool_root(tool)
    if not root.is_dir():
        return []
    marker = f"{arch()}.complete"
    return sorted(d.name for d in root.iterdir() if (d / marker).is_file())


def matches(spec: str, installed: str) -> bool:
    """Whether an installed version satisfies a version spec such as `3.12` or `17`."""
    return installed == spec or installed.startswith((spec + ".", spec + "-"))


def snapshot_path(tool: str) -> Path:
    return Path(os.environ["RUNNER_TEMP"], f"toolcache-setup-{tool}.json")


def before(tool: str, versions: str) -> None:
    installs = complete_installs(tool)
    specs = versions.split()
    if not specs:
        raise GuardError(f"{tool}: no version requested")
    missing = [s for s in specs if not any(matches(s, i) for i in installs)]
    if missing:
        raise GuardError(
            f"{tool} {', '.join(missing)} is not in the runner's tool cache "
            f"({tool_root(tool)} holds {installs or 'nothing'} for {arch()}); the setup "
            "action would download it unchecked. Install it with "
            ".github/actions/pinned-tool first, or request a cached version."
        )
    snapshot_path(tool).write_text(json.dumps(installs))
    print(f"{tool}: {', '.join(specs)} resolve from the tool cache ({installs})")


def after(tool: str) -> None:
    seen = set(json.loads(snapshot_path(tool).read_text()))
    added = sorted(set(complete_installs(tool)) - seen)
    if added:
        raise GuardError(
            f"{tool}: the setup action added {', '.join(added)} to the tool cache, so it "
            "downloaded an archive it did not check"
        )
    print(f"{tool}: the setup action downloaded nothing")


def main(argv: list[str]) -> int:
    mode, tool = argv[0], argv[1]
    if mode == "before":
        before(tool, argv[2] if len(argv) > 2 else "")
    elif mode == "after":
        after(tool)
    else:
        raise GuardError(f"unknown mode {mode!r}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except GuardError as error:
        print(f"::error::{error}")
        sys.exit(1)
