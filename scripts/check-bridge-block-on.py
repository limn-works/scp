#!/usr/bin/env python3.12
"""CI gate: one helper owns every thread-blocking wait in the FFI bridges
(ADR-049 Decision 7a, "Host threads").

A context actor may be waiting on the host for a custody callback, so a
bridge thread that holds the host's lock (the Python GIL, the JS thread)
while it blocks on that actor deadlocks the two, and a `block_on` or
`block_in_place` in the wrong tokio regime panics. `bridge_block_on` in
`crates/scp-ffi/common/src/bridge_wait.rs` picks the regime the ambient
tokio state permits; every other bridge wait goes through it.

---------------------------------------------------------------------------
RULE (a whitelist)
---------------------------------------------------------------------------
Under `crates/scp-ffi/` (the `PyO3` bridge `src/`, `napi/`, `uniffi/` and
`common/`), the body of `fn bridge_block_on` in `bridge_wait.rs` is the only
production code that may name `block_on` or `block_in_place`. Any other
identifier or field named either way fails: a method call, a path call such
as `Handle::block_on(&h, f)` or `futures::executor::block_on(f)`, a `use`
that imports or renames one, a value reference, and a macro whose tokens
carry one. There is no per-site directive. The gate also fails when the
helper is missing.

RULE (an exact caller list)
---------------------------------------------------------------------------
`CALLERS` below names every production function that calls the helper or a
bridge's thin wrapper over it (`WAIT_NAMES`), with its number of
references. A reference from any other function, a `use` that imports or
renames one, or a count above its entry fails; so does an entry whose count
the code no longer reaches, so the list stays exact. A new sync wait
therefore edits this enforcement file, which needs the human's approval:
napi exposes every production actor wait as `async`, and a `PyO3` caller
must hold no GIL, so a `PyO3` actor wait goes through
`actor_wait::block_on_released` (whose own callers are not listed: it
releases the GIL).

Test code is skipped: files under a `tests/` directory, `mod` items gated on
`cfg(test)`, and functions carrying `#[test]`, `#[tokio::test]` or a
`cfg(test)` gate. A module's name never makes it test code: a `mod tests`
without `cfg(test)` compiles into production and is scanned. Code behind a
crate feature such as `testing` is production code here.

The tree-sitter parser and its `cfg(test)` parsing are those of
`scripts/check-block-in-place.py`, which excludes `crates/scp-ffi/**`, so
the two gates do not overlap.

---------------------------------------------------------------------------
USAGE
---------------------------------------------------------------------------
    python3.12 scripts/check-bridge-block-on.py              # real scan
    python3.12 scripts/check-bridge-block-on.py --self-test  # fixtures
    python3.12 scripts/check-bridge-block-on.py --list       # every site
    python3.12 scripts/check-bridge-block-on.py --check-file FILE
        # scan FILE as a non-helper file and fail on any site

Exit codes: 0 pass, 1 violation or self-test failure, 2 invocation error.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCANNER_PATH = REPO_ROOT / "scripts" / "check-block-in-place.py"
FIXTURE_FILE = REPO_ROOT / "scripts" / "tests" / "bridge-block-on-fixture.rs"

BRIDGES_ROOT = "crates/scp-ffi/"
HELPER_FILE = "crates/scp-ffi/common/src/bridge_wait.rs"
HELPER_FN = "bridge_block_on"
NAMES = frozenset({"block_on", "block_in_place"})
WAIT_NAMES = frozenset(
    {"bridge_block_on", "bridge_block_on_off_thread", "block_on_shared"}
)
# (file, enclosing function) -> references to a `WAIT_NAMES` function.
# `<module>` is a reference outside every function (a `use`).
CALLERS: dict[tuple[str, str], int] = {
    ("crates/scp-ffi/common/src/bridge_wait.rs", "bridge_block_on_off_thread"): 2,
    ("crates/scp-ffi/common/src/resolvers.rs", "resolve_sync"): 1,
    ("crates/scp-ffi/napi/src/event_log.rs", "event_log_checkpoint_by_did_on"): 1,
    ("crates/scp-ffi/napi/src/event_log.rs", "event_log_checkpoint_on"): 1,
    ("crates/scp-ffi/napi/src/lib.rs", "block_on_shared"): 1,
    ("crates/scp-ffi/napi/src/mcp.rs", "held_role_state"): 1,
    ("crates/scp-ffi/napi/src/scp.rs", "identity_execute_custody_migration"): 1,
    ("crates/scp-ffi/napi/src/scpid.rs", "scpid_sign_on"): 1,
    ("crates/scp-ffi/napi/src/scpid.rs", "scpid_verify_on"): 1,
    ("crates/scp-ffi/napi/src/testing.rs", "fullstack_add_member_on"): 1,
    ("crates/scp-ffi/napi/src/testing.rs", "fullstack_create_context_on"): 1,
    ("crates/scp-ffi/napi/src/testing.rs", "fullstack_decrypt_message_on"): 1,
    ("crates/scp-ffi/napi/src/testing.rs", "fullstack_join_from_welcome_on"): 1,
    ("crates/scp-ffi/napi/src/testing.rs", "fullstack_remove_member_on"): 1,
    ("crates/scp-ffi/napi/src/testing.rs", "fullstack_seed_peer_pseudonym_on"): 1,
    ("crates/scp-ffi/napi/src/testing.rs", "fullstack_send_message_on"): 1,
    ("crates/scp-ffi/napi/src/ucan.rs", "ucan_delegate_on"): 1,
    ("crates/scp-ffi/src/actor_wait.rs", "<module>"): 1,
    ("crates/scp-ffi/src/actor_wait.rs", "block_on_released"): 1,
    ("crates/scp-ffi/src/identity.rs", "identity_execute_custody_migration"): 1,
    ("crates/scp-ffi/src/lib.rs", "drain_runtime"): 1,
    ("crates/scp-ffi/src/mcp.rs", "block_on_provider_task"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "add_relay"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "address_resolve"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "event_log_checkpoint_by_did_impl"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "event_log_checkpoint_impl"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "gate_active_lifecycle"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "identity_execute_custody_migration"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "outlet_grant"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "role_state_of"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "run_outlet"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "scpid_sign_impl"): 1,
    ("crates/scp-ffi/uniffi/src/bridge.rs", "scpid_verify_on"): 1,
    ("crates/scp-ffi/uniffi/src/lib.rs", "block_on_shared"): 1,
}
NAME_RE = re.compile(r"\b(?:block_on|block_in_place)\b")

# One root per bridge, for the self-test's per-bridge fixture trees.
BRIDGE_ROOTS = {
    "PyO3": "crates/scp-ffi/src/",
    "napi": "crates/scp-ffi/napi/src/",
    "UniFFI": "crates/scp-ffi/uniffi/src/",
    "common": "crates/scp-ffi/common/src/",
}


def _load_scanner():
    spec = importlib.util.spec_from_file_location("check_block_in_place", SCANNER_PATH)
    if spec is None or spec.loader is None:
        sys.stderr.write(f"error: cannot load {SCANNER_PATH}\n")
        sys.exit(2)
    module = importlib.util.module_from_spec(spec)
    # `@dataclass` resolves its class's module through `sys.modules`.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCANNER = _load_scanner()


@dataclass
class Site:
    """One production reference to `block_on` or `block_in_place`."""

    file: str
    line: int
    snippet: str


def _fn_is_test(node, source: bytes) -> bool:
    """True when a function_item carries `#[test]`, `#[tokio::test]`, or a
    `cfg` attribute that gates on `test`."""
    sibling = node.prev_sibling
    while sibling is not None:
        if sibling.type == "attribute_item":
            text = SCANNER.node_text(sibling, source)
            body = re.sub(r"\s+", "", text)
            if re.match(r"#\[(?:[A-Za-z_]+::)*test(?:\(.*\))?\]$", body):
                return True
            for m in re.finditer(r"cfg(?:_attr)?\((.*)\)", text, flags=re.DOTALL):
                if SCANNER._cfg_gates_on_test(m.group(1)):
                    return True
            sibling = sibling.prev_sibling
            continue
        if sibling.type in ("line_comment", "block_comment"):
            sibling = sibling.prev_sibling
            continue
        break
    return False


def _fn_name(node, source: bytes) -> str:
    name = node.child_by_field_name("name")
    return SCANNER.node_text(name, source) if name is not None else ""


def _names_a_blocking_wait(node, source: bytes) -> bool:
    """True for an identifier or field named `block_on` or `block_in_place`,
    and for a macro whose tokens carry either name."""
    if node.type in ("identifier", "field_identifier"):
        return SCANNER.node_text(node, source) in NAMES
    if node.type in ("macro_invocation", "macro_definition", "macro_rules_definition"):
        return NAME_RE.search(SCANNER.node_text(node, source)) is not None
    return False


def scan(
    path: Path, rel: str, is_helper_file: bool
) -> tuple[list[Site], int, dict[tuple[str, str], int]]:
    """Return the production sites in one file outside the helper's body,
    the number of helper definitions found (0 unless `is_helper_file`), and
    the references to `WAIT_NAMES` functions per enclosing function."""
    source = path.read_bytes()
    lines = source.decode("utf-8", errors="replace").splitlines()
    tree = SCANNER.PARSER.parse(source)
    sites: dict[int, Site] = {}
    helpers = 0
    callers: dict[tuple[str, str], int] = {}

    def record(node) -> None:
        line_1 = node.start_point[0] + 1
        if line_1 not in sites:
            text = lines[line_1 - 1].strip() if line_1 <= len(lines) else ""
            sites[line_1] = Site(rel, line_1, text[:100])

    def walk(node, in_test: bool, fn: str) -> None:
        nonlocal helpers
        test = in_test
        if node.type == "mod_item" and SCANNER.has_test_cfg_attribute(node, source):
            test = True
        elif node.type == "function_item":
            if _fn_is_test(node, source):
                test = True
            elif is_helper_file and not in_test and _fn_name(node, source) == HELPER_FN:
                # The whitelisted body. Its own name is not a site.
                helpers += 1
                return
            fn = _fn_name(node, source)
        if (
            not test
            and node.type == "identifier"
            and SCANNER.node_text(node, source) in WAIT_NAMES
        ):
            parent = node.parent
            defines = (
                parent is not None
                and parent.type == "function_item"
                and (parent.child_by_field_name("name") == node)
            )
            if not defines:
                callers[(rel, fn)] = callers.get((rel, fn), 0) + 1
        if not test and _names_a_blocking_wait(node, source):
            record(node)
        for child in node.children:
            walk(child, test, fn)

    walk(tree.root_node, False, "<module>")
    return sorted(sites.values(), key=lambda s: s.line), helpers, callers


def production_files(repo: Path) -> list[str]:
    out = []
    for path in sorted((repo / BRIDGES_ROOT).rglob("*.rs")):
        rel = path.relative_to(repo).as_posix()
        if "/tests/" in rel or "/target/" in rel:
            continue
        out.append(rel)
    return out


def real_scan(
    list_all: bool,
    repo: Path = REPO_ROOT,
    quiet: bool = False,
    allowed: dict[tuple[str, str], int] | None = None,
) -> int:
    """Scan every bridge under `repo` against `allowed` (default `CALLERS`).
    `quiet` suppresses all output, for the self-test's fixture trees."""
    out = (lambda *_a, **_k: None) if quiet else print
    allowed = CALLERS if allowed is None else allowed
    failures: list[str] = []
    helpers = 0
    callers: dict[tuple[str, str], int] = {}
    files = production_files(repo)
    for rel in files:
        is_helper_file = rel == HELPER_FILE
        sites, found, file_callers = scan(repo / rel, rel, is_helper_file)
        helpers += found
        callers.update(file_callers)
        for s in sites:
            failures.append(
                f"{s.file}:{s.line}: `block_on`/`block_in_place` outside "
                f"`{HELPER_FN}`; call `scp_ffi_common::bridge_wait::{HELPER_FN}` "
                f"(or a bridge wrapper over it): {s.snippet}"
            )
            if list_all:
                out(f"{s.file}:{s.line}: {s.snippet}")
    for key in sorted(set(callers) | set(allowed)):
        got, budget = callers.get(key, 0), allowed.get(key, 0)
        if got != budget:
            failures.append(
                f"{key[0]}: `{key[1]}` references a bridge wait {got} time(s); "
                f"`CALLERS` allows exactly {budget}. A new sync wait needs the "
                "human's approval to extend `CALLERS`; a removed one lowers it."
            )
        if list_all and got:
            out(f"{key[0]}: {key[1]} calls a bridge wait {got} time(s)")
    if helpers != 1:
        failures.append(
            f"{HELPER_FILE}: expected exactly one production `fn {HELPER_FN}`, found {helpers}"
        )
    if failures:
        for f in failures:
            out(f"FAIL {f}")
        out(f"check-bridge-block-on: {len(failures)} violation(s)")
        return 1
    out(
        f"check-bridge-block-on: OK ({len(files)} production files; "
        f"`{HELPER_FN}` is the only blocking wait)"
    )
    return 0


def check_file(path: Path, quiet: bool = False) -> int:
    sites, _, _ = scan(path, path.as_posix(), is_helper_file=False)
    if not quiet:
        for s in sites:
            print(f"FAIL {s.file}:{s.line}: {s.snippet}")
    return 1 if sites else 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_HELPER_SRC = """pub fn bridge_block_on<F>(rt: &tokio::runtime::Runtime, fut: F) -> F::Output
where
    F: std::future::Future,
{
    match tokio::runtime::Handle::try_current() {
        Ok(h) => tokio::task::block_in_place(|| h.block_on(fut)),
        Err(_) => rt.block_on(fut),
    }
}
"""

_BARE_SITE = """pub fn production(rt: &tokio::runtime::Runtime) {
    rt.block_on(async {});
}
"""

_CALLS_HELPER = """pub fn production(rt: &tokio::runtime::Runtime) {
    scp_ffi_common::bridge_wait::bridge_block_on(rt, async {});
}
"""

_UNCFGD_TESTS_MODULE = "mod tests {\n" + _BARE_SITE + "}\n"


def _tree_verdict(files: dict[str, str], allowed: dict[tuple[str, str], int]) -> int:
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        for rel, body in files.items():
            path = repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        return real_scan(False, repo, quiet=True, allowed=allowed)


def _real_scan_fixture_trees() -> list[str]:
    """Run `real_scan` over fixture trees. Each bridge gets a tree whose only
    violation sits in that bridge's root, which must fail; the clean tree,
    whose bridges reach the wait only through the helper, must pass."""
    problems: list[str] = []
    clean = {HELPER_FILE: _HELPER_SRC}
    allowed: dict[tuple[str, str], int] = {}
    for root in BRIDGE_ROOTS.values():
        if root == BRIDGE_ROOTS["common"]:
            clean[root + "lib.rs"] = ""
        else:
            clean[root + "lib.rs"] = _CALLS_HELPER
            allowed[(root + "lib.rs", "production")] = 1
    cases: list[tuple[str, dict[str, str], int]] = [("the clean tree", clean, 0)]
    for bridge, root in BRIDGE_ROOTS.items():
        tree = dict(clean)
        tree[root + "violation.rs"] = _BARE_SITE
        cases.append((f"a bare `.block_on` in the {bridge} bridge", tree, 1))
    napi = BRIDGE_ROOTS["napi"]
    uniffi = BRIDGE_ROOTS["UniFFI"]
    pyo3 = BRIDGE_ROOTS["PyO3"]
    extra = {
        "an uncfg'd `mod tests` (PyO3)": ({pyo3 + "m.rs": _UNCFGD_TESTS_MODULE}, 1),
        "a `cfg(test)` module (PyO3)": (
            {pyo3 + "m.rs": "#[cfg(test)]\n" + _UNCFGD_TESTS_MODULE},
            0,
        ),
        "a `block_in_place` in napi": (
            {napi + "m.rs": "pub fn f() { tokio::task::block_in_place(|| ()); }\n"},
            1,
        ),
        "a renaming `use` in UniFFI": (
            {
                uniffi
                + "m.rs": "use tokio::task::block_in_place as bip;\npub fn f() { bip(|| ()); }\n"
            },
            1,
        ),
        "a free `futures::executor::block_on` in napi": (
            {napi + "m.rs": "pub fn f() { futures::executor::block_on(async {}); }\n"},
            1,
        ),
        "a UFCS `Handle::block_on` in UniFFI": (
            {
                uniffi
                + "m.rs": "pub fn f(h: &tokio::runtime::Handle) { tokio::runtime::Handle::block_on(h, async {}); }\n"
            },
            1,
        ),
        "a macro carrying `.block_on` in napi": (
            {
                napi
                + "m.rs": "pub fn f(rt: &tokio::runtime::Runtime) { drop(vec![rt.block_on(async { 1 })]); }\n"
            },
            1,
        ),
        "an old-style `ci-allow` directive in napi": (
            {
                napi
                + "m.rs": "pub fn f(rt: &tokio::runtime::Runtime) {\n    // ci-allow: bridge-block-on: no longer an exemption\n    rt.block_on(async {});\n}\n"
            },
            1,
        ),
        "a `testing`-feature function in napi": (
            {napi + "m.rs": '#[cfg(feature = "testing")]\n' + _BARE_SITE},
            1,
        ),
        "a second `bridge_block_on` outside the helper file": (
            {uniffi + "m.rs": _HELPER_SRC},
            1,
        ),
        "an unlisted napi caller of `block_on_shared`": (
            {
                napi
                + "m.rs": "pub fn f() { let _ = crate::block_on_shared(async {}); }\n"
            },
            1,
        ),
        "an unlisted PyO3 caller of `bridge_block_on`": (
            {pyo3 + "m.rs": _CALLS_HELPER},
            1,
        ),
        "a renaming `use` of the helper in UniFFI": (
            {
                uniffi
                + "m.rs": "use scp_ffi_common::bridge_wait::bridge_block_on as w;\n"
            },
            1,
        ),
        "a listed caller that calls twice (napi)": (
            {
                napi + "lib.rs": _CALLS_HELPER.replace(
                    "{\n",
                    "{\n    scp_ffi_common::bridge_wait::bridge_block_on(rt, async {});\n",
                    1,
                )
            },
            1,
        ),
        "a `cfg(test)` caller of `block_on_shared` (napi)": (
            {
                napi
                + "m.rs": "#[cfg(test)]\nmod t { fn f() { let _ = crate::block_on_shared(async {}); } }\n"
            },
            0,
        ),
    }
    for label, (files, expected) in extra.items():
        cases.append((label, {**clean, **files}, expected))
    no_helper = {k: v for k, v in clean.items() if k != HELPER_FILE}
    cases.append(("a tree without the helper", no_helper, 1))
    stale = {k: v for k, v in clean.items() if k != pyo3 + "lib.rs"}
    cases.append(("a `CALLERS` entry the code no longer reaches", stale, 1))
    for label, files, expected in cases:
        got = _tree_verdict(files, allowed)
        if got != expected:
            problems.append(
                f"real_scan over {label} returned {got}, expected {expected}"
            )
    return problems


def self_test() -> int:
    """The fixture names each function `flag_*` (must be flagged) or
    `test_*` (test code, never seen); the fixture trees exercise
    `real_scan` per bridge."""
    sites, _, _ = scan(FIXTURE_FILE, "fixture", is_helper_file=False)
    source = FIXTURE_FILE.read_bytes()
    tree = SCANNER.PARSER.parse(source)
    ranges: dict[str, tuple[int, int]] = {}

    def collect(node) -> None:
        if node.type == "function_item":
            ranges[_fn_name(node, source)] = (
                node.start_point[0] + 1,
                node.end_point[0] + 1,
            )
        for child in node.children:
            collect(child)

    collect(tree.root_node)

    problems: list[str] = []
    for name, (lo, hi) in ranges.items():
        found = [s for s in sites if lo <= s.line <= hi]
        if name.startswith("flag_") and not found:
            problems.append(f"{name}: a blocking wait was not flagged")
        if name.startswith("test_") and found:
            problems.append(f"{name}: test code was scanned")
    for prefix in ("flag_", "test_"):
        if not any(n.startswith(prefix) for n in ranges):
            problems.append(f"fixture has no `{prefix}*` case")
    if check_file(FIXTURE_FILE, quiet=True) == 0:
        problems.append("--check-file passed a fixture that holds violations")
    problems.extend(_real_scan_fixture_trees())
    if problems:
        for p in problems:
            print(f"SELF-TEST FAIL {p}")
        return 1
    print(f"check-bridge-block-on self-test: OK ({len(ranges)} fixture functions)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--check-file", type=Path)
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.check_file is not None:
        return check_file(args.check_file)
    return real_scan(args.list)


if __name__ == "__main__":
    sys.exit(main())
