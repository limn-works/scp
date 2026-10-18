#!/usr/bin/env python3.12
"""CI gate: one helper owns every thread-blocking wait in the FFI bridges
(ADR-049 Decision 7a, "Host threads"; the human's ruling: "One shared helper
becomes the only code in any bridge allowed to block; the gate fails on any
other blocking call").

A context actor may be waiting on the host for a custody callback, so a
bridge thread that holds the host's lock (the Python GIL, the JS thread)
while it blocks on that actor deadlocks the two, and a `block_on` or
`block_in_place` in the wrong tokio regime panics. `bridge_wait.rs` in
`crates/scp-ffi/common/src/` reads the ambient tokio state once and picks the
regime it permits; every other bridge wait goes through it.

---------------------------------------------------------------------------
RULE (a whitelist)
---------------------------------------------------------------------------
Under `crates/scp-ffi/` (the `PyO3` bridge `src/`, `napi/`, `uniffi/` and
`common/`), the body of the private `fn drive` in `bridge_wait.rs` is the
only production code that may name `block_on` or `block_in_place`. Any other
identifier or field named either way fails: a method call, a path call such
as `Handle::block_on(&h, f)` or `futures::executor::block_on(f)`, a `use`
that imports or renames one, a value reference, and a macro whose tokens
carry one (tree-sitter keeps a macro's tokens as identifiers). The gate also
fails when the helper is missing.

`bridge_wait.rs` is also the only file that may make any other
thread-blocking call. Anywhere else these fail:
  - `std::thread::sleep` (a `thread::sleep` path, or a `use` that imports
    `sleep` from `thread`);
  - `recv_timeout` and `recv_deadline` (a sync channel's timed receive);
  - `recv` and `wait` called without `.await` (a sync channel's receive, a
    `Condvar` or `Barrier` wait); an awaited call, and the future of a
    `select!` arm, are tokio's async forms and pass;
  - `wait_for`, `wait_until`, `wait_while_for` and `wait_while_until`
    called without `.await` (`parking_lot`'s `Condvar` timed waits); an
    awaited call passes, and so does tokio's one-argument
    `watch::Receiver::wait_for(f)` (`h.wait_for(f)` or
    `Receiver::wait_for(h, f)`), whose future may reach `.await` through a
    combinator such as `timeout`;
  - `Condvar`'s `wait_while`, `wait_timeout`, `wait_timeout_ms` and
    `wait_timeout_while`;
  - iterating a sync channel's receiver: `.iter()` or `.into_iter()` called
    on, or a `for` loop over (`for m in rx`, `for m in &rx`,
    `for m in self.rx`), an identifier or field named `rx`, `receiver`, or
    either with a `<word>_` prefix (`event_rx`); `try_iter` does not block
    and passes;
  - any `std::sync::mpsc` (a `std::sync::mpsc` or bare `sync::mpsc` path, a
    `use std::sync::{mpsc, ..}`, the same tokens in a macro, or a glob
    `use std::sync::*` that would let a bare `mpsc` past) and any
    `crossbeam_channel` identifier: a bridge channel is tokio's, so no
    production wait can hide in a sync channel's `recv`;
  - tokio `Runtime::shutdown_timeout`, which blocks until the runtime's
    tasks stop or the timeout passes, and `std::thread::sleep_ms`;
  - tokio's `blocking_recv`, `blocking_recv_many`, `blocking_send`,
    `blocking_lock`, `blocking_lock_owned`, `blocking_read` and
    `blocking_write`;
  - a wait on another thread: `std::thread`'s `JoinHandle::join` (a
    `.join()` method call with no argument, or a path call `X::join(h)` with
    one, that no `.await` consumes; `vec.join(",")`, an awaited tokio
    `JoinHandle` and `JoinSet::join_next().await` pass), and
    `std::thread::park`, `park_timeout`, `park_timeout_ms` and `scope` (whose
    end joins every scoped thread), each as a `thread::` path or a `use` that
    imports it;
  - a glob `use` of `thread` (`use std::thread::*`), which would let a bare
    `sleep`, `park` or `scope` past the path rule.
Such a wait becomes async or goes through the helper. Ordinary std `Mutex`
and `RwLock` acquisition is outside the gate (the human's ruling).

RULE (an exact caller list)
---------------------------------------------------------------------------
`CALLERS` below names every production function that calls a helper wait
or a bridge's thin wrapper over one (`WAIT_NAMES`), with its number of
references. A reference from any other function, a `use` that imports or
renames one, or a count above its entry fails; so does an entry whose count
the code no longer reaches, so the list stays exact. A new sync wait
therefore edits this enforcement file, which needs the human's approval:
napi exposes every production actor wait as `async`, and a `PyO3` caller
must hold no GIL, so a `PyO3` actor wait goes through
`actor_wait::block_on_released` (whose own callers are not listed: it
releases the GIL).

Test code is skipped: a crate's integration tests (a `tests/` directory at a
crate root, never one under `src/`), items whose `#[cfg(..)]` predicate is
false in every build without `test` (`cfg(test)`, `cfg(all(test, ..))`),
files reached only through such a `mod` declaration (following `#[path]`),
and functions carrying `#[test]` or `#[tokio::test]`. A module's name never
makes it test code: a `mod tests` without `cfg(test)` compiles into
production and is scanned. `cfg_attr(test, ..)` changes attributes, not
whether an item compiles, so it marks nothing. Code behind a crate feature
such as `testing`, including `cfg(any(test, feature = "testing"))`, is
production code here.

The tree-sitter parser is that of `scripts/check-block-in-place.py`, which
excludes `crates/scp-ffi/**`, so the two gates do not overlap.

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
# The one function body that may name `block_on` or `block_in_place`.
HELPER_FN = "drive"
NAMES = frozenset({"block_on", "block_in_place"})
WAIT_NAMES = frozenset(
    {
        "bridge_block_on",
        "bridge_block_on_off_thread",
        "bridge_block_on_scoped_thread",
        "block_on_shared",
        "block_on_storage",
    }
)
# (file, enclosing function) -> references to a `WAIT_NAMES` function.
# `<module>` is a reference outside every function (a `use`).
CALLERS: dict[tuple[str, str], int] = {
    ("crates/scp-ffi/common/src/resolvers.rs", "resolve_sync"): 1,
    ("crates/scp-ffi/common/src/ucan_durable_state.rs", "block_on_storage"): 1,
    ("crates/scp-ffi/napi/src/event_log.rs", "event_log_checkpoint_by_did_on"): 1,
    ("crates/scp-ffi/napi/src/event_log.rs", "event_log_checkpoint_on"): 1,
    ("crates/scp-ffi/napi/src/lib.rs", "block_on_shared"): 1,
    ("crates/scp-ffi/napi/src/mcp.rs", "held_role_state"): 1,
    ("crates/scp-ffi/napi/src/runtime.rs", "load_ucan_state_blocking"): 1,
    ("crates/scp-ffi/napi/src/runtime.rs", "persist_ucan_nonces_blocking"): 1,
    ("crates/scp-ffi/napi/src/runtime.rs", "persist_ucan_revocation_blocking"): 1,
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
    ("crates/scp-ffi/src/mcp.rs", "run_outlet"): 1,
    ("crates/scp-ffi/src/runtime.rs", "run_storage_io"): 1,
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
    ("crates/scp-ffi/uniffi/src/runtime.rs", "load_ucan_state_blocking"): 1,
    ("crates/scp-ffi/uniffi/src/runtime.rs", "persist_ucan_nonces_blocking"): 1,
    ("crates/scp-ffi/uniffi/src/runtime.rs", "persist_ucan_revocation_blocking"): 1,
}
# Every other thread-blocking call, which only the helper file
# may make. These names block whenever they are called or named.
ALWAYS_BLOCKING = frozenset(
    {
        "recv_timeout",
        "recv_deadline",
        "shutdown_timeout",
        "sleep_ms",
        "wait_while",
        "wait_timeout",
        "wait_timeout_ms",
        "wait_timeout_while",
        "blocking_recv",
        "blocking_recv_many",
        "blocking_send",
        "blocking_lock",
        "blocking_lock_owned",
        "blocking_read",
        "blocking_write",
    }
)
# These block when called without `.await`: a sync channel's `recv` and a
# `Condvar`'s (or `Barrier`'s) `wait`. Awaited, they are tokio's async forms.
UNAWAITED_BLOCKING = frozenset({"recv", "wait"})
# `parking_lot`'s `Condvar` timed waits, which block when called without
# `.await`. tokio's `watch::Receiver::wait_for(f)` takes only the predicate
# and returns a future that may reach `.await` through a combinator such as
# `timeout(d, rx.wait_for(f))`, so a `wait_for` call with that one argument
# passes; `parking_lot`'s takes a guard and a timeout.
UNAWAITED_TIMED_WAITS = frozenset(
    {"wait_for", "wait_until", "wait_while_for", "wait_while_until"}
)
# A sync channel's receiver, by name: iterating one blocks on every item.
RECEIVER_RE = re.compile(r"^(?:\w+_)?(?:rx|receiver)$")
# The iterator methods that block on a sync channel's receiver.
RECEIVER_ITER_FNS = frozenset({"iter", "into_iter"})
# A path that names `std::sync` (or a bare `sync` imported from it).
STD_SYNC_PATH_RE = re.compile(r"^(?:::)?(?:std::)?sync$")
# Blocking functions of `std::thread`, flagged as a `thread::` path or an
# import from `thread`, with the shape each reports.
THREAD_FNS = {
    "sleep": "std::thread::sleep",
    "park": "std::thread::park",
    "park_timeout": "std::thread::park_timeout",
    "park_timeout_ms": "std::thread::park_timeout_ms",
    "scope": "std::thread::scope",
}
# A crate's integration tests; a `tests/` directory under `src/` is not one.
INTEGRATION_TESTS_RE = re.compile(r"^crates/scp-ffi/(?:napi/|uniffi/|common/)?tests/")

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
    """One production blocking call outside the helper."""

    file: str
    line: int
    shape: str
    snippet: str


def _cfg_value(tokens: list[str], i: int) -> tuple[bool | None, int]:
    """Evaluate one `cfg` predicate starting at `tokens[i]` with `test` false
    and every other option unknown (`None`). Return the value and the index
    after the predicate; raise `ValueError` on a malformed predicate."""
    if i >= len(tokens) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tokens[i]):
        raise ValueError("expected a cfg option")
    name = tokens[i]
    i += 1
    if i < len(tokens) and tokens[i] == "=":
        if i + 1 >= len(tokens) or not tokens[i + 1].startswith('"'):
            raise ValueError("expected a string after `=`")
        return None, i + 2
    if i < len(tokens) and tokens[i] == "(":
        if name not in ("all", "any", "not"):
            raise ValueError(f"unknown cfg combinator `{name}`")
        i += 1
        values: list[bool | None] = []
        while i < len(tokens) and tokens[i] != ")":
            value, i = _cfg_value(tokens, i)
            values.append(value)
            if i < len(tokens) and tokens[i] == ",":
                i += 1
        if i >= len(tokens):
            raise ValueError("unclosed cfg combinator")
        i += 1
        if name == "not":
            if len(values) != 1:
                raise ValueError("`not` takes one predicate")
            return (None if values[0] is None else not values[0]), i
        if name == "all":
            if False in values:
                return False, i
            return (True if all(v is True for v in values) else None), i
        if True in values:
            return True, i
        return (False if all(v is False for v in values) else None), i
    return (False if name == "test" else None), i


def _cfg_excludes_production(predicate: str) -> bool:
    """True when the `cfg` predicate is false in every build without `test`,
    so the item it gates never compiles into production. `cfg(not(test))`,
    `cfg(feature = "testing")` and `cfg(any(test, feature = "testing"))` are
    production; a predicate the parser cannot read is production too."""
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_]*|\S', predicate)
    try:
        value, end = _cfg_value(tokens, 0)
    except ValueError:
        return False
    return end == len(tokens) and value is False


_CFG_ATTR_RE = re.compile(r"#\[\s*cfg\s*\((.*)\)\s*\]", re.DOTALL)
_TEST_ATTR_RE = re.compile(r"#\[(?:[A-Za-z_]+::)*test(?:\(.*\))?\]", re.DOTALL)
_PATH_ATTR_RE = re.compile(r'#\[\s*path\s*=\s*"([^"]*)"\s*\]')


def _outer_attributes(node, source: bytes) -> list[str]:
    """The text of every outer attribute on `node`. Tree-sitter places them
    as preceding siblings, with comments between them."""
    out = []
    sibling = node.prev_sibling
    while sibling is not None and sibling.type in (
        "attribute_item",
        "line_comment",
        "block_comment",
    ):
        if sibling.type == "attribute_item":
            out.append(SCANNER.node_text(sibling, source))
        sibling = sibling.prev_sibling
    return out


def _item_is_test(node, source: bytes) -> bool:
    """True when an item is test code: a `#[cfg(..)]` whose predicate
    excludes every non-test build, or, on a function, `#[test]` or
    `#[tokio::test]`. `cfg_attr(test, ..)` changes attributes, not whether
    the item compiles, so it marks nothing."""
    for text in _outer_attributes(node, source):
        m = _CFG_ATTR_RE.fullmatch(text.strip())
        if m is not None and _cfg_excludes_production(m.group(1)):
            return True
        if node.type == "function_item" and _TEST_ATTR_RE.fullmatch(
            re.sub(r"\s+", "", text)
        ):
            return True
    return False


def _fn_name(node, source: bytes) -> str:
    name = node.child_by_field_name("name")
    return SCANNER.node_text(name, source) if name is not None else ""


def _next_token(node):
    """The next sibling, skipping comments."""
    sibling = node.next_sibling
    while sibling is not None and sibling.type in ("line_comment", "block_comment"):
        sibling = sibling.next_sibling
    return sibling


def _prev_token(node):
    sibling = node.prev_sibling
    while sibling is not None and sibling.type in ("line_comment", "block_comment"):
        sibling = sibling.prev_sibling
    return sibling


def _in_select_arm(token_tree, source: bytes) -> bool:
    """True when `token_tree` is the body of a `select!` or `select_biased!`
    invocation, whose arms await the future between `=` and `=>`."""
    macro = token_tree.parent
    if macro is None or macro.type != "macro_invocation":
        return False
    name = macro.child_by_field_name("macro")
    if name is None:
        return False
    return (
        re.search(r"(?:^|::)select(?:_biased)?$", SCANNER.node_text(name, source))
        is not None
    )


def _token_tree_args(tree, source: bytes) -> int:
    """The number of top-level comma-separated arguments in a `( .. )`
    token tree (nested token trees are single children)."""
    inner = [
        c
        for c in tree.children[1:-1]
        if c.type not in ("line_comment", "block_comment")
    ]
    if not inner:
        return 0
    commas = [i for i, c in enumerate(inner) if SCANNER.node_text(c, source) == ","]
    trailing = 1 if commas and commas[-1] == len(inner) - 1 else 0
    return len(commas) - trailing + 1


def _call_args(call) -> int:
    args = call.child_by_field_name("arguments")
    if args is None:
        return -1
    return sum(
        1
        for c in args.named_children
        if c.type not in ("line_comment", "block_comment")
    )


def _is_thread_join(node, source: bytes) -> bool:
    """True when `node` (a `join` identifier) is `std::thread`'s
    `JoinHandle::join` (or `ScopedJoinHandle::join`): a `.join()` method call
    with no argument, or a path call `X::join(h)` with exactly one, that no
    `.await` consumes. Every other `join` takes a separator or a second
    future (`vec.join(",")`, `Path::join(p, q)`, `future::join(a, b)`), and
    tokio's `JoinHandle` is awaited, not joined."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "token_tree":
        before, after = _prev_token(node), _next_token(node)
        if before is None or after is None or after.type != "token_tree":
            return False
        if not SCANNER.node_text(after, source).startswith("("):
            return False
        sep = SCANNER.node_text(before, source)
        want = 0 if sep == "." else 1 if sep == "::" else None
        if want is None or _token_tree_args(after, source) != want:
            return False
        dot = _next_token(after)
        if dot is None or SCANNER.node_text(dot, source) != ".":
            return True
        word = _next_token(dot)
        return word is None or SCANNER.node_text(word, source) != "await"
    if parent.type == "field_expression":
        want = 0
    elif parent.type == "scoped_identifier":
        want = 1
    else:
        return False
    if not _is_unawaited_call(node, source):
        return False
    return _call_args(parent.parent) == want


def _is_thread_glob(node, source: bytes) -> bool:
    """True when `node` is the `thread` of a `use std::thread::*` (or a
    `use std::{thread::*}`)."""
    if SCANNER.node_text(node, source) != "thread":
        return False
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "scoped_identifier":
        if parent.child_by_field_name("name") != node:
            return False
        parent = parent.parent
    return parent is not None and parent.type == "use_wildcard"


def _is_unawaited_call(node, source: bytes) -> bool:
    """True when `node` (an identifier) is the method or path function of a
    call that no `.await` consumes: `rx.recv()` or `Condvar::wait(&cv, g)`.
    Inside a macro's token tree the call is `ident (..)` after `.` or `::`,
    awaited when `. await` follows or when it is a `select!` arm's future."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "token_tree":
        before, after = _prev_token(node), _next_token(node)
        if before is None or SCANNER.node_text(before, source) not in (".", "::"):
            return False
        if after is None or after.type != "token_tree":
            return False
        if not SCANNER.node_text(after, source).startswith("("):
            return False
        dot = _next_token(after)
        follow = None if dot is None else SCANNER.node_text(dot, source)
        if follow in ("=>", ",") and _in_select_arm(parent, source):
            # `pat = rx.recv() =>` (or `, if guard =>`): `select!` awaits it.
            return False
        if follow != ".":
            return True
        word = _next_token(dot)
        return word is None or SCANNER.node_text(word, source) != "await"
    if parent.type not in ("field_expression", "scoped_identifier"):
        return False
    if (
        parent.child_by_field_name(
            "field" if parent.type == "field_expression" else "name"
        )
        != node
    ):
        return False
    call = parent.parent
    if call is None or call.type != "call_expression":
        return False
    if call.child_by_field_name("function") != parent:
        return False
    outer = call.parent
    while outer is not None and outer.type == "parenthesized_expression":
        outer = outer.parent
    return outer is None or outer.type != "await_expression"


def _path_ends_in_thread(node, source: bytes) -> bool:
    """True when `node` is the last segment of a `thread::<name>` path, a
    `use std::thread::<name>` or a `use std::thread::{<name>, ..}`, in parsed
    code or a macro's tokens."""
    parent = node.parent
    if parent is None:
        return False
    if (
        parent.type == "scoped_identifier"
        and parent.child_by_field_name("name") == node
    ):
        path = parent.child_by_field_name("path")
        return (
            path is not None
            and re.search(r"(?:^|::)thread$", SCANNER.node_text(path, source))
            is not None
        )
    if parent.type == "use_list":
        scoped = parent.parent
        if scoped is not None and scoped.type == "scoped_use_list":
            path = scoped.child_by_field_name("path")
            return (
                path is not None
                and re.search(r"(?:^|::)thread$", SCANNER.node_text(path, source))
                is not None
            )
        return False
    if parent.type == "token_tree":
        sep = _prev_token(node)
        word = _prev_token(sep) if sep is not None else None
        return (
            sep is not None
            and SCANNER.node_text(sep, source) == "::"
            and word is not None
            and SCANNER.node_text(word, source) == "thread"
        )
    return False


def _is_tokio_watch_wait_for(node, source: bytes) -> bool:
    """True when `node` (a `wait_for`) is called with tokio's
    `watch::Receiver::wait_for` arity: one argument after `.`, two after
    `::`. `parking_lot`'s `Condvar::wait_for` takes a guard and a timeout."""
    if SCANNER.node_text(node, source) != "wait_for":
        return False
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "token_tree":
        before, after = _prev_token(node), _next_token(node)
        if before is None or after is None or after.type != "token_tree":
            return False
        want = {".": 1, "::": 2}.get(SCANNER.node_text(before, source))
        return want is not None and _token_tree_args(after, source) == want
    want = {"field_expression": 1, "scoped_identifier": 2}.get(parent.type)
    call = parent.parent
    return (
        want is not None
        and call is not None
        and call.type == "call_expression"
        and _call_args(call) == want
    )


def _is_receiver_iter(node, source: bytes) -> bool:
    """True when `node` (an `iter` or `into_iter`) is a method call on an
    identifier or field named like a receiver (`RECEIVER_RE`): `rx.iter()`,
    `self.event_rx.into_iter()`, in parsed code or a macro's tokens."""
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "token_tree":
        dot, after = _prev_token(node), _next_token(node)
        if dot is None or SCANNER.node_text(dot, source) != ".":
            return False
        if after is None or after.type != "token_tree":
            return False
        if not SCANNER.node_text(after, source).startswith("("):
            return False
        recv = _prev_token(dot)
        return recv is not None and (
            RECEIVER_RE.match(SCANNER.node_text(recv, source)) is not None
        )
    if parent.type != "field_expression" or parent.child_by_field_name("field") != node:
        return False
    call = parent.parent
    if call is None or call.type != "call_expression":
        return False
    if call.child_by_field_name("function") != parent:
        return False
    value = parent.child_by_field_name("value")
    if value is None:
        return False
    if value.type == "field_expression":
        value = value.child_by_field_name("field")
    return (
        value is not None
        and value.type in ("identifier", "field_identifier")
        and RECEIVER_RE.match(SCANNER.node_text(value, source)) is not None
    )


def _is_receiver_for_loop(node, source: bytes) -> bool:
    """True when `node` (an identifier or field named like a receiver) is
    what a `for` loop iterates: `for m in rx`, `for m in &rx`,
    `for m in &mut self.rx`, in parsed code or a macro's tokens."""
    if RECEIVER_RE.match(SCANNER.node_text(node, source)) is None:
        return False
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "token_tree":
        before = _prev_token(node)
        if before is not None and SCANNER.node_text(before, source) == ".":
            owner = _prev_token(before)
            before = _prev_token(owner) if owner is not None else None
        while before is not None and SCANNER.node_text(before, source) in ("&", "mut"):
            before = _prev_token(before)
        if before is None or SCANNER.node_text(before, source) != "in":
            return False
        after = _next_token(node)
        return (
            after is not None
            and after.type == "token_tree"
            and (SCANNER.node_text(after, source).startswith("{"))
        )
    expr = node
    if parent.type == "field_expression":
        if parent.child_by_field_name("field") != node:
            return False
        expr = parent
    while expr.parent is not None and expr.parent.type == "reference_expression":
        expr = expr.parent
    loop = expr.parent
    return (
        loop is not None
        and loop.type == "for_expression"
        and loop.child_by_field_name("value") == expr
    )


def _is_std_mpsc(node, source: bytes) -> bool:
    """True when `node` (an `mpsc`) names `std::sync::mpsc`: the last segment
    of a `std::sync::mpsc` or bare `sync::mpsc` path, an item of a
    `use std::sync::{mpsc, ..}`, or the same tokens in a macro. tokio's
    `tokio::sync::mpsc` passes."""
    if SCANNER.node_text(node, source) != "mpsc":
        return False
    parent = node.parent
    if parent is None:
        return False
    if (
        parent.type == "scoped_identifier"
        and parent.child_by_field_name("name") == node
    ):
        path = parent.child_by_field_name("path")
        return path is not None and (
            STD_SYNC_PATH_RE.match(SCANNER.node_text(path, source)) is not None
        )
    if parent.type == "use_list":
        scoped = parent.parent
        if scoped is not None and scoped.type == "scoped_use_list":
            path = scoped.child_by_field_name("path")
            return path is not None and (
                STD_SYNC_PATH_RE.match(SCANNER.node_text(path, source)) is not None
            )
        return False
    if parent.type == "token_tree":
        sep = _prev_token(node)
        if sep is None or SCANNER.node_text(sep, source) != "::":
            return False
        sync = _prev_token(sep)
        if sync is None or SCANNER.node_text(sync, source) != "sync":
            return False
        sep = _prev_token(sync)
        if sep is None or SCANNER.node_text(sep, source) != "::":
            return True
        root = _prev_token(sep)
        return root is None or SCANNER.node_text(root, source) == "std"
    return False


def _is_std_sync_glob(node, source: bytes) -> bool:
    """True when `node` is the `sync` of a `use std::sync::*`, which would
    let a bare `mpsc::channel()` past the path rule."""
    if SCANNER.node_text(node, source) != "sync":
        return False
    parent = node.parent
    if parent is None or parent.type != "scoped_identifier":
        return False
    if parent.child_by_field_name("name") != node:
        return False
    path = parent.child_by_field_name("path")
    if path is None or SCANNER.node_text(path, source) not in ("std", "::std"):
        return False
    use = parent.parent
    return use is not None and use.type == "use_wildcard"


def _blocking_shape(node, source: bytes) -> str | None:
    """The blocking-call shape `node` names, if any. Only an
    identifier is ever a site, so a macro's tokens are read the same way as
    parsed code (tree-sitter keeps them as identifiers in a token tree)."""
    if node.type not in ("identifier", "field_identifier"):
        return None
    name = SCANNER.node_text(node, source)
    if name in NAMES:
        return name
    if name in ALWAYS_BLOCKING:
        return name
    if name in THREAD_FNS and _path_ends_in_thread(node, source):
        return THREAD_FNS[name]
    if name == "join" and _is_thread_join(node, source):
        return "std::thread JoinHandle::join"
    if _is_thread_glob(node, source):
        return "glob `use` of std::thread"
    if name in UNAWAITED_BLOCKING and _is_unawaited_call(node, source):
        return f"un-awaited `{name}`"
    if (
        name in UNAWAITED_TIMED_WAITS
        and _is_unawaited_call(node, source)
        and not _is_tokio_watch_wait_for(node, source)
    ):
        return f"un-awaited `{name}`"
    if name in RECEIVER_ITER_FNS and _is_receiver_iter(node, source):
        return f"sync receiver `{name}`"
    if _is_receiver_for_loop(node, source):
        return "`for` loop over a sync receiver"
    if _is_std_mpsc(node, source):
        return "std::sync::mpsc"
    if _is_std_sync_glob(node, source):
        return "glob `use` of std::sync"
    if name == "crossbeam_channel":
        return "crossbeam_channel"
    return None


def scan(
    path: Path, rel: str, is_helper_file: bool
) -> tuple[list[Site], int, dict[tuple[str, str], int]]:
    """Return the production sites in one file, the number of helper
    definitions found (0 unless `is_helper_file`), and the references to
    `WAIT_NAMES` functions per enclosing function. In the helper file only
    `block_on`/`block_in_place` outside `drive` are sites: the
    file owns every other blocking shape."""
    source = path.read_bytes()
    lines = source.decode("utf-8", errors="replace").splitlines()
    tree = SCANNER.PARSER.parse(source)
    sites: dict[int, Site] = {}
    helpers = 0
    callers: dict[tuple[str, str], int] = {}

    def record(node, shape: str) -> None:
        line_1 = node.start_point[0] + 1
        if line_1 not in sites:
            text = lines[line_1 - 1].strip() if line_1 <= len(lines) else ""
            sites[line_1] = Site(rel, line_1, shape, text[:100])

    def walk(node, in_test: bool, fn: str) -> None:
        nonlocal helpers
        test = in_test
        if node.type in ("mod_item", "function_item", "impl_item") and _item_is_test(
            node, source
        ):
            test = True
        if node.type == "function_item":
            if is_helper_file and not test and _fn_name(node, source) == HELPER_FN:
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
        if not test:
            shape = _blocking_shape(node, source)
            if shape is not None and (not is_helper_file or shape in NAMES):
                record(node, shape)
        for child in node.children:
            walk(child, test, fn)

    walk(tree.root_node, False, "<module>")
    return sorted(sites.values(), key=lambda s: s.line), helpers, callers


def _module_test_files(repo: Path) -> set[str]:
    """Files that compile only as test code: every file reached through a
    `mod` declaration that `_item_is_test` marks (directly or through an
    ancestor module) and through no production declaration. The module tree
    starts at each crate root (`src/lib.rs`, `src/main.rs`, `src/bin/*.rs`,
    `build.rs`) and follows `#[path]`. A file the walk never reaches stays
    production, so the walk fails closed."""
    reached: dict[Path, bool] = {}  # file -> reached only as test code

    def visit(file: Path, base: Path, in_test: bool) -> None:
        resolved = file.resolve()
        seen = reached.get(resolved)
        if seen is not None and (seen is False or in_test):
            return
        reached[resolved] = in_test
        source = file.read_bytes()
        items(
            SCANNER.PARSER.parse(source).root_node, source, base, file.parent, in_test
        )

    def items(node, source: bytes, base: Path, path_dir: Path, in_test: bool) -> None:
        for child in node.children:
            if child.type != "mod_item":
                continue
            test = in_test or _item_is_test(child, source)
            name = _fn_name(child, source)
            path_attr = None
            for text in _outer_attributes(child, source):
                m = _PATH_ATTR_RE.fullmatch(text.strip())
                if m is not None:
                    path_attr = m.group(1)
            body = child.child_by_field_name("body")
            if body is not None:
                inner = base / (path_attr if path_attr else name)
                items(body, source, inner, inner, test)
                continue
            if path_attr is not None:
                target = path_dir / path_attr
                child_base = target.parent
            else:
                target = base / f"{name}.rs"
                if not target.is_file():
                    target = base / name / "mod.rs"
                child_base = base / name
            if target.is_file():
                visit(target, child_base, test)

    root = repo / BRIDGES_ROOT
    for path in sorted(root.rglob("*.rs")):
        rel = path.relative_to(root).as_posix()
        if "/target/" in f"/{rel}":
            continue
        crate_root = re.search(r"(?:^|/)src/(?:lib|main)\.rs$", rel) or re.search(
            r"(?:^|/)src/bin/[^/]+\.rs$", rel
        )
        if crate_root is not None or path.name == "build.rs":
            visit(path, path.parent, False)
    return {
        p.relative_to(repo.resolve()).as_posix()
        for p, only_test in reached.items()
        if only_test
    }


def production_files(repo: Path) -> list[str]:
    """Every `.rs` file under the bridges except a crate's integration
    tests (a `tests/` directory at a crate root), build output, and files
    that compile only as test modules. A `tests/` directory inside `src/`
    is scanned unless a test-gated `mod` reaches it."""
    test_modules = _module_test_files(repo)
    out = []
    for path in sorted((repo / BRIDGES_ROOT).rglob("*.rs")):
        rel = path.relative_to(repo).as_posix()
        if INTEGRATION_TESTS_RE.match(rel) or "/target/" in rel:
            continue
        if rel in test_modules:
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
                f"{s.file}:{s.line}: blocking call ({s.shape}) outside "
                f"`{HELPER_FILE}`; wait through `scp_ffi_common::bridge_wait` "
                f"or make the call async: {s.snippet}"
            )
            if list_all:
                out(f"{s.file}:{s.line}: [{s.shape}] {s.snippet}")
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
        f"`{HELPER_FILE}` holds every blocking wait)"
    )
    return 0


def check_file(path: Path, quiet: bool = False) -> int:
    sites, _, _ = scan(path, path.as_posix(), is_helper_file=False)
    if not quiet:
        for s in sites:
            print(f"FAIL {s.file}:{s.line}: [{s.shape}] {s.snippet}")
    return 1 if sites else 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_HELPER_SRC = """fn drive<F>(rt: &tokio::runtime::Runtime, fut: F) -> F::Output
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
        "a second `drive` outside the helper file": (
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
    common = BRIDGE_ROOTS["common"]
    sleep_site = (
        "pub fn f() { std::thread::sleep(std::time::Duration::from_millis(1)); }\n"
    )
    join_site = "pub fn f(h: std::thread::JoinHandle<()>) { let _ = h.join(); }\n"
    park_site = "pub fn f() { std::thread::park(); }\n"
    extra.update(
        {
            # G1: only a crate root's `tests/` holds integration tests.
            "a `src/x/tests/mod.rs` (PyO3)": ({pyo3 + "x/tests/mod.rs": _BARE_SITE}, 1),
            "a `src/x/tests/mod.rs` a production `mod` reaches (napi)": (
                {
                    napi + "lib.rs": _CALLS_HELPER + "pub mod x;\n",
                    napi + "x.rs": "mod tests;\n",
                    napi + "x/tests/mod.rs": _BARE_SITE,
                },
                1,
            ),
            "a crate-root integration test (UniFFI)": (
                {"crates/scp-ffi/uniffi/tests/t.rs": _BARE_SITE},
                0,
            ),
            "a crate-root integration test (PyO3)": (
                {"crates/scp-ffi/tests/t.rs": _BARE_SITE},
                0,
            ),
            "an out-of-line `cfg(test)` module (UniFFI)": (
                {
                    uniffi + "lib.rs": _CALLS_HELPER + "#[cfg(test)]\nmod tests;\n",
                    uniffi + "tests.rs": _BARE_SITE + "mod deeper;\n",
                    uniffi + "tests/deeper.rs": sleep_site,
                },
                0,
            ),
            "an out-of-line `cfg(test)` `#[path]` module (common)": (
                {
                    common
                    + "lib.rs": '#[cfg(test)]\n#[path = "lib_tests.rs"]\nmod tests;\n',
                    common + "lib_tests.rs": _BARE_SITE,
                },
                0,
            ),
            "a file reached through both a test and a production `mod` (napi)": (
                {
                    napi + "lib.rs": _CALLS_HELPER
                    + '#[cfg(test)]\nmod t;\n#[path = "t.rs"]\nmod p;\n',
                    napi + "t.rs": _BARE_SITE,
                },
                1,
            ),
            # G2: `cfg_attr(test, ..)` marks nothing.
            "an out-of-line `cfg_attr(test, ..)` module (PyO3)": (
                {
                    pyo3 + "lib.rs": _CALLS_HELPER
                    + "#[cfg_attr(test, allow(dead_code))]\nmod m;\n",
                    pyo3 + "m.rs": _BARE_SITE,
                },
                1,
            ),
            # G3: `cfg(any(test, feature = "testing"))` is production.
            "an out-of-line `cfg(any(test, feature))` module (napi)": (
                {
                    napi + "lib.rs": _CALLS_HELPER
                    + '#[cfg(any(test, feature = "testing"))]\nmod m;\n',
                    napi + "m.rs": _BARE_SITE,
                },
                1,
            ),
            # Blocking shapes other than `block_on`: only the helper file
            # may make them.
            "a `recv_timeout` in UniFFI": (
                {
                    uniffi
                    + "m.rs": "pub fn f(rx: &std::sync::mpsc::Receiver<u8>) { let _ = rx.recv_timeout(std::time::Duration::ZERO); }\n"
                },
                1,
            ),
            "a `blocking_lock` in PyO3": (
                {
                    pyo3
                    + "m.rs": "pub fn f(m: &tokio::sync::Mutex<u8>) { let _ = m.blocking_lock(); }\n"
                },
                1,
            ),
            "an awaited `rx.recv().await` in napi": (
                {
                    napi
                    + "m.rs": "pub async fn f(rx: &mut tokio::sync::mpsc::Receiver<u8>) { let _ = rx.recv().await; }\n"
                },
                0,
            ),
            "a `std::thread::sleep` in the helper file": (
                {HELPER_FILE: _HELPER_SRC + sleep_site},
                0,
            ),
            "a scoped-thread `join` in the helper file": (
                {
                    HELPER_FILE: _HELPER_SRC
                    + "fn g() { std::thread::scope(|s| { let _ = s.spawn(|| ()).join(); }); }\n"
                },
                0,
            ),
        }
    )
    for bridge, root in BRIDGE_ROOTS.items():
        extra[f"a `std::thread::sleep` in the {bridge} bridge"] = (
            {root + "sleep.rs": sleep_site},
            1,
        )
        extra[f"a `JoinHandle::join` in the {bridge} bridge"] = (
            {root + "join.rs": join_site},
            1,
        )
        extra[f"a `std::thread::park` in the {bridge} bridge"] = (
            {root + "park.rs": park_site},
            1,
        )
        extra[f"a `std::sync::mpsc` channel in the {bridge} bridge"] = (
            {
                root
                + "mpsc.rs": "pub fn f() { let _ = std::sync::mpsc::channel::<u8>(); }\n"
            },
            1,
        )
        extra[f"a `crossbeam_channel` in the {bridge} bridge"] = (
            {
                root
                + "cb.rs": "pub fn f() { let _ = crossbeam_channel::bounded::<u8>(1); }\n"
            },
            1,
        )
        extra[f"a `for` loop over a receiver in the {bridge} bridge"] = (
            {root + "rxloop.rs": "pub fn f(rx: Rx) { for m in rx { drop(m); } }\n"},
            1,
        )
        extra[f"a receiver `.iter()` in the {bridge} bridge"] = (
            {root + "rxiter.rs": "pub fn f(rx: &Rx) { for _ in rx.iter() {} }\n"},
            1,
        )
        extra[f"a `shutdown_timeout` in the {bridge} bridge"] = (
            {root + "shut.rs": "pub fn f(rt: Rt) { rt.shutdown_timeout(D); }\n"},
            1,
        )
        extra[f"a `std::thread::sleep_ms` in the {bridge} bridge"] = (
            {root + "sleepms.rs": "pub fn f() { std::thread::sleep_ms(1); }\n"},
            1,
        )
        extra[f"a `Condvar::wait_for` in the {bridge} bridge"] = (
            {
                root
                + "cv.rs": "pub fn f(cv: &Cv, g: &mut G) { let _ = cv.wait_for(g, D); }\n"
            },
            1,
        )
        extra[f"a `Condvar::wait_until` in the {bridge} bridge"] = (
            {
                root
                + "cvu.rs": "pub fn f(cv: &Cv, g: &mut G) { let _ = cv.wait_until(g, I); }\n"
            },
            1,
        )
        extra[f"a tokio watch `wait_for` under `timeout` in the {bridge} bridge"] = (
            {
                root
                + "watch.rs": "pub async fn f(rx: &mut W) { let _ = tokio::time::timeout(D, rx.wait_for(|s| *s)).await; }\n"
            },
            0,
        )
        extra[f"a `tokio::sync::mpsc` channel in the {bridge} bridge"] = (
            {
                root
                + "tmpsc.rs": "pub fn f() { let _ = tokio::sync::mpsc::channel::<u8>(1); }\n"
            },
            0,
        )
        extra[f"a `vec.join(sep)` in the {bridge} bridge"] = (
            {root + "strjoin.rs": 'pub fn f(v: &[String]) -> String { v.join(",") }\n'},
            0,
        )
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
    """The fixture names each function `flag_*` (must be flagged), `pass_*`
    (production code that must not be flagged) or `test_*` (test code, never
    seen); the fixture trees exercise `real_scan` per bridge."""
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
        if name.startswith("pass_") and found:
            problems.append(
                f"{name}: a non-blocking call was flagged: {found[0].shape}"
            )
        if name.startswith("test_") and found:
            problems.append(f"{name}: test code was scanned")
    for prefix in ("flag_", "pass_", "test_"):
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
