"""Seed operation library for cross-bridge parity tests.

Each OpSpec describes:
  - `name`: test ID
  - `py_call`: a function that runs the op on the in-process PyO3 bridge
    and returns a raw dict response (pre-normalization).
  - `node_call`: a dict sent via JSON-RPC to the Bun runner; the runner
    dispatches on the "op" name and returns a raw dict response.
  - `schema`: OpSchema used to normalize both responses for comparison.

Adding a new op is ~20 lines: one `OpSpec`, one `py_call`, one case in
the Bun runner's dispatch. The library is append-only.

MVP: 5 ops per ADR-046. Crypto outputs use shape-only comparators
because we do not yet have a deterministic-seed parameter wired through
all four bridges. See FOLLOWUP.md §1 for the forward-only plan.

Known divergences caught by the harness (all xfail'd — see FOLLOWUP.md):
  - invalid_capability error code: three bridges, three codes.
  - event_log_append starting sequence: bridges disagree on whether a
    ContextCreated event is emitted at create time.

Resolved divergences (previously xfail'd, now full parity):
  - context_id format (§18.4.1): all four bridges emit 64-char lowercase
    hex via `hex::encode(32 random bytes)`. PyO3's `generate_context_id`
    (crates/scp-ffi/src/types.rs) remains the reference.

----------------------------------------------------------------------
XFAIL-STRICT POLICY — READ BEFORE LANDING A FIX
----------------------------------------------------------------------
The `xfail_bridges` / `xfail_reason` fields on an OpSpec translate to
`@pytest.mark.xfail(strict=True)` in `test_bridge_parity.py`. "Strict"
means: if the divergence is fixed and the test starts PASSING, CI FAILS
with XPASS. That is by design — silent passes would hide that the fix
also needs a harness update.

When fixing any divergence listed in FOLLOWUP.md §3 / §4 / §5, your PR
MUST also remove the corresponding `xfail_bridges` and `xfail_reason`
fields from the OpSpec below (and update FOLLOWUP.md's "Current state"
/ "Action" sections to reflect the resolution). Otherwise xfail-strict
will turn your fix into a CI failure.

Each xfail'd op below carries an inline comment pointing at its
FOLLOWUP.md section. When you land a fix:
  1. Remove `xfail_bridges=(...)` and `xfail_reason=...` from the OpSpec.
  2. Update the op's docstring block to drop the "xfail'd" language.
  3. Update FOLLOWUP.md — mark the section resolved or delete it.
  4. Run the full parity suite locally; all 10 cases should pass.
----------------------------------------------------------------------
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .normalizer import FieldSpec, OpSchema

# ---------------------------------------------------------------------------
# Shape constants — single source of truth for what cross-bridge output
# is expected to look like. Updating these is the primary way to tighten
# parity guarantees over time.
# ---------------------------------------------------------------------------

# did:dht zbase32 DIDs are "did:dht:z" + 40..200 zbase32 chars.
# zbase32 alphabet (RFC draft): ybndrfg8ejkmcpqxot1uwisza345h769
DID_DHT_PATTERN = r"did:dht:z[ybndrfg8ejkmcpqxot1uwisza345h769]{40,200}"

# Spec §18.4.1: context IDs MUST be 64-char lowercase hex. All four bridges
# (PyO3, NAPI, WASM, UniFFI) now emit spec-compliant hex IDs via
# `hex::encode(32 random bytes)` — regex is fully anchored to reject any
# non-conformant format (e.g. the legacy `ctx-<uuidv4>` shape the parity
# harness caught).
CONTEXT_ID_PATTERN = r"^[0-9a-f]{64}$"

# All three bridges reject the malformed SCPID challenge with
# SCP-IDENT-1038 (validation error) before they ever reach the identity
# registry lookup. This is the parity we want: the challenge's
# protocol/shape validation is shared via scp-protocol, so all bridges
# agree on the code.
#
# Note: a valid-challenge + unregistered-DID path WOULD diverge (PyO3
# SCP-IDENT-1001 vs NAPI SCP-PERM-3023 vs WASM SCP-IDENT-1010). That is
# tracked in FOLLOWUP.md §4 but is not exercised by this op — the
# malformed-challenge path is what was spec'd in ADR-046 for the MVP.
EXPECTED_INVALID_CAPABILITY_CODE = "SCP-IDENT-1038"


# ---------------------------------------------------------------------------
# OpSpec: a single cross-bridge op
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OpContext:
    """Per-op execution context passed to py_call.

    Holds the imported PyO3 module so py_call closures don't need to
    re-import. Carries a scratch dict for ops that build on each other
    within a single test (none do currently, but the hook is here for
    future expansion without a refactor).
    """

    scp_core: Any
    scratch: dict[str, Any]


@dataclass(frozen=True)
class OpSpec:
    name: str
    py_call: Callable[[OpContext], dict[str, Any]]
    node_call: dict[str, Any]
    schema: OpSchema
    # Bridges for which this op is a known divergence (xfail'd). Tracked in
    # FOLLOWUP.md. Empty tuple means all bridges are expected to pass.
    xfail_bridges: tuple[str, ...] = ()
    xfail_reason: str = ""
    # Post-normalization absolute-value assertions. Each tuple is
    # (dotted_field_path, expected_value). Checked AFTER the PyO3 vs alt
    # bridge equality assert — so both sides must agree on the value AND
    # the value must equal the literal we committed to.
    #
    # Rationale: "exact" comparators only verify that PyO3 and the alt
    # bridge produce the SAME value. If all bridges drift together (e.g.
    # all three start returning "UNKNOWN"), parity holds but the spec
    # commitment breaks silently. `expected_values` pins the ground truth.
    #
    # Use for fields whose value is a spec-level commitment (error codes,
    # protocol strings). Do NOT use for values that legitimately vary per
    # call (DIDs, signatures, timestamps) — those belong on `FieldSpec`
    # as `regex`/`timestamp_window`.
    expected_values: tuple[tuple[str, Any], ...] = ()


def _extract_code(text: str) -> str | None:
    """Best-effort extraction of an SCP-XXXX-NNNN code from a message."""
    m = re.search(r"SCP-[A-Z]+-\d+", text)
    return m.group(0) if m else None


# ---------------------------------------------------------------------------
# op 1: identity_create_deterministic
#
# Each bridge creates its own identity with OsRng-backed key generation
# and returns the DID + custody type. DID shape is regex-checked. The
# verifying key is NOT compared: PyO3's `identity_resolve` hits the
# DHT (which does not contain the fresh identity), and the bridges do
# not expose a direct pubkey getter on PyIdentity. Adding that accessor
# is in FOLLOWUP.md along with the deterministic seed parameter.
# ---------------------------------------------------------------------------


def _py_identity_create(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    return {"did": identity.did, "custody": "in_memory"}


OP_IDENTITY_CREATE = OpSpec(
    name="identity_create_deterministic",
    py_call=_py_identity_create,
    node_call={"op": "identity_create", "args": {"custody": "in_memory"}},
    schema=OpSchema(
        fields=(
            FieldSpec("did", "regex", pattern=DID_DHT_PATTERN),
            FieldSpec("custody", "exact"),
        )
    ),
)


# ---------------------------------------------------------------------------
# op 2: context_create
#
# Random context ID per bridge, freshly-created identity per bridge.
# Compare shapes plus the deterministic `mode` echo. The context_id
# regex is anchored to the spec-compliant hex form per §18.4.1 — all
# four bridges (PyO3, NAPI, WASM, UniFFI) emit `hex::encode(32 random
# bytes)`.
# ---------------------------------------------------------------------------


def _py_context_create(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    params = {"name": "parity-test", "mode": "encrypted"}
    handle = ctx.scp_core.py_context_create(identity.did, params)
    return {
        "context_id": handle.context_id,
        "creator_did": identity.did,
        "mode": "encrypted",
    }


OP_CONTEXT_CREATE = OpSpec(
    name="context_create",
    py_call=_py_context_create,
    node_call={
        "op": "context_create",
        "args": {"params": {"name": "parity-test", "mode": "encrypted"}},
    },
    schema=OpSchema(
        fields=(
            FieldSpec("context_id", "regex", pattern=CONTEXT_ID_PATTERN),
            FieldSpec("creator_did", "regex", pattern=DID_DHT_PATTERN),
            FieldSpec("mode", "exact"),
        )
    ),
)


# ---------------------------------------------------------------------------
# op 3: invalid_capability_rejected
#
# Error-path parity: both bridges must reject an invalid SCPID sign
# attempt with a structured error code. The DID is unregistered (we
# pass a syntactically valid but never-created DID).
#
# Real divergence caught by the harness: three bridges, three codes.
# PyO3 returns SCP-IDENT-1001 (reference); NAPI returns SCP-PERM-3023;
# WASM returns SCP-IDENT-1010. See FOLLOWUP.md §4. The NAPI and WASM
# cases are xfail'd until the codes are aligned.
# ---------------------------------------------------------------------------


def _py_invalid_sign(ctx: OpContext) -> dict[str, Any]:
    try:
        ctx.scp_core.scpid_sign(
            "did:dht:znevercreatednevercreatednevercreatednevercreated",
            "#active",
            '{"protocol":"scpid/1","nonce":"00","audience":"x","issued_at":0,"expires_at":0}',
        )
    except Exception as err:  # we want the error shape — test surface
        err_type = type(err).__name__
        code = getattr(err, "code", None) or _extract_code(str(err))
        return {
            "error": {
                "type": err_type,
                "code": code or "UNKNOWN",
                "message": str(err),
            }
        }
    return {"error": {"type": "none", "code": "NONE", "message": "no error raised"}}


OP_INVALID_CAPABILITY = OpSpec(
    name="invalid_capability_rejected",
    py_call=_py_invalid_sign,
    node_call={"op": "invalid_capability_rejected", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("error.type", "ignore"),
            # `error.code` must be an exact match. All three bridges
            # should produce EXPECTED_INVALID_CAPABILITY_CODE for this
            # malformed-challenge path.
            FieldSpec("error.code", "exact"),
            FieldSpec("error.message", "ignore"),
        )
    ),
    # Pin the absolute value so joint drift (e.g. all bridges switching
    # to "UNKNOWN" together) cannot pass parity silently. FOLLOWUP.md §4
    # commits to SCP-IDENT-1038 as the shared code for the malformed-
    # challenge path; this assertion enforces that commitment.
    expected_values=(("error.code", EXPECTED_INVALID_CAPABILITY_CODE),),
)


# ---------------------------------------------------------------------------
# op 4: event_log_append
#
# Cross-bridge exposed path: create a context, then query the event log.
# Compare event count + first event type + starting sequence exactly.
#
# Bridges currently disagree on whether a ContextCreated event is emitted
# at create time, so event_count and first_sequence diverge. NAPI/WASM
# are xfail'd (see FOLLOWUP.md §5). When aligned the xfail lifts without
# schema changes.
# ---------------------------------------------------------------------------


def _py_event_log_append(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    handle = ctx.scp_core.py_context_create(
        identity.did, {"name": "parity-elog", "mode": "encrypted"}
    )
    events = ctx.scp_core.event_log_query(handle.context_id, None)
    first = events[0] if events else None
    if first is None:
        return {"event_count": 0, "first_event_type": "", "first_sequence": 0}
    return {
        "event_count": len(events),
        "first_event_type": str(first.event_type),
        "first_sequence": int(first.sequence),
    }


OP_EVENT_LOG_APPEND = OpSpec(
    name="event_log_append",
    py_call=_py_event_log_append,
    node_call={"op": "event_log_append", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("event_count", "exact"),
            FieldSpec("first_event_type", "exact"),
            FieldSpec("first_sequence", "exact"),
        )
    ),
    # XFAIL (strict): see FOLLOWUP.md §5. When the bridge fix lands, REMOVE
    # `xfail_bridges` and `xfail_reason` below in the SAME PR — xfail-strict
    # will otherwise fail CI with XPASS once the fix unblocks this case.
    xfail_bridges=("napi", "wasm"),
    xfail_reason=(
        "Event log starting state diverges — bridges disagree on "
        "whether ContextCreated is emitted at create time. "
        "See FOLLOWUP.md §5. "
        "Remove this xfail in the same PR that fixes the bridges. "
        "MUST remove xfail marker in the same PR as the fix."
    ),
)


# ---------------------------------------------------------------------------
# op 5: sign_message (via SCPID)
#
# Each bridge creates an identity, generates a challenge with a fixed
# audience + TTL, signs the challenge. Signature byte value is bridge-
# specific (different keys); shape only: protocol exact, DID regex,
# signing_key_id exact, signature regex (128 hex chars = 64 raw bytes).
# When deterministic seeds land (FOLLOWUP.md §1), flip `signature` to
# `bytes_from_hex` and add an expected value for byte-exact parity.
# ---------------------------------------------------------------------------


def _py_sign_message(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    challenge_json = ctx.scp_core.scpid_challenge(
        "https://parity-test.example.com",
        60,
    )
    response_json = ctx.scp_core.scpid_sign(identity.did, "#active", challenge_json)
    response = json.loads(response_json)
    return {
        "protocol": response.get("protocol"),
        "did": response.get("did"),
        "signing_key_id": response.get("signing_key_id"),
        "signature": response.get("signature"),
    }


OP_SIGN_MESSAGE = OpSpec(
    name="sign_message",
    py_call=_py_sign_message,
    node_call={
        "op": "sign_message",
        "args": {
            "audience": "https://parity-test.example.com",
            "ttl_seconds": 60,
            "payload": "parity-test-v1",
        },
    },
    schema=OpSchema(
        fields=(
            FieldSpec("protocol", "exact"),
            FieldSpec("signing_key_id", "exact"),
            FieldSpec("did", "regex", pattern=DID_DHT_PATTERN),
            FieldSpec("signature", "regex", pattern=r"[0-9a-f]{128}"),
        )
    ),
)


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


SEED_OPS: tuple[OpSpec, ...] = (
    OP_IDENTITY_CREATE,
    OP_CONTEXT_CREATE,
    OP_INVALID_CAPABILITY,
    OP_EVENT_LOG_APPEND,
    OP_SIGN_MESSAGE,
)
