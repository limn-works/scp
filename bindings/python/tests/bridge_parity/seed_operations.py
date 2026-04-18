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

MVP: 5 ops per ADR-046. Crypto outputs now compare byte-exactly where
possible: `identity_create_deterministic` pins DID + identity-key
verifying bytes under a fixed seed. `sign_message` remains shape-only
for the signature itself because Ed25519 covers a timestamp that
cannot be frozen across bridges without a testing-feature clock
injection — see FOLLOWUP.md §1 for the follow-up.

Resolved divergences (previously xfail'd tripwires, now full parity):
  - context_id format (§18.4.1): all four bridges emit 64-char lowercase
    hex via `hex::encode(32 random bytes)`. PyO3's `generate_context_id`
    (crates/scp-ffi/src/types.rs) remains the reference.
  - event_log_append starting sequence: all bridges emit `ContextCreated`
    at context-create time via `builder_create_context`. PyO3 was rewired
    from `NoOpEventLogProvider` to `MerkleEventLogProvider` matching the
    NAPI/UniFFI bridges.
  - invalid_capability_rejected unregistered-DID code: aligned on
    SCP-IDENT-1001 (identity-domain, identity-not-found) across bridges.
    The MVP op below exercises the malformed-challenge path
    (SCP-IDENT-1038, shared); a future `unregistered_did_rejected` op
    will lock IDENT-1001 into the parity gate.

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
# Note: the valid-challenge + unregistered-DID path historically diverged
# (PyO3 SCP-IDENT-1001, NAPI SCP-PERM-3023, WASM SCP-IDENT-1010). All three
# bridges are now aligned on SCP-IDENT-1001 (identity-domain, identity-not-
# found). The MVP op below still exercises the malformed-challenge path per
# ADR-046; an `unregistered_did_rejected` op added in a follow-up will lock
# the IDENT-1001 alignment into the parity gate.
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
# Each bridge creates its own identity using a FIXED 32-byte seed fed
# through the `testing`-gated `seed` parameter on `identity_create`. The
# seed drives `rand::rngs::StdRng::from_seed` (same KDF across every
# bridge per ADR-046 / FOLLOWUP.md §1), so:
#   - the identity-key Ed25519 private bytes are byte-identical,
#   - the DID derived from `z{zbase32(identity_pubkey)}` is byte-identical,
#   - the exposed `verifying_key` hex is byte-identical.
#
# Both `did` and `verifying_key` are compared EXACTLY against the known
# expected values below. Any drift in the underlying keygen or DID
# derivation breaks the test immediately.
# ---------------------------------------------------------------------------


# Fixed 32-byte seed used by every bridge on this op. 0x7B chosen
# arbitrarily — any stable seed works; changing it invalidates the
# expected DID/verifying_key below (recompute both).
PARITY_SEED_HEX = "7b" * 32

# Expected outputs under `PARITY_SEED_HEX`. These are the ground truth
# the bridges are being held to. If legitimate key-derivation changes
# (e.g. StdRng algorithm update) require moving these, update all four
# bridges AND these constants in the same PR.
#
# Derivation: `SigningKey::from_bytes(StdRng::from_seed([0x7b; 32])
# .fill_bytes(32))`, verifying key = SigningKey.verifying_key().to_bytes().
# DID = `did:dht:z{zbase32(verifying_key)}`.
#
# To regenerate after a legitimate KDF bump, run:
#   cargo test -p scp-identity print_parity_seed_expected_values \
#     -- --ignored --nocapture
EXPECTED_SEEDED_VERIFYING_KEY_HEX = (
    "4a08f8429d35967b4f0e2d987f45e1220d8173ace4097a539a6103ced5611f0c"
)
EXPECTED_SEEDED_DID = "did:dht:zjerxoow7gsm8suaqfsc86txbreganh7chorzwwh4crbh7imbdhgy"


def _py_identity_create(ctx: OpContext) -> dict[str, Any]:
    seed = bytes.fromhex(PARITY_SEED_HEX)
    identity = ctx.scp_core.py_identity_create("in_memory", seed)
    return {
        "did": identity.did,
        "custody": "in_memory",
        "verifying_key": identity.verifying_key,
    }


OP_IDENTITY_CREATE = OpSpec(
    name="identity_create_deterministic",
    py_call=_py_identity_create,
    node_call={
        "op": "identity_create",
        "args": {"custody": "in_memory", "seed_hex": PARITY_SEED_HEX},
    },
    schema=OpSchema(
        fields=(
            # Exact DID + verifying_key comparison is the whole point of
            # the seeded path: both sides must derive the same bytes.
            FieldSpec("did", "exact"),
            FieldSpec("custody", "exact"),
            FieldSpec("verifying_key", "bytes_from_hex"),
        )
    ),
    # Ground-truth pinning: the `expected_values` tuples below anchor
    # the DID + verifying_key to the literal outputs produced by
    # `SigningKey::from_bytes(StdRng::from_seed([0x7b; 32]).fill_bytes(32))`.
    # If the KDF ever changes (e.g. rand crate algorithm bump), these
    # constants must move in the same PR that changes all four bridges.
    expected_values=(
        ("did", EXPECTED_SEEDED_DID),
        # `bytes_from_hex` canonicalizes to base64 in the normalizer, so
        # the expected value must also be the base64 of the raw key.
        (
            "verifying_key",
            __import__("base64")
            .b64encode(bytes.fromhex(EXPECTED_SEEDED_VERIFYING_KEY_HEX))
            .decode("ascii"),
        ),
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
# All four bridges (PyO3, NAPI, WASM, UniFFI) emit a `ContextCreated`
# event at context-create time via `builder_create_context` in scp-runtime.
# The PyO3 bridge was previously wired to `NoOpEventLogProvider` and so
# returned an empty log for this path; it now uses `MerkleEventLogProvider`
# matching the other bridges.
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
)


# ---------------------------------------------------------------------------
# op 5: sign_message (via SCPID)
#
# Each bridge creates an identity using the shared parity seed, then
# generates a challenge and signs it. `did`, `signing_key_id`, and
# `protocol` are byte-exact cross-bridge. Signature bytes remain
# shape-only — Ed25519 signatures cover the canonical hash which
# includes `signed_at = SystemTime::now() / js_sys::Date::now()`, so
# two bridges signing a millisecond apart produce different signatures
# even with identical keys and challenges. A future op may freeze the
# clock via a testing-feature override to enable byte-exact signature
# parity; see FOLLOWUP.md §1 for the clock-injection follow-up.
#
# Additionally, `#active` in scp-core is the SECOND key generated by
# `DidDht::create` (see crate docs). The WASM bridge uses a single-key
# model where `#active` resolves to the identity key. So even with a
# shared seed, `#active`-signed signatures differ between WASM and
# scp-core-backed bridges. The seed parity contract only covers the
# identity key (VM `#0`) at this time.
# ---------------------------------------------------------------------------


def _py_sign_message(ctx: OpContext) -> dict[str, Any]:
    seed = bytes.fromhex(PARITY_SEED_HEX)
    identity = ctx.scp_core.py_identity_create("in_memory", seed)
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
            "seed_hex": PARITY_SEED_HEX,
        },
    },
    schema=OpSchema(
        fields=(
            FieldSpec("protocol", "exact"),
            FieldSpec("signing_key_id", "exact"),
            # DID is byte-exact under the shared seed.
            FieldSpec("did", "exact"),
            # Signatures remain shape-only — see module docstring above.
            FieldSpec("signature", "regex", pattern=r"[0-9a-f]{128}"),
        )
    ),
    expected_values=(("did", EXPECTED_SEEDED_DID),),
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
