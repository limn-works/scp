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

Current op library: 10 ops. The first 5 are the MVP per ADR-046;
ops 6-10 cover tool registration, UCAN mint/validate-error,
transport status, and filtered event-log query. Crypto outputs
compare byte-exactly where
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
# op 6: tool_register
#
# Register a single tool in a fresh context. The tool_id is derived
# deterministically across all four bridges from the tool name via the
# shared `format!("tool-{}", name.replace(' ', "-").to_lowercase())`
# convention (see scp-ffi/src/tools.rs, scp-ffi/napi/src/tools.rs,
# scp-ffi/wasm/src/tools.rs, scp-ffi/uniffi/src/bridge.rs — all four
# use the same format). That makes tool_id byte-exact for parity.
# ---------------------------------------------------------------------------


# Ceiling must include `tool:register` to permit the registration action.
_TOOL_CEILING = ["messages:read", "messages:write", "tool:register", "tool_invoke:*"]
_TOOL_NAME = "parity_probe"
_EXPECTED_TOOL_ID = f"tool-{_TOOL_NAME}"
_TOOL_SCHEMA: dict[str, Any] = {
    "input_schema": {"type": "object", "properties": {"x": {"type": "integer"}}},
    "output_schema": {"type": "object", "properties": {"y": {"type": "integer"}}},
}


def _py_tool_register(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    handle = ctx.scp_core.py_context_create(
        identity.did,
        {"name": "parity-tools", "mode": "encrypted", "ceiling": _TOOL_CEILING},
    )
    tool_id = ctx.scp_core.tool_register(
        handle.context_id,
        {
            "name": _TOOL_NAME,
            "description": "parity harness probe tool",
            "operator_did": identity.did,
            "schema": _TOOL_SCHEMA,
        },
    )
    return {"tool_id": tool_id}


OP_TOOL_REGISTER = OpSpec(
    name="tool_register",
    py_call=_py_tool_register,
    node_call={
        "op": "tool_register",
        "args": {
            "name": _TOOL_NAME,
            "description": "parity harness probe tool",
            "schema": _TOOL_SCHEMA,
            "ceiling": _TOOL_CEILING,
        },
    },
    schema=OpSchema(fields=(FieldSpec("tool_id", "exact"),)),
    # Spec-pin the derivation: `tool-{name-lowercased-spaces-to-dashes}`.
    # Joint drift (e.g. all bridges hash instead of format) would pass
    # parity step 3 but violate the shared convention; this locks it.
    expected_values=(("tool_id", _EXPECTED_TOOL_ID),),
)


# ---------------------------------------------------------------------------
# op 7: ucan_mint
#
# Mint a UCAN in a freshly created context with a pinned member DID and
# capability set. All four bridges return metadata — issuer, audience,
# capabilities — byte-exactly under those inputs. The encoded JWT is
# NOT compared: PyO3's PyUcanToken intentionally does not expose the
# JWT (see crates/scp-ffi/src/ucan.rs), and both the signature and the
# wall-clock `exp` would diverge even if it did. Cross-bridge encoded-
# JWT parity is a follow-up gated on two things: (1) exposing `encoded`
# in PyO3, and (2) clock injection (FOLLOWUP.md §1) — the `exp` field
# prevents byte-exact parity today.
#
# The `audience` is a fixed well-formed DID string (the bridges don't
# require the DID to be resolvable for minting). Capabilities are
# compared as a sorted set — bridges may differ on list ordering but
# the set must match.
# ---------------------------------------------------------------------------


_UCAN_MEMBER_DID = "did:dht:zparitymemberparitymemberparitymemberparitymember"
_UCAN_CEILING = ["messages:read", "messages:write"]
# Capabilities are context-scoped by the bridges: passing "messages:read"
# becomes "scp:ctx:{context_id}/messages:read" in the minted token. The
# context_id is random per bridge, so we compare the capability COUNT
# (shape-only) rather than literal URIs. Issuer = creator_did (random per
# bridge), audience = _UCAN_MEMBER_DID (fixed) — issuer is regex'd, audience
# is exact.
_UCAN_REQUESTED_CAPS = ["messages:read"]


def _py_ucan_mint(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    handle = ctx.scp_core.py_context_create(
        identity.did,
        {"name": "parity-ucan", "mode": "encrypted", "ceiling": _UCAN_CEILING},
    )
    token = ctx.scp_core.ucan_mint(handle.context_id, _UCAN_MEMBER_DID, _UCAN_REQUESTED_CAPS)
    return {
        "issuer": token.issuer,
        "audience": token.audience,
        "capability_count": len(token.capabilities),
    }


OP_UCAN_MINT = OpSpec(
    name="ucan_mint",
    py_call=_py_ucan_mint,
    node_call={
        "op": "ucan_mint",
        "args": {
            "member_did": _UCAN_MEMBER_DID,
            "capabilities": _UCAN_REQUESTED_CAPS,
            "ceiling": _UCAN_CEILING,
        },
    },
    schema=OpSchema(
        fields=(
            # Issuer is the context creator's DID — different per bridge
            # (random identity creation) but must match did:dht shape.
            FieldSpec("issuer", "regex", pattern=DID_DHT_PATTERN),
            # Audience is the fixed member DID we passed in; must round-trip.
            FieldSpec("audience", "exact"),
            # Count exactly matches the number of requested capabilities.
            FieldSpec("capability_count", "exact"),
        )
    ),
    expected_values=(
        ("audience", _UCAN_MEMBER_DID),
        ("capability_count", len(_UCAN_REQUESTED_CAPS)),
    ),
)


# ---------------------------------------------------------------------------
# op 8: ucan_validate_malformed
#
# Validate a clearly-malformed UCAN token ("not.a.jwt"). All four bridges
# share `scp_protocol::crypto::ucan::validate::parse_ucan` and now map its
# `UcanError` outputs through each bridge's canonical `From<UcanError>`
# mapping to SCP-PERM-3001 — matching the reference PyO3 behaviour. WASM
# and UniFFI previously emitted SCP-PERM-3000 / SCP-PERM-3002 via inline
# ad-hoc error construction; that divergence was fixed in the same PR
# that removed the xfail on this op.
# ---------------------------------------------------------------------------


_MALFORMED_UCAN = "not.a.jwt"
# Canonical PERM_3001 across all four bridges (UcanError → SCP-PERM-3001).
_EXPECTED_MALFORMED_UCAN_CODE = "SCP-PERM-3001"


def _py_ucan_validate_malformed(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    handle = ctx.scp_core.py_context_create(
        identity.did, {"name": "parity-ucan-v", "mode": "encrypted", "ceiling": _UCAN_CEILING}
    )
    try:
        ctx.scp_core.ucan_validate(
            handle.context_id,
            _MALFORMED_UCAN,
            # Any well-formed capability string — the malformed-JWT
            # rejection happens before capability matching.
            "scp:ctx:any/messages:read",
        )
    except Exception as err:
        err_type = type(err).__name__
        code = getattr(err, "code", None) or _extract_code(str(err))
        return {"error": {"type": err_type, "code": code or "UNKNOWN"}}
    return {"error": {"type": "none", "code": "NONE"}}


OP_UCAN_VALIDATE_MALFORMED = OpSpec(
    name="ucan_validate_malformed",
    py_call=_py_ucan_validate_malformed,
    node_call={
        "op": "ucan_validate_malformed",
        "args": {"ceiling": _UCAN_CEILING},
    },
    schema=OpSchema(
        fields=(
            FieldSpec("error.type", "ignore"),
            FieldSpec("error.code", "exact"),
        )
    ),
    expected_values=(("error.code", _EXPECTED_MALFORMED_UCAN_CODE),),
)


# ---------------------------------------------------------------------------
# op 9: transport_status_disconnected
#
# Query the transport status with no relay connected. PyO3 and WASM
# expose a stateless global `transport_status()` that returns the
# default disconnected shape {connected:false, relay_url:None,
# latency_ms:None}.
#
# NAPI and UniFFI expose `transport_status(manager)` which requires a
# prior `transport_connect()` that opens a real WebSocket. That means
# the stateless-query path does not exist on those bridges — exercising
# it on a loopback URL would require a running relay, which the parity
# harness does not provide. Per the op-library contract, we document
# the surface divergence as an xfail rather than silently dropping the
# op. When NAPI / UniFFI grow a handleless status probe (or the
# harness grows an in-process loopback relay fixture), flip the
# `xfail_bridges` entry and the test should pass automatically.
# ---------------------------------------------------------------------------


def _py_transport_status(ctx: OpContext) -> dict[str, Any]:
    status = ctx.scp_core.transport_status()
    return {
        "connected": status.connected,
        "relay_url": status.relay_url,
        "latency_ms": status.latency_ms,
    }


OP_TRANSPORT_STATUS = OpSpec(
    name="transport_status_disconnected",
    py_call=_py_transport_status,
    node_call={"op": "transport_status", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("connected", "exact"),
            # relay_url and latency_ms are None when disconnected. Compare
            # exactly — a bridge returning "" or 0.0 instead of null is a
            # real divergence we want to catch.
            FieldSpec("relay_url", "exact"),
            FieldSpec("latency_ms", "exact"),
        )
    ),
    xfail_bridges=("napi", "uniffi-kotlin", "uniffi-swift"),
    xfail_reason=(
        "NAPI and UniFFI transport_status require a connected handle "
        "(transport_connect opens a real WebSocket). Stateless query "
        "is only on PyO3 and WASM. Tracked in FOLLOWUP.md §7."
    ),
    expected_values=(
        ("connected", False),
        ("relay_url", None),
        ("latency_ms", None),
    ),
)


# ---------------------------------------------------------------------------
# op 10: event_log_query_filtered
#
# Create a context (emits ContextCreated), then query the event log
# with an `event_type=ContextCreated` filter. All four bridges support
# this filter key and must return exactly one event whose type matches
# the filter. This locks in the filter semantics independently of op 4,
# which does an unfiltered query.
# ---------------------------------------------------------------------------


_EVENT_LOG_FILTER = {"event_type": "ContextCreated"}


def _py_event_log_query_filtered(ctx: OpContext) -> dict[str, Any]:
    identity = ctx.scp_core.py_identity_create("in_memory")
    handle = ctx.scp_core.py_context_create(
        identity.did, {"name": "parity-elog-f", "mode": "encrypted"}
    )
    events = ctx.scp_core.event_log_query(handle.context_id, _EVENT_LOG_FILTER)
    first = events[0] if events else None
    return {
        "event_count": len(events),
        "first_event_type": str(first.event_type) if first is not None else "",
    }


OP_EVENT_LOG_FILTERED = OpSpec(
    name="event_log_query_filtered",
    py_call=_py_event_log_query_filtered,
    node_call={
        "op": "event_log_query_filtered",
        "args": {"filter": _EVENT_LOG_FILTER},
    },
    schema=OpSchema(
        fields=(
            FieldSpec("event_count", "exact"),
            FieldSpec("first_event_type", "exact"),
        )
    ),
    expected_values=(
        ("event_count", 1),
        ("first_event_type", "ContextCreated"),
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
    OP_TOOL_REGISTER,
    OP_UCAN_MINT,
    OP_UCAN_VALIDATE_MALFORMED,
    OP_TRANSPORT_STATUS,
    OP_EVENT_LOG_FILTERED,
)
