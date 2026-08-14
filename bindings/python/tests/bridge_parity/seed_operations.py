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

Storage-required model (ADR-049 / spec §17.6): any op that creates a
context MUST first attach a supervisor backed by a storage backend. The
PyO3 runtime never defaults storage and `SCP({"type": "in_memory"})` (bare constructor) carries
none, so a context op on a bare instance fail-closes with SCP-CTX-2001.
Such ops use `OpContext.attached_scp()`, which calls
`configure_local_transport(did)` — the bridge-layer DEV affordance that
seeds an encrypted in-memory store and attaches a local-transport
supervisor in one shot. The alt-bridge runners need no equivalent explicit
call: NAPI/UniFFI seed their in-memory `mls_storage` at CONSTRUCTION TIME
(`new_napi` / `new_uniffi`). Both sides therefore end up backed by an in-memory store
and emit identical canonical output. See `OpContext.attached_scp` for the
full rationale. Non-context ops (identity_create, scpid_sign error paths,
transport_status) need no supervisor and keep the bare `SCP({"type": "in_memory"})` constructor.

Current op library: 12 ops. The first 5 are the MVP per ADR-046;
ops 6-10 cover outlet registration, UCAN mint/validate-error, transport
status, and filtered event-log query; op 11 pins the
unregistered-DID rejection code (SCP-IDENT-1001) across every bridge;
the structured `ucan_evaluate` op pins the six-boolean
`CapabilityValidation` return (no-throw partial-false path) across
every bridge.
Crypto outputs compare byte-exactly: `identity_create_deterministic`
pins DID + identity-key verifying bytes under a fixed seed, and
`sign_message` pins the SCPID signature byte-exactly under the
`signed_at_override` testing affordance (see `scp-runtime::scpid_sign`).
The latter also derives a distinct `#active` key from `seed[32..64]`
under the `testing` feature, matching scp-core's two-key
`DidDht::create` sequence.

Resolved divergences (previously xfail'd tripwires, now full parity):
  - context_id format (§18.4.1): all three bridges emit 64-char lowercase
    hex via `hex::encode(32 random bytes)`. PyO3's `generate_context_id`
    (crates/scp-ffi/src/types.rs) remains the reference.
  - event_log_append starting sequence: all bridges emit `ContextCreated`
    at context-create time via `builder_create_context`. PyO3 was rewired
    from `NoOpEventLogProvider` to `MerkleEventLogProvider` matching the
    NAPI/UniFFI bridges.
  - invalid_capability_rejected unregistered-DID code: aligned on
    SCP-IDENT-1001 (identity-domain, identity-not-found) across bridges.
    The MVP op exercises the malformed-challenge path (SCP-IDENT-1038,
    shared); `unregistered_did_rejected` (op 11 below) locks the
    IDENT-1001 alignment into the parity gate.
  - sign_message signature byte-exactness: previously shape-only because
    Ed25519 covers a wall-clock `signed_at`. Now byte-exact via the
    `signed_at_override` parameter on `scpid_sign`, wired across all
    three bridges + scp-core under the `testing` feature. Paired with a
    distinct `#active` key (derived from `seed[32..64]` to
    match scp-core's two-key sequence) so the signature hashes are
    identical across every bridge.

----------------------------------------------------------------------
XFAIL-STRICT POLICY — READ BEFORE LANDING A FIX
----------------------------------------------------------------------
The `xfail_bridges` / `xfail_reason` fields on an OpSpec translate to
`@pytest.mark.xfail(strict=True)` in `test_bridge_parity.py`. "Strict"
means: if the divergence is fixed and the test starts PASSING, CI FAILS
with XPASS. That is by design — silent passes would hide that the fix
also needs a harness update.

When fixing a newly discovered divergence:
  1. Remove `xfail_bridges=(...)` and `xfail_reason=...` from the OpSpec.
  2. Update the op's docstring block to drop the "xfail'd" language.
  3. Run the full parity suite locally; all cases should pass.

There is no separate tracking document — git history and the inline
docstrings on each OpSpec carry the rationale.
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

# Spec §18.4.1: context IDs MUST be 64-char lowercase hex. All three bridges
# (PyO3, NAPI, UniFFI) now emit spec-compliant hex IDs via
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
# (PyO3 SCP-IDENT-1001, NAPI SCP-PERM-3023). The
# bridges are now aligned on SCP-IDENT-1001 (identity-domain, identity-not-
# found). The MVP op below exercises the malformed-challenge path per
# ADR-046; the companion `unregistered_did_rejected` op locks the
# IDENT-1001 alignment into the parity gate.
EXPECTED_INVALID_CAPABILITY_CODE = "SCP-IDENT-1038"
# Pinned SCP-IDENT-1001 code for the valid-challenge + unregistered-DID
# path. Used by `OP_UNREGISTERED_DID_REJECTED` below.
EXPECTED_UNREGISTERED_DID_CODE = "SCP-IDENT-1001"

# Shape-valid `did:dht:z…` DID that is NOT registered in any bridge's
# identity registry. zbase32 suffix is 64 chars, which decodes to 40 bytes
# (not the 32 bytes a real did:dht key would) — so the UniFFI path (which
# validates the DID's zbase32 suffix when it resolves the DID) also
# surfaces the same error through `From<IdentityError>` → IDENT-1001. The
# DID still passes the bridge-level `validate_did` shape check
# (`did:{method}:{id}` with lowercase-alphanumeric method), so every
# bridge enters its registry lookup path before rejecting. Pinned fixture
# — do not change without updating every runner.
FAKE_UNREGISTERED_DID = "did:dht:znever1never1never1never1never1never1never1never1never1never1neva"


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

    def attached_scp(self, seed: bytes | None = None) -> tuple[Any, Any]:
        """Build a fresh PyO3 `SCP` with a supervisor attached, plus an identity.

        Storage-required model (ADR-049 / spec §17.6): the PyO3 runtime
        never defaults storage, and `PyBridgeInstance::new_py` (the bare
        `SCP({"type": "in_memory"})` constructor) carries no storage backend. Any context /
        event-log / outlet / UCAN-with-context op therefore needs a
        supervisor attached *with* a storage backend first, otherwise the
        supervisor build fails closed and the op surfaces SCP-CTX-2001.

        `configure_local_transport(did)` is the sanctioned bridge-layer
        DEV affordance: it seeds the encrypted in-memory storage backend
        (the equivalent of `SCP.with_storage({"type": "in_memory"})`)
        *and* attaches a `LocalTransportProvider`-backed supervisor in one
        call. This is exactly the affordance the production relay path
        (`configure_relay_transport`) deliberately does NOT provide — it
        fail-closes without storage so a forgetful production caller never
        silently runs on an ephemeral in-memory store.

        Cross-bridge parity note: the NAPI and UniFFI (Kotlin/Swift)
        constructors seed their in-memory `mls_storage` backend AT
        CONSTRUCTION TIME (see `new_napi` / `new_uniffi` in the respective
        `runtime.rs`), so their `context_create` auto-attaches a supervisor
        with no explicit attach call. PyO3 alone defers the dev
        affordance to `configure_local_transport`. This helper is the PyO3
        equivalent of those bridges' constructor-time seeding, so both
        sides of every parity comparison end up backed by an encrypted
        in-memory store and emit byte-identical canonical output.

        Returns the attached `SCP` instance and the created identity so
        callers can reference `identity.did`.
        """
        scp = self.scp_core.SCP({"type": "in_memory"})
        identity = (
            scp.identity_create("in_memory", seed)
            if seed is not None
            else scp.identity_create("in_memory")
        )
        scp.configure_local_transport(identity.did)
        return scp, identity


@dataclass(frozen=True)
class OpSpec:
    name: str
    py_call: Callable[[OpContext], dict[str, Any]]
    node_call: dict[str, Any]
    schema: OpSchema
    # Bridges for which this op is a known divergence (xfail'd). Empty
    # tuple means all bridges are expected to pass. Inline docstrings on
    # each OpSpec carry the rationale when the tuple is non-empty.
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
# bridge per ADR-046), so:
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
# (e.g. StdRng algorithm update) require moving these, update all three
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
    scp = ctx.scp_core.SCP({"type": "in_memory"})
    identity = scp.identity_create("in_memory", seed)
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
    # constants must move in the same PR that changes all three bridges.
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
# three bridges (PyO3, NAPI, UniFFI) emit `hex::encode(32 random
# bytes)`.
# ---------------------------------------------------------------------------


def _py_context_create(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    params = {"name": "parity-test", "mode": "encrypted"}
    handle = scp.context_create(identity.did, params)
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
# Real divergence caught by the harness: differing codes per bridge.
# PyO3 returned SCP-IDENT-1001 (reference); NAPI returned SCP-PERM-3023.
# Aligned across the bridges on
# SCP-IDENT-1001 for the unregistered-DID path; the op below exercises
# the malformed-challenge path (SCP-IDENT-1038, shared), and
# `OP_UNREGISTERED_DID_REJECTED` (op 11) locks in the IDENT-1001 path.
# ---------------------------------------------------------------------------


def _py_invalid_sign(ctx: OpContext) -> dict[str, Any]:
    scp = ctx.scp_core.SCP({"type": "in_memory"})
    try:
        scp.scpid_sign(
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
    # to "UNKNOWN" together) cannot pass parity silently. SCP-IDENT-1038
    # is the committed shared code for the malformed-challenge path;
    # this assertion enforces that commitment.
    expected_values=(("error.code", EXPECTED_INVALID_CAPABILITY_CODE),),
)


# ---------------------------------------------------------------------------
# op 4: event_log_append
#
# Cross-bridge exposed path: create a context, then query the event log.
# Compare event count + first event type + starting sequence exactly.
#
# All three bridges (PyO3, NAPI, UniFFI) emit a `ContextCreated`
# event at context-create time via `builder_create_context` in scp-runtime.
# The PyO3 bridge was previously wired to `NoOpEventLogProvider` and so
# returned an empty log for this path; it now uses `MerkleEventLogProvider`
# matching the other bridges.
# ---------------------------------------------------------------------------


def _py_event_log_append(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(identity.did, {"name": "parity-elog", "mode": "encrypted"})
    events = scp.event_log_query(handle.context_id, None)
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
# generates a challenge and signs it via SCPID. Under the `testing`-
# gated `signed_at_override` affordance (wired across all three bridges
# and `scp-runtime::scpid_sign`), the harness pins `signed_at` in the
# canonical hash to `PARITY_SIGNED_AT_MS`. Combined with:
#
#   - seed → identity key (`#0`) and active key (`#active`) both byte-
#     identical across bridges (StdRng::from_seed stream consumed in the
#     same order by every bridge),
#   - `PARITY_NONCE_HEX` pinned in the challenge,
#   - fixed audience string,
#
# every bridge's Ed25519 signature is byte-identical. This FieldSpec
# uses `bytes_from_hex` + an `expected_values` pin so the gate catches
# any drift in the SCPID canonical-hash construction, the key-sequence
# contract, or the override plumbing.
# ---------------------------------------------------------------------------


# Pinned Unix millisecond timestamp stuffed into the SCPID canonical
# hash. The challenge's issued_at / expires_at must straddle this value;
# we use a far-future `expires_at` (year 2286) so wall-clock expiry
# never trips.
PARITY_SIGNED_AT_MS = 1_700_000_000_000
PARITY_CHALLENGE_EXPIRES_AT_MS = 9_999_999_999_000
# Fixed 32-byte nonce so the canonical hash is fully determined.
PARITY_NONCE_HEX = "aa" * 32

# Pinned SCPID signature under the fixture above. Ground truth is
# produced by `scp-runtime::tests::print_parity_sign_golden_value`:
#   cargo test -p scp-runtime --lib print_parity_sign_golden_value \
#     -- --ignored --nocapture
# If you change the seed, canonical-hash construction, or override
# plumbing, rerun that test and update this literal in the same PR.
EXPECTED_SEEDED_SIGNATURE_HEX = (
    "b46755a5bebcfe331e9f937e9668302a4283b490752f0c4e9260b879acf2e9d7"
    "3f4476765c4f4f11c47e61fcbe6c0611acbff84af6e3ce9ed5fa8ceaa6672d0b"
)


def _pinned_challenge_json(audience: str = "https://parity-test.example.com") -> str:
    """Build the pinned SCPID challenge used by the parity sign path.

    Mirrored in `node_bridge_runner.ts::patchChallengeForOverride` so
    every bridge feeds an IDENTICAL challenge into `scpid_sign`.
    """
    return json.dumps(
        {
            "protocol": "scpid/1.0",
            "nonce": PARITY_NONCE_HEX,
            "audience": audience,
            "issued_at": PARITY_SIGNED_AT_MS,
            "expires_at": PARITY_CHALLENGE_EXPIRES_AT_MS,
        }
    )


def _py_sign_message(ctx: OpContext) -> dict[str, Any]:
    seed = bytes.fromhex(PARITY_SEED_HEX)
    scp = ctx.scp_core.SCP({"type": "in_memory"})
    identity = scp.identity_create("in_memory", seed)
    challenge_json = _pinned_challenge_json()
    response_json = scp.scpid_sign(
        identity.did,
        "#active",
        challenge_json,
        PARITY_SIGNED_AT_MS,
    )
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
            "signed_at_override": PARITY_SIGNED_AT_MS,
        },
    },
    schema=OpSchema(
        fields=(
            FieldSpec("protocol", "exact"),
            FieldSpec("signing_key_id", "exact"),
            # DID is byte-exact under the shared seed.
            FieldSpec("did", "exact"),
            # Signatures are now byte-exact under the shared seed +
            # pinned override. `bytes_from_hex` canonicalizes to base64
            # in the normalizer, so the expected literal must match.
            FieldSpec("signature", "bytes_from_hex"),
        )
    ),
    expected_values=(
        ("did", EXPECTED_SEEDED_DID),
        (
            "signature",
            __import__("base64")
            .b64encode(bytes.fromhex(EXPECTED_SEEDED_SIGNATURE_HEX))
            .decode("ascii"),
        ),
    ),
)


# ---------------------------------------------------------------------------
# op 6: outlet_register
#
# Register a single outlet in a fresh context. The outlet_id is derived
# deterministically across all three bridges from the outlet name via the
# shared `format!("outlet-{}", name.replace(' ', "-").to_lowercase())`
# convention (see scp-ffi/common/src/outlet_id.rs, consumed by
# scp-ffi/src, scp-ffi/napi/src, scp-ffi/uniffi/src/bridge.rs — all three
# use the same format). That makes outlet_id byte-exact for parity.
# ---------------------------------------------------------------------------


# Ceiling must include `outlet:register` to permit the registration action.
_OUTLET_CEILING = ["messages:read", "messages:write", "outlet:register", "outlet_call:*"]
_OUTLET_NAME = "parity_probe"
_EXPECTED_OUTLET_ID = f"outlet-{_OUTLET_NAME}"
_OUTLET_SCHEMA: dict[str, Any] = {
    "input_schema": {
        "type": "object",
        "properties": {"x": {"type": "integer"}, "label": {"type": "string"}},
    },
    "output_schema": {
        "type": "object",
        "properties": {"y": {"type": "integer"}, "status": {"type": "string"}},
    },
}


def _py_outlet_register(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(
        identity.did,
        {"name": "parity-outlets", "mode": "encrypted", "ceiling": _OUTLET_CEILING},
    )
    outlet_id = scp.outlet_register(
        handle.context_id,
        {
            "name": _OUTLET_NAME,
            "description": "parity harness probe outlet",
            "kind": "action",
            "operator_did": identity.did,
            "schema": _OUTLET_SCHEMA,
        },
    )
    return {"outlet_id": outlet_id}


OP_OUTLET_REGISTER = OpSpec(
    name="outlet_register",
    py_call=_py_outlet_register,
    node_call={
        "op": "outlet_register",
        "args": {
            "name": _OUTLET_NAME,
            "description": "parity harness probe outlet",
            "kind": "action",
            "schema": _OUTLET_SCHEMA,
            "ceiling": _OUTLET_CEILING,
        },
    },
    schema=OpSchema(fields=(FieldSpec("outlet_id", "exact"),)),
    # Spec-pin the derivation: `outlet-{name-lowercased-spaces-to-dashes}`.
    # Joint drift (e.g. all bridges hash instead of format) would pass
    # parity step 3 but violate the shared convention; this locks it.
    expected_values=(("outlet_id", _EXPECTED_OUTLET_ID),),
)


# ---------------------------------------------------------------------------
# op 7: ucan_mint
#
# Mint a UCAN in a freshly created context with a pinned member DID and
# capability set. All three bridges return metadata — issuer, audience,
# capabilities — byte-exactly under those inputs. The encoded JWT is
# NOT compared: PyO3's PyUcanToken intentionally does not expose the
# JWT (see crates/scp-ffi/src/ucan.rs), and both the signature and the
# wall-clock `exp` would diverge even if it did. Extending the SCPID
# `signed_at_override` affordance to UCAN minting is a possible future
# op; until then the `exp` field prevents byte-exact JWT parity.
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
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(
        identity.did,
        {"name": "parity-ucan", "mode": "encrypted", "ceiling": _UCAN_CEILING},
    )
    token = scp.ucan_mint(handle.context_id, _UCAN_MEMBER_DID, _UCAN_REQUESTED_CAPS)
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
# Validate a clearly-malformed UCAN token ("not.a.jwt"). All bridges
# share `scp_protocol::crypto::ucan::validate::parse_ucan` and now map its
# `UcanError` outputs through each bridge's canonical `From<UcanError>`
# mapping to SCP-PERM-3001 — matching the reference PyO3 behaviour. UniFFI
# previously emitted SCP-PERM-3002 via inline
# ad-hoc error construction; that divergence was fixed in the same PR
# that removed the xfail on this op.
# ---------------------------------------------------------------------------


_MALFORMED_UCAN = "not.a.jwt"
# Canonical PERM_3001 across all three bridges (UcanError → SCP-PERM-3001).
_EXPECTED_MALFORMED_UCAN_CODE = "SCP-PERM-3001"


def _py_ucan_validate_malformed(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(
        identity.did, {"name": "parity-ucan-v", "mode": "encrypted", "ceiling": _UCAN_CEILING}
    )
    try:
        scp.ucan_validate(
            handle.context_id,
            _MALFORMED_UCAN,
            # Any well-formed capability string — the malformed-JWT
            # rejection happens at parse, before capability matching.
            "scp:ctx:any/messages:read",
            # The enforcing gate fails closed without a presenting agent; supply
            # one so the malformed JWT is still rejected at PARSE (the behavior
            # under test), not short-circuited by the fail-closed audience gate.
            identity.did,
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
# op: ucan_evaluate_malformed
#
# Companion to OP_UCAN_VALIDATE_MALFORMED. Where `ucan_validate` THROWS on a
# malformed token, the structured `ucan_evaluate` op returns a per-stage
# CapabilityValidation summary. A malformed JWT fails at stage 1 (parse), so
# every bridge must return tokens_valid=false with all later fields false —
# WITHOUT throwing. This pins the new structured op's cross-bridge shape and
# the all-false short-circuit behavior. (A "not.a.jwt" string fails the FFI
# UCAN-token validator before reaching evaluate; the bridges all surface that
# as a thrown ValidationError. The parity contract here is the THROWN-code
# alignment, identical to the validate companion.)
#
# The OTHER half of the structured contract — a parseable, well-signed token
# that reaches evaluate_ucan and returns a PARTIAL-FALSE struct without
# throwing — is exercised by OP_UCAN_EVALUATE_STRUCTURED (below), which
# compares the six returned booleans byte-for-byte across every bridge. The
# six-field short-circuit field mapping and the read-only / no-nonce-record
# invariant are additionally pinned at the core level by the
# `evaluate_ucan_*` tests in
# `crates/scp-runtime/tests/ucan_validate_integration.rs`.
# ---------------------------------------------------------------------------


def _py_ucan_evaluate_malformed(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(
        identity.did, {"name": "parity-ucan-e", "mode": "encrypted", "ceiling": _UCAN_CEILING}
    )
    try:
        scp.ucan_evaluate(
            handle.context_id,
            _MALFORMED_UCAN,
            "scp:ctx:any/messages:read",
            # Fail-closed presenting-agent gate: supply one so the malformed JWT
            # is rejected at PARSE (the behavior under test), not short-circuited.
            identity.did,
        )
    except Exception as err:
        err_type = type(err).__name__
        code = getattr(err, "code", None) or _extract_code(str(err))
        return {"error": {"type": err_type, "code": code or "UNKNOWN"}}
    return {"error": {"type": "none", "code": "NONE"}}


OP_UCAN_EVALUATE_MALFORMED = OpSpec(
    name="ucan_evaluate_malformed",
    py_call=_py_ucan_evaluate_malformed,
    node_call={
        "op": "ucan_evaluate_malformed",
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
# op: ucan_evaluate_structured
#
# The structured-return half of the `ucan_evaluate` contract. Where
# OP_UCAN_EVALUATE_MALFORMED pins the THROWN-code path (a "not.a.jwt" string
# rejected by the FFI token validator before the pipeline runs), this op pins
# the NO-THROW path: a parseable, validly-signed root UCAN that reaches core
# `evaluate_ucan` and returns a per-stage `CapabilityValidation` (six booleans)
# WITHOUT throwing.
#
# Construction: mint a valid root token granting `messages:read` in a context
# whose ceiling is `messages:read`, then evaluate it requiring `messages:write`
# (a capability the token does NOT grant). The pipeline short-circuits: parse
# succeeds (`tokens_valid: true`), but the step-6 invoked-capability grant-match
# fails — `messages:write` is not in the token's `att` set — so `signatures_valid`
# and everything after it are false. The result is therefore the deterministic,
# identical-across-bridges partial struct:
#
#   {tokens_valid: true, signatures_valid: false, within_ceiling: false,
#    nonce_valid: false, not_revoked: false, time_bounds_valid: false}
#
# All six booleans are compared exactly across every bridge (PyO3 reference vs.
# NAPI / UniFFI-Kotlin / UniFFI-Swift). The literals are pinned via
# `expected_values` so joint drift (e.g. all bridges flipping a field) is caught.
# ---------------------------------------------------------------------------


# Token grants `messages:read`; evaluation requires `messages:write`. The
# ceiling permits both so the divergence is purely the unstated invoked
# capability, keeping the failing stage (grant-match, inside `signatures_valid`)
# unambiguous and identical across bridges.
_UCAN_STRUCTURED_GRANTED_CAPS = ["messages:read"]
_UCAN_STRUCTURED_REQUIRED_CAP = "messages:write"


def _py_ucan_evaluate_structured(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(
        identity.did,
        {"name": "parity-ucan-es", "mode": "encrypted", "ceiling": _UCAN_CEILING},
    )
    token = scp.ucan_mint(handle.context_id, _UCAN_MEMBER_DID, _UCAN_STRUCTURED_GRANTED_CAPS)
    # Evaluate against a capability the token does NOT grant. The required URI is
    # context-scoped exactly as minting scopes the granted caps.
    required = f"scp:ctx:{handle.context_id}/{_UCAN_STRUCTURED_REQUIRED_CAP}"
    # Presenting agent is REQUIRED (fail-closed): pass the token's audience
    # (the minted member DID) so the step-5 audience check passes and the
    # failing stage is purely the grant-match, identical across bridges.
    result = scp.ucan_evaluate(handle.context_id, token.encoded, required, _UCAN_MEMBER_DID)
    return {
        "tokens_valid": result.tokens_valid,
        "signatures_valid": result.signatures_valid,
        "within_ceiling": result.within_ceiling,
        "nonce_valid": result.nonce_valid,
        "not_revoked": result.not_revoked,
        "time_bounds_valid": result.time_bounds_valid,
    }


OP_UCAN_EVALUATE_STRUCTURED = OpSpec(
    name="ucan_evaluate_structured",
    py_call=_py_ucan_evaluate_structured,
    node_call={
        "op": "ucan_evaluate_structured",
        "args": {
            "member_did": _UCAN_MEMBER_DID,
            "capabilities": _UCAN_STRUCTURED_GRANTED_CAPS,
            "required_capability": _UCAN_STRUCTURED_REQUIRED_CAP,
            "ceiling": _UCAN_CEILING,
        },
    },
    schema=OpSchema(
        fields=(
            FieldSpec("tokens_valid", "exact"),
            FieldSpec("signatures_valid", "exact"),
            FieldSpec("within_ceiling", "exact"),
            FieldSpec("nonce_valid", "exact"),
            FieldSpec("not_revoked", "exact"),
            FieldSpec("time_bounds_valid", "exact"),
        )
    ),
    expected_values=(
        ("tokens_valid", True),
        ("signatures_valid", False),
        ("within_ceiling", False),
        ("nonce_valid", False),
        ("not_revoked", False),
        ("time_bounds_valid", False),
    ),
)


# ---------------------------------------------------------------------------
# op 9: transport_status_disconnected
#
# Query the transport status with no relay connected.
#
# **Bridge semantics differ for this op**:
#   - **PyO3**: `SCP.transport_status()` — handleless instance method,
#     returns the per-instance BridgeInstance snapshot. With no connect,
#     that state is `{connected: false, relay_url: None, latency_ms: None}`.
#   - **NAPI**: `SCP.transportStatus(manager: Option<&NapiTransportManager>)`
#     — pass `null` for the stateless probe path on the same instance.
#   - **UniFFI (Kotlin/Swift)**: `Scp.transportStatus(manager:
#     TransportManager)` — REQUIRES a non-optional TransportManager handle
#     after ADR-048 Phase D / #1549 PR 4. The prior handleless probe was
#     deleted when the process-wide default bridge was removed; without a
#     relay fixture to wire up a real `transport_connect` first, the
#     runners cannot produce a TransportManager.
#
# UniFFI is xfailed below on that basis. Aligning UniFFI with the other
# bridges requires either exposing a handleless instance-level probe on
# `Scp` or teaching the parity harness to spin up a relay fixture — both
# are cross-cutting enough to track outside this gate.
# ---------------------------------------------------------------------------


def _py_transport_status(ctx: OpContext) -> dict[str, Any]:
    scp = ctx.scp_core.SCP({"type": "in_memory"})
    status = scp.transport_status()
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
# with an `event_type=ContextCreated` filter. All three bridges support
# this filter key and must return exactly one event whose type matches
# the filter. This locks in the filter semantics independently of op 4,
# which does an unfiltered query.
# ---------------------------------------------------------------------------


_EVENT_LOG_FILTER = {"event_type": "ContextCreated"}


def _py_event_log_query_filtered(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(identity.did, {"name": "parity-elog-f", "mode": "encrypted"})
    events = scp.event_log_query(handle.context_id, _EVENT_LOG_FILTER)
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
# op 11: unregistered_did_rejected
#
# Companion to op 3. Op 3 exercises the malformed-challenge path
# (SCP-IDENT-1038) — the challenge JSON fails shape validation before any
# DID lookup happens. This op exercises the OTHER historically-divergent
# path: a VALID challenge paired with a well-formed but unregistered
# DID. Before alignment, PyO3 returned SCP-IDENT-1001 and NAPI returned
# SCP-PERM-3023. All bridges
# (PyO3, NAPI, UniFFI-Kotlin, UniFFI-Swift) now converge on
# SCP-IDENT-1001 (identity-domain, identity-not-found) for this path.
#
# Bridge-specific dispatch:
#   - PyO3/NAPI `scpid_sign(did_string, …)` looks the DID up in
#     the bridge-local identity registry; an absent entry surfaces
#     IDENT-1001 from `with_identity` / `sign_with_identity`.
#   - UniFFI `scpid_sign(identity: Identity, …)` takes an opaque handle,
#     not a DID string — it never performs the registry lookup the other
#     bridges do. To exercise the same unregistered-DID code path, the
#     Kotlin/Swift runners call the UniFFI `identityResolve` entrypoint
#     with the fake DID instead:
#     the fake DID's 64-char zbase32 suffix decodes to 40 bytes (not the
#     32 required by did:dht), so `DidDht::extract_public_key` returns
#     `IdentityError::InvalidDidFormat` locally — no DHT round-trip — and
#     the bridge's blanket `From<IdentityError>` mapping in
#     `crates/scp-ffi/uniffi/src/bridge.rs` surfaces it as IDENT-1001.
#     This keeps every bridge locked to the same committed code without
#     requiring UniFFI's `scpid_sign` to replicate the other bridges'
#     DID-string-to-registry lookup semantics.
# ---------------------------------------------------------------------------


def _py_unregistered_did_rejected(ctx: OpContext) -> dict[str, Any]:
    scp = ctx.scp_core.SCP({"type": "in_memory"})
    challenge_json = _pinned_challenge_json()
    try:
        scp.scpid_sign(FAKE_UNREGISTERED_DID, "#active", challenge_json)
    except Exception as err:
        err_type = type(err).__name__
        code = getattr(err, "code", None) or _extract_code(str(err))
        return {"error": {"type": err_type, "code": code or "UNKNOWN"}}
    return {"error": {"type": "none", "code": "NONE"}}


OP_UNREGISTERED_DID_REJECTED = OpSpec(
    name="unregistered_did_rejected",
    py_call=_py_unregistered_did_rejected,
    node_call={"op": "unregistered_did_rejected", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("error.type", "ignore"),
            # `error.code` must match EXPECTED_UNREGISTERED_DID_CODE
            # exactly across every bridge; this is the whole point of
            # this op. Mirrors OP_UCAN_VALIDATE_MALFORMED.
            FieldSpec("error.code", "exact"),
        )
    ),
    # Pin the committed code. If all bridges silently drift (e.g. to
    # "UNKNOWN"), exact-equality parity would still hold — this literal
    # pin is what catches that mode.
    expected_values=(("error.code", EXPECTED_UNREGISTERED_DID_CODE),),
)


# ---------------------------------------------------------------------------
# op 12: event_log_verify_inclusion
#
# Cross-bridge verify-path parity (GitHub #1933 / ADR-046). Every bridge
# creates a context (all three emit `ContextCreated` at leaf 0 of the
# AUTHORITATIVE supervisor log), then asks event_log_verify to prove
# inclusion of leaf 0. The op pins the HONEST proof shape the branch
# committed to: a returned proof IS the positive answer (there is no
# producer-set `verified` flag on any bridge), and its details carry the
# checkable Merkle material — leaf hash, sibling path, root — plus the
# `leaf_count` of the ONE snapshot the proof was generated from.
#
# The comparison runs on shape booleans + the snapshot leaf count, not
# raw hashes: context IDs (and therefore leaf hashes/roots) legitimately
# differ per run, but WHICH fields the proof carries and HOW MANY leaves
# the authoritative log holds after one create must be identical across
# PyO3, NAPI, and UniFFI (Kotlin + Swift).
# ---------------------------------------------------------------------------


_VERIFY_CONTEXT_PARAMS = {"name": "parity-elog-v", "mode": "encrypted"}


def _py_event_log_verify_inclusion(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(identity.did, dict(_VERIFY_CONTEXT_PARAMS))
    proof = scp.event_log_verify(handle.context_id, {"type": "inclusion", "leaf_index": 0})
    details = proof.details
    return {
        "proof_type": str(proof.proof_type),
        "leaf_count": int(details["leaf_count"]),
        "has_leaf_hash": "leaf_hash" in details,
        "has_path": "path" in details,
        "has_root": "root" in details,
    }


OP_EVENT_LOG_VERIFY_INCLUSION = OpSpec(
    name="event_log_verify_inclusion",
    py_call=_py_event_log_verify_inclusion,
    node_call={"op": "event_log_verify_inclusion", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("proof_type", "exact"),
            FieldSpec("leaf_count", "exact"),
            FieldSpec("has_leaf_hash", "exact"),
            FieldSpec("has_path", "exact"),
            FieldSpec("has_root", "exact"),
        )
    ),
    # Pin the absolute proof type so joint drift (e.g. every bridge
    # starting to answer "absence" or "" together) cannot pass parity
    # silently.
    expected_values=(("proof_type", "inclusion"),),
)


# ---------------------------------------------------------------------------
# op 13: event_log_absence_of_lifecycle_event_rejected
#
# The literal cross-bridge assertion of GitHub #1933 acceptance
# criterion 4: an absence proof for a REAL lifecycle event must FAIL
# identically on every bridge. Each bridge creates a context, extracts
# the `ContextCreated` leaf hash from its own inclusion proof (so the
# absence claim provably names an event that IS in the authoritative
# log), then claims that event is absent. Every bridge must reject the
# claim with SCP-CTX-2139 — the committed "claim is false over a
# readable log" code — never mint a verifying absence proof (the
# repudiation primitive the issue closed) and never confuse the honest
# negative with SCP-CTX-2138 ("cannot reach the log", fail-closed).
# ---------------------------------------------------------------------------


# The committed cross-bridge code for "the claim is false over a
# readable log" — distinct from CTX-2138 ("cannot answer"). Pinned so
# joint drift across bridges cannot pass parity silently.
EXPECTED_ABSENCE_REJECTED_CODE = "SCP-CTX-2139"


def _py_event_log_absence_rejected(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(identity.did, dict(_VERIFY_CONTEXT_PARAMS))
    inclusion = scp.event_log_verify(handle.context_id, {"type": "inclusion", "leaf_index": 0})
    leaf_hash = str(inclusion.details["leaf_hash"])
    try:
        scp.event_log_verify(handle.context_id, {"type": "absence", "event_hash": leaf_hash})
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


OP_EVENT_LOG_ABSENCE_OF_LIFECYCLE_EVENT_REJECTED = OpSpec(
    name="event_log_absence_of_lifecycle_event_rejected",
    py_call=_py_event_log_absence_rejected,
    node_call={"op": "event_log_absence_of_lifecycle_event_rejected", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("error.type", "ignore"),
            # `error.code` must match EXPECTED_ABSENCE_REJECTED_CODE
            # exactly across every bridge; this is the whole point of
            # this op. Mirrors OP_UNREGISTERED_DID_REJECTED.
            FieldSpec("error.code", "exact"),
            FieldSpec("error.message", "ignore"),
        )
    ),
    # Pin the committed code. If all bridges silently drift together —
    # or worse, all start SUCCEEDING (returning no error at all, i.e.
    # minting the forgeable absence proof again) — exact-equality parity
    # would still hold; this literal pin is what catches both modes.
    expected_values=(("error.code", EXPECTED_ABSENCE_REJECTED_CODE),),
)


# ---------------------------------------------------------------------------
# op 14: event_log_absence_over_divergent_local_tree_rejected
#
# Reproduces the F3 divergence precondition (GitHub #1933) through the
# PUBLIC runner surface — the property the pristine-context ops 12/13
# CANNOT catch. Ops 12/13 run on a context whose bridge-local
# (UCAN-state) tree still equals the authoritative log, so a bridge that
# regressed to proving over the caller-influenceable local tree would
# still answer identically and pass parity. This op forces the two trees
# APART first:
#
#   1. create a context (authoritative log gets `ContextCreated` @ leaf 0);
#   2. call the public `provenance_attach` with a MISSING source context, so
#      only the `ProvenanceReceived` leaf (the target-side append) lands on
#      the BRIDGE-LOCAL tree — a leaf NOT in the authoritative log — while the
#      source-side `ProvenanceAttached` append is dropped best-effort; the
#      trees now diverge;
#   3. read the AUTHORITATIVE `ContextCreated` leaf hash from
#      `event_log_query` (which reads the authoritative log, INDEPENDENT
#      of the verify path — so the hash is not derived from the surface
#      under test, unlike op 13's inclusion-proof hash);
#   4. claim that authoritative hash is ABSENT.
#
# A correct bridge proves over the authoritative log, where the hash IS
# present, and REJECTS with SCP-CTX-2139 on every bridge. A bridge that
# regressed to the divergent local tree — where the authoritative hash is
# absent — would MINT a verifying absence proof (no error), which this op
# catches as a parity + `expected_values` failure. This is the mechanical
# guard that a reverted F3 fix, or a verify that proves over the local
# tree, can no longer slip past parity.
# ---------------------------------------------------------------------------


# Made-up source context id: `provenance_attach` is best-effort on a
# missing source (it only appends the bridge-local target leaf), so this
# needs no real second context — matching the PyO3/NAPI/UniFFI
# `inject_local_leaf` test helpers.
_DIVERGENCE_PROV_SOURCE = "parity-prov-source"


def _py_event_log_absence_over_divergent_local_tree_rejected(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(identity.did, dict(_VERIFY_CONTEXT_PARAMS))
    ctx_id = handle.context_id
    # Diverge the bridge-local tree from the authoritative log via a real
    # public bridge call.
    scp.provenance_attach(
        _DIVERGENCE_PROV_SOURCE,
        "persistent",
        "full",
        [identity.did],
        ctx_id,
        identity.did,
        None,
    )
    # The AUTHORITATIVE ContextCreated leaf hash, read from the query path
    # (authoritative), NOT the verify path under test.
    events = scp.event_log_query(ctx_id, {"event_type": "ContextCreated"})
    auth_hash = str(events[0].payload["hash"])
    try:
        scp.event_log_verify(ctx_id, {"type": "absence", "event_hash": auth_hash})
    except Exception as err:  # we want the error shape — test surface
        code = getattr(err, "code", None) or _extract_code(str(err))
        return {
            "error": {
                "type": type(err).__name__,
                "code": code or "UNKNOWN",
                "message": str(err),
            }
        }
    return {"error": {"type": "none", "code": "NONE", "message": "no error raised"}}


OP_EVENT_LOG_ABSENCE_OVER_DIVERGENT_LOCAL_TREE_REJECTED = OpSpec(
    name="event_log_absence_over_divergent_local_tree_rejected",
    py_call=_py_event_log_absence_over_divergent_local_tree_rejected,
    node_call={"op": "event_log_absence_over_divergent_local_tree_rejected", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("error.type", "ignore"),
            FieldSpec("error.code", "exact"),
            FieldSpec("error.message", "ignore"),
        )
    ),
    # Pin the committed honest-negative code. If a bridge regresses to the
    # divergent local tree it will SUCCEED (error.code == "NONE") and both
    # the parity equality and this literal pin fail.
    expected_values=(("error.code", EXPECTED_ABSENCE_REJECTED_CODE),),
)


# ---------------------------------------------------------------------------
# op 15: event_log_verify_malformed_claim_rejected
#
# The mechanical cross-bridge guard for Fix 1 (GitHub #1933): malformed
# CLAIM input carries SCP-VALID-7000 on EVERY bridge — it is caller input
# validation, distinct from the honest-negative SCP-CTX-2139 and the
# fail-closed SCP-CTX-2138. The PyO3 reference bridge previously emitted
# the generic SCP-VALID-7001 here while NAPI/UniFFI emitted SCP-VALID-7000,
# and no parity op fed a malformed claim, so the drift went undetected.
# This op feeds a malformed inclusion claim (missing `leaf_index`) over a
# readable log and pins `error.code == SCP-VALID-7000` across all bridges.
# ---------------------------------------------------------------------------


# The committed cross-bridge code for "the claim itself is malformed" —
# caller input validation, distinct from CTX-2138/CTX-2139. Pinned so a
# single bridge drifting (or all drifting together) cannot pass silently.
EXPECTED_MALFORMED_CLAIM_CODE = "SCP-VALID-7000"


def _py_event_log_verify_malformed_claim(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(identity.did, dict(_VERIFY_CONTEXT_PARAMS))
    try:
        # `type` is present and valid, so this reaches the inclusion arm
        # over a readable log; the MISSING `leaf_index` is the malformed
        # input the arm rejects with VALID-7000.
        scp.event_log_verify(handle.context_id, {"type": "inclusion"})
    except Exception as err:  # we want the error shape — test surface
        code = getattr(err, "code", None) or _extract_code(str(err))
        return {
            "error": {
                "type": type(err).__name__,
                "code": code or "UNKNOWN",
                "message": str(err),
            }
        }
    return {"error": {"type": "none", "code": "NONE", "message": "no error raised"}}


OP_EVENT_LOG_VERIFY_MALFORMED_CLAIM_REJECTED = OpSpec(
    name="event_log_verify_malformed_claim_rejected",
    py_call=_py_event_log_verify_malformed_claim,
    node_call={"op": "event_log_verify_malformed_claim_rejected", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("error.type", "ignore"),
            FieldSpec("error.code", "exact"),
            FieldSpec("error.message", "ignore"),
        )
    ),
    # Pin the committed malformed-claim code. A bridge drifting to
    # VALID-7001 (the pre-fix PyO3 behavior) fails both the parity
    # equality and this literal pin.
    expected_values=(("error.code", EXPECTED_MALFORMED_CLAIM_CODE),),
)


# ---------------------------------------------------------------------------
# op 16: mcp_context_events_authoritative
#
# The direct cross-bridge regression guard for the `context_events` twin
# (GitHub #1933, BLACK-1933-1). The MCP `events` resource — and the
# `mcp_context_events` bridge method that publishes the identical summary —
# reports an event-log summary `{event_count, merkle_root}`. Before this fix
# every bridge computed that root over its OWN caller-influenceable
# bridge-local tree (PyO3/UniFFI) or returned an empty array (NAPI): the
# exact forgeable-root class #1933 severs on verify/checkpoint/query, left
# live on the agent-facing MCP surface, plus a THIRD cross-bridge
# inconsistency. Ops 12/13/14 cover the verify path; NONE covers the MCP
# summary surface, so the twin went unguarded.
#
# This op:
#   1. creates a context (authoritative log gets `ContextCreated` @ leaf 0);
#   2. reads the AUTHORITATIVE root + leaf count from `event_log_verify`
#      inclusion@0 — an INDEPENDENT path, NOT the MCP surface under test;
#   3. calls the public `provenance_attach`, which appends a
#      `ProvenanceReceived` leaf to the BRIDGE-LOCAL tree that is NOT in the
#      authoritative log — the two trees now diverge;
#   4. reads the `mcp_context_events` summary and asserts its root + count
#      STILL equal the authoritative ones (it did NOT move to the
#      caller-shaped tree) — the direct regression guard for this twin.
#
# The raw `merkle_root` bytes are NOT compared cross-bridge: a fresh
# `ContextCreated` leaf carries a wall-clock timestamp, so its hash (and the
# root) legitimately differs per bridge — the same reason ops 4/12/13 pin
# `event_count`/`leaf_count` but never the root value. Instead this op pins
# the SEMANTIC invariant `root_matches_authoritative` (a within-bridge
# comparison against the independent verify path) plus the authoritative
# `event_count` (deterministically 1), both IDENTICAL across all three
# bridges post-fix. Pre-fix the bridges DISAGREE — PyO3/UniFFI report the
# 2-leaf divergent local tree (`event_count == 2`,
# `root_matches_authoritative == False`), NAPI the empty array
# (`event_count == -1`) — and the `expected_values` pins flip, catching both
# a reverted routing fix AND joint drift.
# ---------------------------------------------------------------------------


# The committed post-fix invariant: after the bridge-local tree is diverged,
# the MCP `events` summary STILL commits to the authoritative log.
EXPECTED_CONTEXT_EVENTS_MATCHES_AUTHORITATIVE = True


def _py_mcp_context_events_authoritative(ctx: OpContext) -> dict[str, Any]:
    scp, identity = ctx.attached_scp()
    handle = scp.context_create(identity.did, dict(_VERIFY_CONTEXT_PARAMS))
    ctx_id = handle.context_id
    # AUTHORITATIVE root + count from the verify path — independent of the
    # MCP summary surface under test.
    proof = scp.event_log_verify(ctx_id, {"type": "inclusion", "leaf_index": 0})
    auth_root = str(proof.details["root"])
    auth_count = int(proof.details["leaf_count"])
    # Diverge the bridge-local tree via a real public bridge call (appends a
    # `ProvenanceReceived` leaf NOT in the authoritative log).
    scp.provenance_attach(
        _DIVERGENCE_PROV_SOURCE,
        "persistent",
        "full",
        [identity.did],
        ctx_id,
        identity.did,
        None,
    )
    # The MCP `events` summary under test.
    summary = json.loads(scp.mcp_context_events(ctx_id))
    ce_root = summary.get("merkle_root")
    ce_count = summary.get("event_count")
    return {
        "event_count": ce_count if isinstance(ce_count, int) else -1,
        "root_matches_authoritative": ce_root == auth_root,
        "count_matches_authoritative": ce_count == auth_count,
    }


OP_MCP_CONTEXT_EVENTS_AUTHORITATIVE = OpSpec(
    name="mcp_context_events_authoritative",
    py_call=_py_mcp_context_events_authoritative,
    node_call={"op": "mcp_context_events_authoritative", "args": {}},
    schema=OpSchema(
        fields=(
            FieldSpec("event_count", "exact"),
            FieldSpec("root_matches_authoritative", "exact"),
            FieldSpec("count_matches_authoritative", "exact"),
        )
    ),
    # Pin the committed post-fix invariant. A bridge that regressed to the
    # divergent local tree (or the empty array) fails both the parity equality
    # and these literal pins — including under joint drift, where every bridge
    # would report `count_matches_authoritative == False` together. The absolute
    # `event_count` is intentionally NOT pinned (it equals the authoritative
    # leaf count, which the cross-bridge `exact` comparison already holds
    # identical without hard-coding its value).
    expected_values=(
        (
            "root_matches_authoritative",
            EXPECTED_CONTEXT_EVENTS_MATCHES_AUTHORITATIVE,
        ),
        (
            "count_matches_authoritative",
            EXPECTED_CONTEXT_EVENTS_MATCHES_AUTHORITATIVE,
        ),
    ),
)


# ---------------------------------------------------------------------------
# Why there is NO missing-signing-custody parity op here.
#
# The missing-signing-custody condition (a sign operation invoked for an
# identity/handle that retains no custody) is deliberately NOT a cross-bridge
# equality op: (a) the expected code diverges by bridge BY DESIGN, so an
# equality comparator would force a false match; and (b) the no-custody handle
# is not reachable through the public JSON-RPC flow the parity runners drive —
# a normal `context_create` always stamps the creator's retained custody onto
# the returned handle, and the runner exposes no synthetic-handle construction
# to bypass that. The condition is instead covered by per-bridge inline tests.
#
# For the canonical code and its full per-bridge cross-bridge contract, see the
# "SCP-IDENT-1017 and its cross-bridge contract" section in
# `.docs/standards/sdk-common.md`.


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


SEED_OPS: tuple[OpSpec, ...] = (
    OP_IDENTITY_CREATE,
    OP_CONTEXT_CREATE,
    OP_INVALID_CAPABILITY,
    OP_EVENT_LOG_APPEND,
    OP_SIGN_MESSAGE,
    OP_OUTLET_REGISTER,
    OP_UCAN_MINT,
    OP_UCAN_VALIDATE_MALFORMED,
    OP_UCAN_EVALUATE_MALFORMED,
    OP_UCAN_EVALUATE_STRUCTURED,
    OP_TRANSPORT_STATUS,
    OP_EVENT_LOG_FILTERED,
    OP_UNREGISTERED_DID_REJECTED,
    OP_EVENT_LOG_VERIFY_INCLUSION,
    OP_EVENT_LOG_ABSENCE_OF_LIFECYCLE_EVENT_REJECTED,
    OP_EVENT_LOG_ABSENCE_OVER_DIVERGENT_LOCAL_TREE_REJECTED,
    OP_EVENT_LOG_VERIFY_MALFORMED_CLAIM_REJECTED,
    OP_MCP_CONTEXT_EVENTS_AUTHORITATIVE,
)
