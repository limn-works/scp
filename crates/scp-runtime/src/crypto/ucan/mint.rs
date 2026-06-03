//! UCAN token minting and delegation for SCP.
//!
//! Creates, signs, and delegates UCAN tokens with Ed25519 signatures, nonce
//! generation, and capability attestation construction. Tokens are scoped to a
//! specific context and audience (member DID).
//!
//! # Minting
//!
//! [`mint_ucan`] creates a new root UCAN token signed by the context creator.
//! The token includes a unique nonce, capability attestations scoped to a
//! context, and an Ed25519 signature.
//!
//! # Delegation
//!
//! [`delegate_ucan`] creates a delegated UCAN from an existing parent token.
//! Delegation enforces attenuation (capabilities can only narrow, never widen)
//! and links to the parent via its CID in the proof chain.
//!
//! # CID computation
//!
//! [`compute_cid`] produces a content identifier for a UCAN token, used as the
//! key in proof chains (`prf`) and revocation lists. The CID is a SHA-256 hash
//! of the encoded JWT, multibase-encoded with a `bafyrei` prefix following the
//! CID v1 / raw codec / sha2-256 convention.
//!
//! See ADR-009 in `.docs/adrs/phase-2.md` and ADR-016 in `.docs/adrs/phase-3.md`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use scp_platform::traits::{KeyCustody, KeyHandle};
use scp_primitives::Clock;

use std::collections::HashSet;

use scp_protocol::crypto::ucan::capability::{CapabilityUri, verify_ceiling_compliance};
use scp_protocol::crypto::ucan::nonce::generate_nonce;
use scp_protocol::crypto::ucan::{Attenuation, UcanError, UcanHeader, UcanPayload, UcanToken};
use scp_protocol::identity::SigningKeyId;

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Validates `key_scope` format: must start with `#` (verification method fragment).
///
/// Returns `Ok(())` if `key_scope` is `None` or a valid fragment.
fn validate_key_scope(key_scope: Option<&String>) -> Result<(), UcanError> {
    if let Some(scope) = key_scope
        && !scope.starts_with('#')
    {
        return Err(UcanError::MalformedToken(format!(
            "key_scope must be a verification method fragment starting with '#', got: {scope}"
        )));
    }
    Ok(())
}

/// Rejects self-delegation (iss == aud) without `key_scope` (ADR-039).
///
/// Self-delegation is the mechanism for human-to-agent key delegation on the
/// same DID. Without `key_scope`, such tokens always fail validation.
fn reject_self_delegation_without_scope(
    issuer: &str,
    audience: &str,
    key_scope: Option<&String>,
) -> Result<(), UcanError> {
    if issuer == audience && key_scope.is_none() {
        return Err(UcanError::MalformedToken(
            "self-delegation (iss == aud) requires key_scope (ADR-039)".to_owned(),
        ));
    }
    Ok(())
}

/// Verifies that attestation capability URIs are within the ceiling.
///
/// Parses each attestation's `with` field as a [`CapabilityUri`] and checks
/// it against the ceiling set. Returns an error if any capability is outside
/// the ceiling or if any URI is unparseable.
fn verify_attestation_ceiling_compliance(
    attenuations: &[Attenuation],
    ceiling: &HashSet<String>,
) -> Result<(), UcanError> {
    let cap_uris: Vec<CapabilityUri> = attenuations
        .iter()
        .map(|att| {
            att.with.parse::<CapabilityUri>().map_err(|e: UcanError| {
                UcanError::AttenuationViolation(format!(
                    "invalid capability URI '{}': {e}",
                    att.with
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    verify_ceiling_compliance(&cap_uris, ceiling)
}

/// Infers the [`OutletKind`] of a delegation from the stem family of its
/// delegated capability URIs, mirroring the root-mint inference in
/// [`scp_protocol::trust::caveats::InvocationCaveats::try_new_for_root`].
///
/// Used by [`build_delegated_caveats`] to materialize an explicit
/// `origin_kind` on the FIRST non-root delegation, where the parent (root)
/// token may legitimately carry `origin_kind = None` (§7.3.8 rule 3): the
/// root's single-kind stem set is unambiguous, and the first delegation
/// pins the inferred value into the child's signed caveats so every
/// downstream hop sees an explicit, equality-checked value.
///
/// - `outlet_query:*` / `outlet_query:{id}` ⇒ [`OutletKind::Query`].
/// - `outlet_call:*` / `outlet_call:{id}` ⇒ [`OutletKind::Action`].
/// - Non-outlet stems contribute nothing (returns `None` when no outlet
///   stems are present — there is no outlet kind to materialize).
///
/// # Errors
///
/// Returns [`UcanError::AttenuationViolation`] when the delegated set is
/// mixed-kind (carries BOTH `outlet_query:*` and `outlet_call:*` stems):
/// such a set has no single unambiguous `origin_kind` and is rejected at
/// mint, matching [`scp_protocol::trust::caveats::CaveatMintError::OriginKindMixedStemRoot`].
/// Returns [`UcanError::AttenuationViolation`] when any attestation URI is
/// unparseable (fail-closed).
fn infer_origin_kind_from_capabilities(
    attenuated_capabilities: &[Attenuation],
) -> Result<Option<scp_protocol::context::outlets::OutletKind>, UcanError> {
    use scp_protocol::context::outlets::OutletKind;

    let mut has_query = false;
    let mut has_action = false;
    for att in attenuated_capabilities {
        let uri: CapabilityUri = att.with.parse().map_err(|e: UcanError| {
            UcanError::AttenuationViolation(format!(
                "invalid capability URI '{}' while inferring origin_kind: {e}",
                att.with
            ))
        })?;
        match uri.resource() {
            "outlet_query" => has_query = true,
            "outlet_call" => has_action = true,
            _ => {}
        }
    }

    match (has_query, has_action) {
        (true, true) => Err(UcanError::AttenuationViolation(
            "origin-kind-mixed-stem: delegated set carries both outlet_query and \
             outlet_call stems; origin_kind is ambiguous"
                .to_owned(),
        )),
        (true, false) => Ok(Some(OutletKind::Query)),
        (false, true) => Ok(Some(OutletKind::Action)),
        (false, false) => Ok(None),
    }
}

/// SCP-OUT-023 / A+A caveat re-materialization: builds the delegated
/// child's COMPLETE, self-contained `nb` (effective caveat set) per the
/// §7.3.8 canonical model.
///
/// The canonical model requires that EVERY non-root token's `nb` carry the
/// complete narrowed effective set — never a partial that relies on the
/// validator inferring inherited bounds. The mint folds the parent's
/// effective caveats into the child so the leaf `nb` IS the
/// validated-narrowed `effective_caveats` (§5.4.5) with no SDK-side fold,
/// and the validator can enforce per-edge narrowing statelessly while
/// rejecting any non-root child that omits a field its parent bound.
///
/// Construction:
///
/// 1. **Caller supplies `None`** — the child inherits the parent's `nb`
///    verbatim (the full effective set). A root parent with no caveats
///    (`nb = None`) yields a child with no caveats EXCEPT that an
///    `origin_kind` is still materialized from the delegated capability
///    stems when those stems are outlet stems (so the first delegation off
///    an unconstrained root pins the kind).
///
/// 2. **Caller supplies `Some(child)`** — every field the caller omitted
///    (`None`) is filled from the parent's value (inherit), and every field
///    the caller set is taken as-is (tighten). `origin_kind` is materialized
///    explicitly: inherited from the parent when the parent has a value, or
///    inferred from the delegated capability stems when the parent (root) is
///    `None`.
///
/// After materialization the function runs `parent.narrow(&materialized)`
/// (the per-field §7.3.8 attenuation gate — rejects any widening, removal,
/// or `origin_kind` change) and then [`InvocationCaveats::try_new`] (the
/// mint-limit gate). The result is a child `nb` that is provably `<=` the
/// parent on every field and is structurally complete.
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] when the materialized child fails
/// [`scp_protocol::trust::caveats::InvocationCaveats::try_new`] (mint-limit
/// overflow, mask-width violation). Returns
/// [`UcanError::AttenuationViolation`] when the parent's caveats reject the
/// materialized child via
/// [`scp_protocol::trust::caveats::InvocationCaveats::narrow`], or when
/// `origin_kind` inference fails (mixed-stem set / unparseable URI).
fn build_delegated_caveats(
    params: &DelegateParams<'_>,
) -> Result<Option<scp_protocol::trust::caveats::InvocationCaveats>, UcanError> {
    use scp_protocol::trust::caveats::InvocationCaveats;

    let parent_nb = params.parent_token.payload.nb.as_ref();

    // §7.3.8 outlet-scoping: invocation caveats (max_calls / amount_max_* /
    // rate_window / origin_kind / valid_* / hours_of_day / days_of_week /
    // allowed_adapters / allowed_target_dids / input_schema) bind outlet
    // *invocation* and are meaningless on a non-outlet capability. A delegated
    // capability set that contains NO outlet stem (outlet_query:* /
    // outlet_call:*) therefore carries NO invocation caveats — its `nb` MUST
    // be `None`. We must NOT fold an ancestor's outlet-scoped caveats onto a
    // legitimately-narrowed non-outlet child: doing so would (a) attach
    // nonsensical bounds to e.g. `messages:write`, and (b) wrongly reject the
    // honest delegation when origin_kind cannot be materialized for a
    // non-outlet stem (no stem family to infer). This is the symmetric mirror
    // of the validator's outlet-edge gate in `verify_edge_attenuation`. Uses
    // the SHARED stem classifier so mint and validator never diverge.
    let child_is_outlet_edge = scp_protocol::crypto::ucan::capability::att_set_has_outlet_stem(
        params.attenuated_capabilities,
    )
    .map_err(|e| {
        UcanError::AttenuationViolation(format!("outlet-scope classification failed: {e}"))
    })?;
    if !child_is_outlet_edge {
        // Non-outlet child: drop any inherited outlet-scoped caveats entirely.
        // Do not materialize origin_kind, do not narrow. The child is
        // genuinely caveat-free — identical to the pre-caveat baseline. A
        // caller that supplied non-`None` caveats on a non-outlet delegation
        // is supplying outlet-scoped fields that cannot apply; the strongest
        // safe action is to drop them (the validator likewise ignores them on
        // a non-outlet edge), keeping the child attenuated and well-formed.
        return Ok(None);
    }

    // The child's effective set is the parent's effective set overlaid with
    // the caller-supplied fields. When the caller supplies nothing, the
    // overlay is empty and the child inherits the parent verbatim (modulo
    // origin_kind materialization below).
    let child_caveats = params
        .caveats
        .clone()
        .unwrap_or_else(InvocationCaveats::empty);

    // The parent's effective set: a root with no nb contributes no field
    // bounds (empty). A non-root parent (or a root minted WITH caveats)
    // already carries its complete validated set.
    let parent_effective = parent_nb.map_or_else(InvocationCaveats::empty, Clone::clone);

    // Infer the origin_kind implied by the delegated capability stems.
    // Always computed (even when the parent pins a value) so a caller's
    // explicit origin_kind can be cross-checked against the stem family —
    // closing the gap where a root with NO caveats (parent_nb = None) never
    // ran the root-mint stem/kind agreement check (`try_new_for_root`).
    let inferred_origin_kind = infer_origin_kind_from_capabilities(params.attenuated_capabilities)?;

    // Materialize an explicit origin_kind for the child. Inherit the
    // parent's value when present; otherwise — the parent is a root with
    // origin_kind = None (permitted by §7.3.8 rule 3) — use the inferred
    // stem kind. This is the point at which the chain's origin_kind becomes
    // a signed, explicit, equality-checked value for every hop below the
    // root (rule 4 materialization).
    let inherited_origin_kind = parent_effective.origin_kind.or(inferred_origin_kind);

    // When the parent pins NO origin_kind (root-None) and the caller
    // supplied an explicit origin_kind, that value MUST agree with the stem
    // family. The downstream narrow() against an empty parent cannot catch
    // this (parent None vs child Some is admissible there), so enforce the
    // stem/kind agreement here — the same invariant the root mint enforces
    // via `try_new_for_root` when the root DOES carry caveats.
    if parent_effective.origin_kind.is_none()
        && let Some(caller_kind) = child_caveats.origin_kind
        && let Some(inferred) = inferred_origin_kind
        && caller_kind != inferred
    {
        return Err(UcanError::AttenuationViolation(format!(
            "origin-kind-stem-mismatch: declared origin_kind {caller_kind:?} \
             disagrees with delegated stem family {inferred:?}"
        )));
    }

    // At this point the delegated set is guaranteed to contain at least one
    // outlet stem (the non-outlet edge returned `None` above), so
    // `infer_origin_kind_from_capabilities` resolved to `Some` (a single-
    // family outlet set) or already errored (mixed-stem). Therefore
    // `inherited_origin_kind` is always `Some` here and the child's `nb` is
    // always materialized — an outlet edge can never be silently caveat-free.

    let materialized = InvocationCaveats {
        amount_max_per_call: child_caveats
            .amount_max_per_call
            .or(parent_effective.amount_max_per_call),
        amount_max_cumulative: child_caveats
            .amount_max_cumulative
            .or(parent_effective.amount_max_cumulative),
        valid_from: child_caveats.valid_from.or(parent_effective.valid_from),
        valid_until: child_caveats.valid_until.or(parent_effective.valid_until),
        hours_of_day: child_caveats.hours_of_day.or(parent_effective.hours_of_day),
        days_of_week: child_caveats.days_of_week.or(parent_effective.days_of_week),
        max_calls: child_caveats.max_calls.or(parent_effective.max_calls),
        rate_window: child_caveats.rate_window.or(parent_effective.rate_window),
        input_schema: child_caveats
            .input_schema
            .clone()
            .or_else(|| parent_effective.input_schema.clone()),
        allowed_adapters: child_caveats
            .allowed_adapters
            .clone()
            .or_else(|| parent_effective.allowed_adapters.clone()),
        allowed_target_dids: child_caveats
            .allowed_target_dids
            .clone()
            .or_else(|| parent_effective.allowed_target_dids.clone()),
        // origin_kind: a caller-supplied value must agree with the inherited
        // value (narrow() enforces equality below); when the caller omits
        // it, materialize the inherited/inferred value so the child is never
        // origin_kind = None on a non-root.
        origin_kind: child_caveats.origin_kind.or(inherited_origin_kind),
    };

    // Final gates: per-field attenuation against the parent, then mint
    // limits. narrow() rejects any widening / field removal / origin_kind
    // change and rejects a still-absent origin_kind (OriginKindUnspecified).
    let validated = InvocationCaveats::try_new(materialized)
        .map_err(|e| UcanError::MalformedToken(format!("caveat-mint-limit-exceeded: {e}")))?;
    if let Some(parent_caveats) = parent_nb {
        parent_caveats.narrow(&validated).map_err(|e| {
            UcanError::AttenuationViolation(format!("caveat narrow violation: {e}"))
        })?;
    } else {
        // Root parent (no nb): there is no parent bound to narrow against,
        // but a non-root child still MUST carry an explicit origin_kind.
        // narrow() against an empty parent enforces exactly this
        // (OriginKindUnspecified when child.origin_kind is None) without
        // imposing any field bound the root never had.
        InvocationCaveats::empty().narrow(&validated).map_err(|e| {
            UcanError::AttenuationViolation(format!("caveat narrow violation: {e}"))
        })?;
    }
    Ok(Some(validated))
}

/// Builds the ROOT token's `nb` (invocation caveats) per §7.3.8 outlet-scoping
/// and the root stem/`origin_kind` agreement gate.
///
/// `None` preserves legacy caveat-free behaviour. Limit violations are mapped
/// to [`UcanError::MalformedToken`] carrying the spec slug, which the bridge
/// layer surfaces as `SCP-TOOL-6114` (`caveat-mint-limit-exceeded`).
///
/// §7.3.8 outlet-scoping (consistent with [`build_delegated_caveats`]):
/// invocation caveats are meaningful ONLY for outlet stems (`outlet_query:*` /
/// `outlet_call:*`). A root whose capability set contains NO outlet stem
/// carries NO invocation caveats — its `nb` is `None` even when the caller
/// supplied a `caveats` value (those outlet-scoped fields cannot apply to a
/// non-outlet capability such as `messages:write`).
///
/// When the root DOES carry outlet stems, the caveats are routed through
/// [`scp_protocol::trust::caveats::InvocationCaveats::try_new_for_root`], which
/// (1) rejects a mixed outlet-stem root (both `outlet_query` and `outlet_call`
/// present — ambiguous `origin_kind`), (2) rejects an explicit `origin_kind`
/// that contradicts the single stem family, and (3) runs the full
/// `try_new` mint-limit check. This wires the previously-unused root stem/kind
/// agreement gate into the mint path so a root can never be signed with an
/// `origin_kind` disagreeing with its stems.
///
/// # Mixed-family rejection is UNCONDITIONAL (§7.3.8:868)
///
/// The mixed-family stem check runs for EVERY outlet root regardless of whether
/// the caller supplied `caveats`. The mint is the single point where root-signer
/// intent is verified: a root whose capability stems span BOTH the
/// `outlet_query` and `outlet_call` families has an ambiguous `origin_kind` and
/// is rejected (`SCP-TOOL-6114` / `origin-kind-mixed-stem-root`), even when
/// `caveats == None`. Previously the `None` and `Some(_)`-without-outlet-stem
/// arms short-circuited to `Ok(None)` BEFORE this check, so a mixed-family root
/// with `caveats == None` could be signed — that hole is now closed by running
/// `try_new_for_root` (over [`InvocationCaveats::empty()`](scp_protocol::trust::caveats::InvocationCaveats::empty)
/// when no caveats were supplied) purely for its mixed-family / stem-agreement
/// gate, then returning `None` so a single-family root with no caveats still
/// carries `nb = None`.
///
/// A non-outlet root (no outlet stems) carries `nb = None` regardless of any
/// supplied (and inapplicable) outlet-scoped caveats.
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] when `try_new_for_root` rejects the
/// caveats (mint-limit overflow, mixed-stem root, or stem/`origin_kind`
/// mismatch).
fn build_root_caveats(
    caveats: Option<scp_protocol::trust::caveats::InvocationCaveats>,
    parsed_stems: &[scp_protocol::context::roles::Capability],
) -> Result<Option<scp_protocol::trust::caveats::InvocationCaveats>, UcanError> {
    use scp_protocol::context::roles::Capability;
    use scp_protocol::trust::caveats::InvocationCaveats;

    let root_has_outlet_stem = parsed_stems.iter().any(|cap| {
        matches!(
            cap,
            Capability::OutletQuery(_)
                | Capability::OutletQueryAll
                | Capability::OutletCall(_)
                | Capability::OutletCallAll
        )
    });

    // Non-outlet root: invocation caveats are outlet-scoped (§7.3.8), so any
    // supplied caveats are inapplicable and `nb` is `None`. There is no stem
    // family to mix, so the mixed-family gate does not apply.
    if !root_has_outlet_stem {
        return Ok(None);
    }

    // Outlet root: ALWAYS run the root stem/kind agreement gate, regardless of
    // whether caveats were supplied. `try_new_for_root` performs the
    // UNCONDITIONAL mixed-family rejection (§7.3.8:868) plus the stem/origin_kind
    // agreement and mint-limit checks. When no caveats were supplied we route
    // `empty()` purely for that gate, then drop the validated `empty()` back to
    // `None` so a single-family root with no caveats still carries `nb = None`.
    let had_caveats = caveats.is_some();
    let validated = InvocationCaveats::try_new_for_root(
        caveats.unwrap_or_else(InvocationCaveats::empty),
        parsed_stems,
    )
    .map_err(|e| UcanError::MalformedToken(format!("caveat-mint-limit-exceeded: {e}")))?;

    // A single-family outlet root with no supplied caveats passes the gate but
    // still carries `nb = None` (the validated `empty()` is not a real caveat
    // set — it existed only to run the mixed-family / stem-agreement check).
    Ok(had_caveats.then_some(validated))
}

/// Builds the `fct` (facts) section, merging `scp_key_scope` when present.
///
/// Returns an error if `facts` already contains an `scp_key_scope` value that
/// conflicts with the `key_scope` parameter.
fn build_facts_with_key_scope(
    facts: Option<&serde_json::Value>,
    key_scope: Option<&String>,
) -> Result<Option<serde_json::Value>, UcanError> {
    match key_scope {
        Some(scope) => {
            let mut facts_obj = match facts {
                Some(serde_json::Value::Object(map)) => map.clone(),
                Some(val) => {
                    // If facts is a non-object value, wrap it: preserve the
                    // original under "_original" and add scp_key_scope at the
                    // top level. This is defensive — callers should pass objects.
                    let mut map = serde_json::Map::new();
                    map.insert("_original".to_owned(), val.clone());
                    map
                }
                None => serde_json::Map::new(),
            };
            let old = facts_obj.insert(
                "scp_key_scope".to_owned(),
                serde_json::Value::String(scope.clone()),
            );
            if old
                .as_ref()
                .is_some_and(|existing| *existing != serde_json::Value::String(scope.clone()))
            {
                return Err(UcanError::MalformedToken(
                    "facts.scp_key_scope conflicts with key_scope parameter".to_owned(),
                ));
            }
            Ok(Some(serde_json::Value::Object(facts_obj)))
        }
        None => Ok(facts.cloned()),
    }
}

/// Parameters for minting a new UCAN token.
///
/// Encapsulates the inputs needed by [`mint_ucan`] to create a signed UCAN
/// token. The caller provides the issuer's signing key handle, the audience
/// DID, the context ID, the capabilities to grant, and the desired expiry.
///
/// # Key scope delegation (ADR-039)
///
/// When `key_scope` is set (e.g., `Some("#agent".to_owned())`), the minted
/// token includes:
/// - `kid` in the JWT header — identifies which verification method signed
///   the token (RFC 7515).
/// - `scp_key_scope` in the `fct` (facts) section — scopes the delegation
///   to the specified key.
///
/// Self-delegation (`iss == aud`, same DID) with `key_scope` is explicitly
/// valid per ADR-039 acceptance criterion 8. This is the mechanism by which
/// a human delegates permissions to their agent key on the same DID.
///
/// See ADR-016 acceptance criterion 3 and ADR-039 acceptance criterion 6.
pub struct MintParams<'a> {
    /// The issuer's DID string (context creator).
    pub issuer_did: &'a str,
    /// Handle to the issuer's Ed25519 signing key (managed by [`KeyCustody`]).
    pub issuer_key: &'a KeyHandle,
    /// The audience DID (the member receiving this token).
    pub audience_did: &'a str,
    /// The context ID this token is scoped to.
    pub context_id: &'a str,
    /// Capabilities to grant, as `{resource}:{action}` strings (e.g.,
    /// `"messages:write"`, `"outlet_call:assistant"`).
    pub capabilities: &'a [String],
    /// Token lifetime in seconds from now. Must not exceed 24 hours (86400s).
    pub lifetime_secs: u64,
    /// Optional not-before timestamp (Unix seconds). If `None`, the token is
    /// valid immediately.
    pub not_before: Option<u64>,
    /// Optional proof chain CIDs (for delegated tokens).
    pub proofs: Vec<String>,
    /// Optional facts to attach to the token.
    pub facts: Option<serde_json::Value>,
    /// Optional key scope for key-specific delegation (ADR-039).
    ///
    /// When set, identifies which verification method on the issuer's DID
    /// document this token is scoped to (e.g., `"#active"` or `"#agent"`).
    /// The value is included as `scp_key_scope` in the payload `fct` section
    /// and also sets `kid` in the JWT header (unless overridden by
    /// `signing_key_id`).
    ///
    /// Self-delegation (`iss == aud`) is valid when `key_scope` is present.
    pub key_scope: Option<String>,
    /// Optional signing key identity for the JWT `kid` header (ADR-039).
    ///
    /// When set, explicitly identifies which verification method signed this
    /// token. This ensures agent-signed UCANs have `kid: "#agent"` in the
    /// header, enabling Category A enforcement during validation.
    ///
    /// If both `signing_key_id` and `key_scope` are set, `signing_key_id`
    /// takes precedence for the `kid` header value, while `key_scope` is
    /// still used for the `scp_key_scope` fact.
    ///
    /// If neither is set, the header has no `kid` field, which verifiers
    /// interpret as `#active` (the default human key).
    pub signing_key_id: Option<SigningKeyId>,
    /// Optional capability ceiling for the context (§5.3, ADR-016 step 8).
    ///
    /// When set, the requested capabilities are checked against the ceiling
    /// **before** the token is signed. Any capability not in the ceiling is
    /// rejected with [`UcanError::CapabilityOutsideCeiling`].
    ///
    /// The ceiling contains `{resource}:{action}` strings (e.g.,
    /// `"messages:read"`, `"outlet_call:assistant"`).
    ///
    /// `None` means no ceiling enforcement (backward-compatible default).
    pub ceiling: Option<HashSet<String>>,
    /// §7.3.8 invocation caveats (SCP-OUT-023). Routed into the UCAN `nb`
    /// field of the minted/delegated token. `None` produces a caveat-free
    /// token (legacy behaviour). The mint path runs
    /// [`scp_protocol::trust::caveats::InvocationCaveats::try_new`] before
    /// signing — limit violations surface as
    /// [`UcanError::CaveatMintLimitExceeded`].
    pub caveats: Option<scp_protocol::trust::caveats::InvocationCaveats>,
}

/// Mints a new UCAN token with Ed25519 signature.
///
/// Creates a complete UCAN token from the provided parameters: constructs
/// the JWT header and payload, generates a unique nonce, builds capability
/// attestations in the `scp:ctx:{context_id}/{capability}` format, encodes
/// the token as a JWT, and signs it with the issuer's Ed25519 key.
///
/// # Token structure
///
/// The minted token is a JWT with three base64url-encoded segments:
/// `base64url(header).base64url(payload).base64url(signature)`.
///
/// # Expiry constraint
///
/// The `lifetime_secs` must not exceed 24 hours (86400 seconds) per spec
/// section 9.5. If exceeded, returns [`UcanError::ExpiryTooFar`].
///
/// # Errors
///
/// Returns [`UcanError::ExpiryTooFar`] if `lifetime_secs` exceeds 24 hours.
/// Returns [`UcanError::MalformedToken`] if serialization or signing fails.
///
/// See ADR-016 acceptance criterion 3 and ADR-039 acceptance criterion 6.
pub async fn mint_ucan(
    params: &MintParams<'_>,
    custody: &impl KeyCustody,
    clock: &dyn Clock,
) -> Result<UcanToken, UcanError> {
    validate_key_scope(params.key_scope.as_ref())?;
    reject_self_delegation_without_scope(
        params.issuer_did,
        params.audience_did,
        params.key_scope.as_ref(),
    )?;

    // Enforce 24-hour maximum expiry.
    if params.lifetime_secs > MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(params.lifetime_secs));
    }

    // Convert capability strings to UCAN resource/action pairs. This bridges
    // the canonical user-facing colon format (e.g. "outlet:call:*") to the
    // UCAN underscore format (e.g. resource="outlet_call", action="*") by
    // parsing through the Capability enum. See #1293.
    //
    // The parsed `Capability` enum values are also retained so the root-mint
    // stem/origin_kind agreement check (`try_new_for_root`) can classify the
    // outlet stem family below — the same single source of truth the
    // delegation path uses, so a root can never be minted with an
    // origin_kind that contradicts its stems or with mixed outlet stems.
    let mut parsed_stems: Vec<scp_protocol::context::roles::Capability> =
        Vec::with_capacity(params.capabilities.len());
    let parsed_caps: Vec<(String, String)> = params
        .capabilities
        .iter()
        .map(|cap| {
            // Strict §5.4.2.1 parser: malformed outlet stems (e.g.
            // `outlet:invoke:foo`, `outlet_query:` empty suffix,
            // `outlet_query:FOO` uppercase) reject with
            // `MalformedToken` rather than silently degrading to a
            // `Custom` capability. This is the parser-differential
            // guard required by SCP-OUT-014.
            let capability =
                scp_protocol::context::roles::Capability::new(cap).ok_or_else(|| {
                    UcanError::MalformedToken(format!(
                        "invalid capability name {cap:?} (fails §5.4.2.1 parser)"
                    ))
                })?;
            let (resource, action) = capability.ucan_resource_action();
            let owned = (resource.into_owned(), action.into_owned());
            parsed_stems.push(capability);
            Ok::<(String, String), UcanError>(owned)
        })
        .collect::<Result<Vec<_>, UcanError>>()?;

    // Enforce ceiling compliance before doing any work (§5.3, #339).
    // Defense-in-depth: when no explicit ceiling is provided, apply the
    // protocol default ceiling so that capabilities outside the standard
    // set are always rejected at the core layer.
    let effective_ceiling = params
        .ceiling
        .clone()
        .unwrap_or_else(|| scp_protocol::context::roles::default_ceiling().to_ucan_string_set());
    {
        let cap_uris: Vec<CapabilityUri> = parsed_caps
            .iter()
            .map(|(resource, action)| {
                CapabilityUri::new(params.context_id, resource.as_str(), action.as_str())
            })
            .collect();
        verify_ceiling_compliance(&cap_uris, &effective_ceiling)?;
    }

    let now = clock.now_secs();
    let exp = now + params.lifetime_secs;

    // Build attestations from capabilities, scoped to the context.
    // Uses UCAN resource/action format for correct URI construction (#1293).
    let att: Vec<Attenuation> = parsed_caps
        .iter()
        .map(|(resource, action)| {
            let ucan_cap = format!("{resource}:{action}");
            Attenuation {
                with: format!("scp:ctx:{}/{ucan_cap}", params.context_id),
                can: action.clone(),
            }
        })
        .collect();

    // Build header — include kid when signing_key_id or key_scope is present
    // (ADR-039). signing_key_id takes precedence over key_scope for the kid
    // header value.
    let header = params.signing_key_id.as_ref().map_or_else(
        || {
            params
                .key_scope
                .as_ref()
                .map_or_else(UcanHeader::new, |scope| UcanHeader::with_kid(scope.clone()))
        },
        |signing_key_id| UcanHeader::with_kid(signing_key_id.as_fragment().to_owned()),
    );

    // Build facts — merge scp_key_scope into existing facts when key_scope
    // is present (ADR-039 acceptance criterion 6).
    let fct = build_facts_with_key_scope(params.facts.as_ref(), params.key_scope.as_ref())?;

    // SCP-OUT-023: validate caveats at mint time and route them into the
    // payload's `nb` field (§7.3.8 outlet-scoping + root stem/kind agreement).
    let nb = build_root_caveats(params.caveats.clone(), &parsed_stems)?;

    let payload = UcanPayload {
        iss: params.issuer_did.to_owned(),
        aud: params.audience_did.to_owned(),
        exp,
        nbf: params.not_before,
        nnc: generate_nonce(clock),
        att,
        prf: params.proofs.clone(),
        fct,
        nb,
    };

    // Encode header and payload as base64url JSON.
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| UcanError::MalformedToken(format!("header serialization failed: {e}")))?;
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| UcanError::MalformedToken(format!("payload serialization failed: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // The signing input is `base64url(header).base64url(payload)`.
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with Ed25519 via KeyCustody.
    let sig = custody
        .sign(params.issuer_key, signing_input.as_bytes())
        .await
        .map_err(|e| UcanError::MalformedToken(format!("signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    Ok(UcanToken {
        header,
        payload,
        signature: sig.into_bytes(),
        encoded,
    })
}

// ---------------------------------------------------------------------------
// CID computation
// ---------------------------------------------------------------------------

/// Computes the content identifier (CID) for a UCAN token.
///
/// The CID is used as the key in proof chains (`prf` field) and revocation
/// lists. It is computed as the SHA-256 hash of the encoded JWT string,
/// hex-encoded with a `bafyrei` prefix following the CID v1 / raw codec /
/// sha2-256 convention used throughout SCP.
///
/// # Determinism
///
/// The CID is deterministic: the same encoded token always produces the same
/// CID. This is critical for revocation (a revoked CID must match the token
/// it was computed from) and proof chain integrity.
///
/// See ADR-016 acceptance criteria 4 and 5.
#[must_use]
pub fn compute_cid(token: &UcanToken) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.encoded.as_bytes());
    let hash = hasher.finalize();

    let hex = hash.iter().fold(String::with_capacity(64), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    });

    format!("bafyrei{hex}")
}

// ---------------------------------------------------------------------------
// Delegation
// ---------------------------------------------------------------------------

/// Parameters for creating a delegated UCAN token.
///
/// Encapsulates the inputs needed by [`delegate_ucan`] to create a delegated
/// UCAN. The delegator (parent token's audience) delegates a subset of their
/// capabilities to a new delegatee.
///
/// See ADR-016 acceptance criterion 4.
pub struct DelegateParams<'a> {
    /// The parent UCAN token being delegated from. The delegator must be the
    /// audience (`aud`) of this token.
    pub parent_token: &'a UcanToken,
    /// The delegator's DID — must match `parent_token.payload.aud`.
    pub delegator_did: &'a str,
    /// Handle to the delegator's Ed25519 signing key.
    pub delegator_key: &'a KeyHandle,
    /// The delegatee's DID (the entity receiving the delegated capabilities).
    pub delegatee_did: &'a str,
    /// Capabilities to delegate, as full capability URI strings
    /// (`scp:ctx:{context_id}/{resource}:{action}`). Must be a subset of the
    /// parent token's `att` (attenuation, never widening).
    pub attenuated_capabilities: &'a [Attenuation],
    /// Token lifetime in seconds from now. Must not exceed 24 hours (86400s)
    /// and should not exceed the parent token's remaining lifetime.
    pub lifetime_secs: u64,
    /// Optional facts to attach to the delegated token.
    pub facts: Option<serde_json::Value>,
    /// Optional key scope for key-specific delegation (ADR-039).
    ///
    /// When set, identifies which verification method on the delegator's DID
    /// document signed this token (e.g., `"#active"` or `"#agent"`). Included
    /// as `scp_key_scope` in the payload `fct` and also sets `kid` in the
    /// JWT header (unless overridden by `signing_key_id`).
    pub key_scope: Option<String>,
    /// Optional signing key identity for the JWT `kid` header (ADR-039).
    ///
    /// When set, explicitly identifies which verification method signed this
    /// delegated token. Takes precedence over `key_scope` for the `kid`
    /// header value.
    ///
    /// See [`MintParams::signing_key_id`] for full documentation.
    pub signing_key_id: Option<SigningKeyId>,
    /// Optional capability ceiling for the context (§5.3, ADR-016 step 8).
    ///
    /// When set, delegated capabilities are checked against the ceiling
    /// **after** the attenuation check but **before** the token is signed.
    /// Any capability not in the ceiling is rejected with
    /// [`UcanError::CapabilityOutsideCeiling`].
    ///
    /// `None` means no ceiling enforcement (backward-compatible default).
    pub ceiling: Option<HashSet<String>>,
    /// §7.3.8 invocation caveats (SCP-OUT-023). Routed into the UCAN `nb`
    /// field of the minted/delegated token. `None` produces a caveat-free
    /// token (legacy behaviour). The mint path runs
    /// [`scp_protocol::trust::caveats::InvocationCaveats::try_new`] before
    /// signing — limit violations surface as
    /// [`UcanError::CaveatMintLimitExceeded`].
    pub caveats: Option<scp_protocol::trust::caveats::InvocationCaveats>,
}

/// Creates a delegated UCAN token from a parent token.
///
/// Delegation enforces the following invariants from ADR-016:
///
/// 1. **Delegator identity** — The `delegator_did` must match the parent
///    token's `aud` field. Only the intended audience of a token can delegate
///    it further.
///
/// 2. **Attenuation** — The `attenuated_capabilities` must be a subset of the
///    parent token's `att`. Delegation can only narrow capabilities, never
///    widen them. This prevents privilege escalation through delegation chains.
///
/// 3. **Proof chain** — The delegated token's `prf` field includes the parent
///    token's CID (computed via [`compute_cid`]), linking the delegation chain
///    for verification.
///
/// 4. **Signing** — The delegated token is signed with the delegator's Ed25519
///    key, proving the delegation was authorized by the parent's audience.
///
/// # Errors
///
/// Returns [`UcanError::AudienceMismatch`] if `delegator_did` does not match
/// `parent_token.payload.aud`.
/// Returns [`UcanError::AttenuationViolation`] if any capability in
/// `attenuated_capabilities` is not granted by the parent token.
/// Returns [`UcanError::ExpiryTooFar`] if `lifetime_secs` exceeds 24 hours.
/// Returns [`UcanError::MalformedToken`] if serialization or signing fails.
///
/// See ADR-016 acceptance criterion 4.
pub async fn delegate_ucan(
    params: &DelegateParams<'_>,
    custody: &impl KeyCustody,
    clock: &dyn Clock,
) -> Result<UcanToken, UcanError> {
    validate_key_scope(params.key_scope.as_ref())?;
    reject_self_delegation_without_scope(
        params.delegator_did,
        params.delegatee_did,
        params.key_scope.as_ref(),
    )?;

    // Step 1: Verify delegator DID matches parent token's audience.
    if params.delegator_did != params.parent_token.payload.aud {
        return Err(UcanError::AudienceMismatch {
            expected: params.parent_token.payload.aud.clone(),
            actual: params.delegator_did.to_owned(),
        });
    }

    // Step 2: Verify attenuation — all requested capabilities must be a subset
    // of the parent token's capabilities (never widen).
    // SECURITY: fail-closed — any unparseable parent URI rejects the entire delegation.
    let parent_caps: Vec<CapabilityUri> = params
        .parent_token
        .payload
        .att
        .iter()
        .map(|att| {
            att.with.parse::<CapabilityUri>().map_err(|_| {
                UcanError::MalformedToken(format!(
                    "unparseable capability URI in parent token: {}",
                    att.with
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for child_att in params.attenuated_capabilities {
        let child_cap: CapabilityUri = child_att.with.parse().map_err(|e: UcanError| {
            UcanError::AttenuationViolation(format!(
                "invalid capability URI '{}': {e}",
                child_att.with
            ))
        })?;

        let is_granted = parent_caps.iter().any(|parent| parent.matches(&child_cap));
        if !is_granted {
            return Err(UcanError::AttenuationViolation(format!(
                "capability '{}' is not granted by the parent token",
                child_att.with
            )));
        }
    }

    // Step 2b: Enforce ceiling compliance on delegated capabilities (#339).
    // Defense-in-depth: when no explicit ceiling is provided, apply the
    // protocol default ceiling so that capabilities outside the standard
    // set are always rejected at the core layer.
    let effective_ceiling = params
        .ceiling
        .clone()
        .unwrap_or_else(|| scp_protocol::context::roles::default_ceiling().to_ucan_string_set());
    verify_attestation_ceiling_compliance(params.attenuated_capabilities, &effective_ceiling)?;

    // Step 3: Enforce 24-hour maximum expiry.
    if params.lifetime_secs > MAX_EXPIRY_SECS {
        return Err(UcanError::ExpiryTooFar(params.lifetime_secs));
    }

    let now = clock.now_secs();
    let exp = now + params.lifetime_secs;

    // Step 4: Compute the parent token's CID for the proof chain.
    let parent_cid = compute_cid(params.parent_token);

    // NESTED proof chain (canonical model): the child references ONLY its
    // direct parent. The delegation chain is a linked list — each token's
    // `prf` holds the single CID of the token one hop up, and the validator
    // walks parent -> grandparent -> ... -> root by resolving each token's
    // own `prf` recursively (see `verify_chain_recursive`). We do NOT flatten
    // the parent's ancestors into the child's `prf`: a flattened leaf would
    // list `[root_cid, mid_cid]`, and the validator — which treats every
    // `prf` entry as a DIRECT parent and checks `parent.aud == child.iss` —
    // would reject the flattened grandparent (whose `aud` is the mid agent,
    // not the leaf issuer). The proof resolver is CID-keyed, so the full
    // chain is still resolvable: every token in the chain is inserted into
    // the resolver by CID, and the walk follows each token's direct-parent
    // pointer. No proofs are transported inline through the leaf's `prf`.
    let proofs = vec![parent_cid];

    // Build header — include kid when signing_key_id or key_scope is present
    // (ADR-039). signing_key_id takes precedence.
    let header = params.signing_key_id.as_ref().map_or_else(
        || {
            params
                .key_scope
                .as_ref()
                .map_or_else(UcanHeader::new, |scope| UcanHeader::with_kid(scope.clone()))
        },
        |signing_key_id| UcanHeader::with_kid(signing_key_id.as_fragment().to_owned()),
    );

    // Build facts — merge scp_key_scope into existing facts when key_scope
    // is present (ADR-039).
    let fct = build_facts_with_key_scope(params.facts.as_ref(), params.key_scope.as_ref())?;

    // SCP-OUT-023: child caveats are validated against parent caveats via
    // `narrow()`, then routed into the delegated token's `nb` field. The
    // helper centralises the try_new / narrow sequence so the mint-side
    // and any future caveat-bearing path share a single implementation.
    let nb = build_delegated_caveats(params)?;

    let payload = UcanPayload {
        iss: params.delegator_did.to_owned(),
        aud: params.delegatee_did.to_owned(),
        exp,
        nbf: None,
        nnc: generate_nonce(clock),
        att: params.attenuated_capabilities.to_vec(),
        prf: proofs,
        fct,
        nb,
    };

    // Encode header and payload as base64url JSON.
    let header_json = serde_json::to_vec(&header)
        .map_err(|e| UcanError::MalformedToken(format!("header serialization failed: {e}")))?;
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| UcanError::MalformedToken(format!("payload serialization failed: {e}")))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_json);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_json);

    // The signing input is `base64url(header).base64url(payload)`.
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with the delegator's Ed25519 key via KeyCustody.
    let sig = custody
        .sign(params.delegator_key, signing_input.as_bytes())
        .await
        .map_err(|e| UcanError::MalformedToken(format!("signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_bytes());
    let encoded = format!("{signing_input}.{sig_b64}");

    Ok(UcanToken {
        header,
        payload,
        signature: sig.into_bytes(),
        encoded,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use scp_platform::testing::InMemoryKeyCustody;
    use scp_platform::traits::KeyType;

    /// Helper: create an `InMemoryKeyCustody`, generate a key, and return both.
    async fn setup_custody() -> (InMemoryKeyCustody, KeyHandle, String) {
        let custody = InMemoryKeyCustody::new();
        let handle = custody.generate_keypair(KeyType::Ed25519).await.unwrap();
        let pubkey = custody.public_key(&handle).await.unwrap();
        let did = format!("did:dht:z{}", zbase32::encode(pubkey.as_bytes()));
        (custody, handle, did)
    }

    #[tokio::test]
    async fn mint_ucan_produces_valid_jwt_structure() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-abc123",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Verify JWT has three segments.
        assert_eq!(
            token.encoded.split('.').count(),
            3,
            "JWT must have 3 segments"
        );

        // Verify header fields.
        assert_eq!(token.header.alg, "EdDSA");
        assert_eq!(token.header.typ, "JWT");
        assert_eq!(token.header.ucv, "0.10.0");

        // Verify payload fields.
        assert_eq!(token.payload.iss, issuer_did);
        assert_eq!(token.payload.aud, "did:dht:z6MkMember");
        assert_eq!(token.payload.att.len(), 1);
        assert_eq!(
            token.payload.att[0].with,
            "scp:ctx:ctx-abc123/messages:write"
        );
        assert_eq!(token.payload.att[0].can, "write");
        assert!(token.payload.nbf.is_none());
        assert!(token.payload.prf.is_empty());

        // Verify signature length (Ed25519 = 64 bytes).
        assert_eq!(token.signature.len(), 64);
    }

    #[tokio::test]
    async fn mint_ucan_signature_verifies_with_issuer_public_key() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkAudience",
            context_id: "ctx-test",
            capabilities: &caps,
            lifetime_secs: 7200,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Reconstruct signing input from encoded token.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        // Verify signature using ed25519-dalek directly.
        let pubkey = custody.public_key(&key_handle).await.unwrap();
        let pk_bytes: [u8; 32] = pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let sig_bytes: [u8; 64] = token.signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok(),
            "Ed25519 signature must verify"
        );
    }

    #[tokio::test]
    async fn mint_ucan_nonce_has_correct_format() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let nonce = &token.payload.nnc;

        // Nonce format: {unix_millis_timestamp}-{32_hex_chars}
        let parts: Vec<&str> = nonce.splitn(2, '-').collect();
        assert_eq!(parts.len(), 2, "nonce must have timestamp-hex format");

        // Timestamp part must be a valid integer.
        let _ts: u128 = parts[0].parse().expect("timestamp must be numeric");

        // Hex part must be exactly 32 hex chars (16 bytes).
        assert_eq!(parts[1].len(), 32, "random suffix must be 32 hex chars");
        assert!(
            parts[1].chars().all(|c| c.is_ascii_hexdigit()),
            "random suffix must be valid hex"
        );
    }

    #[tokio::test]
    async fn mint_ucan_nonces_are_unique() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token1 = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let token2 = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_ne!(
            token1.payload.nnc, token2.payload.nnc,
            "nonces must be unique"
        );
    }

    #[tokio::test]
    async fn mint_ucan_rejects_expiry_beyond_24h() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: MAX_EXPIRY_SECS + 1,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(matches!(err, UcanError::ExpiryTooFar(_)));
    }

    #[tokio::test]
    async fn mint_ucan_expiry_exactly_24h_succeeds() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: MAX_EXPIRY_SECS,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        assert!(
            mint_ucan(&params, &custody, &scp_primitives::SystemClock)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn mint_ucan_multiple_capabilities() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "outlet_call:assistant".to_owned(),
        ];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-multi",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(token.payload.att.len(), 3);
        assert_eq!(token.payload.att[0].with, "scp:ctx:ctx-multi/messages:read");
        assert_eq!(token.payload.att[0].can, "read");
        assert_eq!(
            token.payload.att[1].with,
            "scp:ctx:ctx-multi/messages:write"
        );
        assert_eq!(token.payload.att[1].can, "write");
        assert_eq!(
            token.payload.att[2].with,
            "scp:ctx:ctx-multi/outlet_call:assistant"
        );
        assert_eq!(token.payload.att[2].can, "assistant");
    }

    #[tokio::test]
    async fn mint_ucan_with_proofs_and_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: Some(1_700_000_000),
            proofs: vec!["bafyreiabc123".to_owned()],
            facts: Some(serde_json::json!({"role": "member"})),
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(token.payload.nbf, Some(1_700_000_000));
        assert_eq!(token.payload.prf, vec!["bafyreiabc123"]);
        assert_eq!(
            token.payload.fct,
            Some(serde_json::json!({"role": "member"}))
        );
    }

    #[tokio::test]
    async fn mint_ucan_encoded_token_decodes_correctly() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-decode",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Decode the JWT parts and verify they match the struct fields.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();

        let decoded_header: UcanHeader = serde_json::from_slice(&header_bytes).unwrap();
        let decoded_payload: UcanPayload = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(decoded_header, token.header);
        assert_eq!(decoded_payload, token.payload);
    }

    // -------------------------------------------------------------------
    // compute_cid
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn compute_cid_returns_bafyrei_prefix() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let cid = compute_cid(&token);

        assert!(
            cid.starts_with("bafyrei"),
            "CID must start with 'bafyrei' prefix, got: {cid}"
        );
    }

    #[tokio::test]
    async fn compute_cid_is_deterministic() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let cid1 = compute_cid(&token);
        let cid2 = compute_cid(&token);

        assert_eq!(cid1, cid2, "CID must be deterministic for the same token");
    }

    #[tokio::test]
    async fn compute_cid_different_tokens_produce_different_cids() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token1 = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let token2 = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let cid1 = compute_cid(&token1);
        let cid2 = compute_cid(&token2);

        assert_ne!(
            cid1, cid2,
            "different tokens (different nonces) must produce different CIDs"
        );
    }

    #[tokio::test]
    async fn compute_cid_hex_has_correct_length() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-cid",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let cid = compute_cid(&token);

        // "bafyrei" (7 chars) + 64 hex chars (SHA-256) = 71 chars total.
        assert_eq!(cid.len(), 7 + 64, "CID must be 'bafyrei' + 64 hex chars");

        // The hex portion must be valid hex.
        let hex_part = &cid[7..];
        assert!(
            hex_part.chars().all(|c| c.is_ascii_hexdigit()),
            "CID hex portion must be valid hex"
        );
    }

    // -------------------------------------------------------------------
    // delegate_ucan — success cases
    // -------------------------------------------------------------------

    /// Helper: mint a root token from Alice to Bob with given capabilities.
    async fn mint_root_token(
        custody: &InMemoryKeyCustody,
        issuer_key: &KeyHandle,
        issuer_did: &str,
        audience_did: &str,
        context_id: &str,
        capabilities: &[String],
    ) -> UcanToken {
        let params = MintParams {
            issuer_did,
            issuer_key,
            audience_did,
            context_id,
            capabilities,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };
        mint_ucan(&params, custody, &scp_primitives::SystemClock)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn delegate_ucan_creates_valid_delegated_token() {
        // Alice creates a root token for Bob.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob delegates a subset to Carol.
        let carol_did = "did:dht:z6MkCarol";
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: carol_did,
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Verify structure.
        assert_eq!(delegated.payload.iss, bob_did);
        assert_eq!(delegated.payload.aud, carol_did);
        assert_eq!(delegated.payload.att.len(), 1);
        assert_eq!(delegated.payload.att[0].with, "scp:ctx:ctx-1/messages:read");
        assert_eq!(delegated.payload.att[0].can, "read");

        // Verify JWT has three segments.
        assert_eq!(
            delegated.encoded.split('.').count(),
            3,
            "delegated JWT must have 3 segments"
        );

        // Verify signature length.
        assert_eq!(delegated.signature.len(), 64);
    }

    #[tokio::test]
    async fn delegate_ucan_proof_chain_contains_parent_cid() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let parent_cid = compute_cid(&root_token);

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // The proof chain must include the parent CID.
        assert!(
            delegated.payload.prf.contains(&parent_cid),
            "delegated token prf must contain parent CID"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_signature_verifies_with_delegator_key() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Verify signature with Bob's public key.
        let bob_pubkey = bob_custody.public_key(&bob_key).await.unwrap();
        let pk_bytes: [u8; 32] = bob_pubkey.as_bytes().try_into().unwrap();
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).unwrap();

        let parts: Vec<&str> = delegated.encoded.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        let sig_bytes: [u8; 64] = delegated.signature.as_slice().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        assert!(
            verifying_key
                .verify(signing_input.as_bytes(), &signature)
                .is_ok(),
            "delegated token Ed25519 signature must verify with delegator's key"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_preserves_all_parent_capabilities() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "outlet_call:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegate all capabilities (exact copy, no narrowing).
        let attenuated: Vec<Attenuation> = root_token.payload.att.clone();

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        assert_eq!(delegated.payload.att.len(), 3);
    }

    #[tokio::test]
    async fn delegate_ucan_narrows_to_single_capability() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec![
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "outlet_call:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegate only messages:read.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        assert_eq!(delegated.payload.att.len(), 1);
        assert_eq!(delegated.payload.att[0].with, "scp:ctx:ctx-1/messages:read");
    }

    #[tokio::test]
    async fn delegate_ucan_includes_facts() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: Some(serde_json::json!({"delegated_by": "bob"})),
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        assert_eq!(
            delegated.payload.fct,
            Some(serde_json::json!({"delegated_by": "bob"}))
        );
    }

    #[tokio::test]
    async fn delegate_ucan_generates_unique_nonces() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let d1 = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let d2 = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_ne!(
            d1.payload.nnc, d2.payload.nnc,
            "delegated tokens must have unique nonces"
        );
    }

    // -------------------------------------------------------------------
    // delegate_ucan — chained delegation (A -> B -> C)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_chained_delegation_nests_proof_chain() {
        // Alice -> Bob -> Carol -> Dave: verify the proof chain is NESTED,
        // not flattened. Each delegated token references ONLY its direct
        // parent's CID (a linked list), so the validator can walk
        // child -> parent -> grandparent -> root recursively via each token's
        // own `prf`. A flattened chain (every ancestor CID in the leaf's
        // `prf`) breaks the walk's `parent.aud == child.iss` linkage check
        // for the flattened grandparents and rejects all depth>=3 honest
        // delegation.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;
        let (carol_custody, carol_key, carol_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];

        // Alice mints root token for Bob.
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;
        let root_cid = compute_cid(&root_token);
        assert!(root_token.payload.prf.is_empty());

        // Bob delegates to Carol.
        let bob_attenuated = vec![
            Attenuation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            },
            Attenuation {
                with: "scp:ctx:ctx-1/messages:write".to_owned(),
                can: "write".to_owned(),
            },
        ];

        let bob_delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: &carol_did,
            attenuated_capabilities: &bob_attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let bob_to_carol = delegate_ucan(
            &bob_delegate_params,
            &bob_custody,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();
        let bob_to_carol_cid = compute_cid(&bob_to_carol);

        // Bob's delegated token should have root CID in proof chain.
        assert_eq!(bob_to_carol.payload.prf.len(), 1);
        assert!(bob_to_carol.payload.prf.contains(&root_cid));

        // Carol delegates to Dave (further narrowing).
        let carol_attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let carol_delegate_params = DelegateParams {
            parent_token: &bob_to_carol,
            delegator_did: &carol_did,
            delegator_key: &carol_key,
            delegatee_did: "did:dht:z6MkDave",
            attenuated_capabilities: &carol_attenuated,
            lifetime_secs: 900,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let carol_to_dave = delegate_ucan(
            &carol_delegate_params,
            &carol_custody,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        // Carol's delegated token references ONLY its direct parent
        // (bob_to_carol), NOT the flattened ancestor (root). The chain is a
        // linked list: carol_to_dave.prf = [bob_to_carol_cid];
        // bob_to_carol.prf = [root_cid]; root.prf = []. The walk resolves
        // each hop via the proof resolver and recurses into the parent's own
        // `prf`.
        assert_eq!(
            carol_to_dave.payload.prf.len(),
            1,
            "nested chain: child references only its direct parent"
        );
        assert!(
            carol_to_dave.payload.prf.contains(&bob_to_carol_cid),
            "child prf must contain the direct parent's CID"
        );
        assert!(
            !carol_to_dave.payload.prf.contains(&root_cid),
            "child prf must NOT contain the flattened grandparent (root) CID"
        );
    }

    // -------------------------------------------------------------------
    // delegate_ucan — error cases
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_rejects_delegator_not_matching_parent_audience() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (_bob_custody, _bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Eve (not Bob) tries to delegate.
        let (eve_custody, eve_key, eve_did) = setup_custody().await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &eve_did,
            delegator_key: &eve_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = delegate_ucan(&delegate_params, &eve_custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AudienceMismatch { .. }),
            "must reject delegator not matching parent aud: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_capability_widening() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Root token only grants messages:read.
        let caps = vec!["messages:read".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate messages:write (not in parent).
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject capability widening: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_widening_with_extra_capability() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate including outlet_call:assistant (not in parent).
        let attenuated = vec![
            Attenuation {
                with: "scp:ctx:ctx-1/messages:read".to_owned(),
                can: "read".to_owned(),
            },
            Attenuation {
                with: "scp:ctx:ctx-1/outlet_call:assistant".to_owned(),
                can: "assistant".to_owned(),
            },
        ];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject widening with extra capability: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_different_context_as_widening() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Bob tries to delegate for a different context.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-OTHER/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject delegation for a different context: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_expiry_beyond_24h() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: MAX_EXPIRY_SECS + 1,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::ExpiryTooFar(_)),
            "must reject expiry beyond 24h: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_invalid_capability_uri() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "not-a-valid-uri".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::AttenuationViolation(_)),
            "must reject invalid capability URI: {err}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_empty_capabilities_succeeds() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Delegating zero capabilities is valid attenuation (maximally narrow).
        let attenuated: Vec<Attenuation> = vec![];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        assert!(delegated.payload.att.is_empty());
    }

    #[tokio::test]
    async fn delegate_ucan_wildcard_parent_grants_specific_child() {
        // A parent token with a wildcard capability should allow delegation to
        // a specific context.
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Manually create a root token with a wildcard capability.
        let wildcard_caps = vec![Attenuation {
            with: "scp:ctx:*/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let params = MintParams {
            issuer_did: &alice_did,
            issuer_key: &alice_key,
            audience_did: &bob_did,
            context_id: "*",
            capabilities: &["messages:write".to_owned()],
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };
        let mut root_token = mint_ucan(&params, &alice_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        // Overwrite att to use the explicitly wildcard form.
        root_token.payload.att = wildcard_caps;

        // Bob delegates to Carol for a specific context.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-specific/messages:write".to_owned(),
            can: "write".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        assert_eq!(
            delegated.payload.att[0].with,
            "scp:ctx:ctx-specific/messages:write"
        );
    }

    // -----------------------------------------------------------------------
    // key_scope / kid tests (ADR-039)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_without_key_scope_has_no_kid_in_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Header must not have kid.
        assert!(
            token.header.kid.is_none(),
            "kid must be None without key_scope"
        );

        // Facts must not contain scp_key_scope.
        assert!(
            token.payload.fct.is_none(),
            "fct must be None without key_scope and no explicit facts"
        );

        // Serialized JWT header must not contain "kid".
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let header_json = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header_str = String::from_utf8(header_json).unwrap();
        assert!(
            !header_str.contains("kid"),
            "serialized header must not contain kid: {header_str}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_with_key_scope_agent_sets_kid_in_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Header must have kid="#agent".
        assert_eq!(
            token.header.kid,
            Some("#agent".to_owned()),
            "kid must be #agent"
        );

        // Facts must contain scp_key_scope="#agent".
        let fct = token
            .payload
            .fct
            .as_ref()
            .expect("fct must be present with key_scope");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
            "fct.scp_key_scope must be #agent"
        );
    }

    #[tokio::test]
    async fn mint_ucan_with_key_scope_active_sets_kid_in_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#active".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(
            token.header.kid,
            Some("#active".to_owned()),
            "kid must be #active"
        );

        let fct = token
            .payload
            .fct
            .as_ref()
            .expect("fct must be present with key_scope");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#active"),
            "fct.scp_key_scope must be #active"
        );
    }

    #[tokio::test]
    async fn mint_ucan_self_delegation_with_key_scope_succeeds() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned(), "messages:read".to_owned()];

        // Self-delegation: iss == aud, same DID. Per ADR-039 acceptance
        // criterion 8, this is explicitly valid when key_scope is present.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-self",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Verify self-delegation fields.
        assert_eq!(token.payload.iss, issuer_did);
        assert_eq!(token.payload.aud, issuer_did);
        assert_eq!(token.header.kid, Some("#agent".to_owned()));

        let fct = token.payload.fct.as_ref().expect("fct must be present");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
        );

        // Verify JWT structure is valid (3 segments, signature verifies).
        assert_eq!(token.encoded.split('.').count(), 3);
        assert_eq!(token.signature.len(), 64);
    }

    #[tokio::test]
    async fn mint_ucan_kid_appears_in_serialized_jwt_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Decode the header segment from the JWT.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let header_value: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(
            header_value.get("kid").and_then(|v| v.as_str()),
            Some("#agent"),
            "kid must appear in serialized JWT header"
        );
        assert_eq!(
            header_value.get("alg").and_then(|v| v.as_str()),
            Some("EdDSA"),
        );
    }

    #[tokio::test]
    async fn mint_ucan_scp_key_scope_appears_in_deserialized_fct() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Decode the payload segment from the JWT and verify fct.scp_key_scope.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload_value: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

        let fct = payload_value
            .get("fct")
            .expect("fct must be present in serialized payload");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
            "scp_key_scope must appear in deserialized fct"
        );
    }

    #[tokio::test]
    async fn mint_ucan_key_scope_roundtrip_serialize_parse() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Round-trip: serialize the token, then parse header and payload back.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 segments");

        // Parse header.
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let parsed_header: UcanHeader = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(parsed_header.kid, Some("#agent".to_owned()));
        assert_eq!(parsed_header.alg, "EdDSA");
        assert_eq!(parsed_header.typ, "JWT");
        assert_eq!(parsed_header.ucv, "0.10.0");

        // Parse payload.
        let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let parsed_payload: UcanPayload = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(parsed_payload.iss, issuer_did);
        assert_eq!(parsed_payload.aud, "did:dht:z6MkMember");

        let fct = parsed_payload.fct.expect("fct must be present");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
        );
    }

    #[tokio::test]
    async fn mint_ucan_key_scope_merges_with_existing_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"role": "admin", "note": "test"})),
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let fct = token.payload.fct.as_ref().expect("fct must be present");

        // scp_key_scope must be present.
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent"),
        );

        // Original facts must be preserved.
        assert_eq!(fct.get("role").and_then(|v| v.as_str()), Some("admin"),);
        assert_eq!(fct.get("note").and_then(|v| v.as_str()), Some("test"),);
    }

    #[tokio::test]
    async fn mint_ucan_backward_compat_no_key_scope_no_scp_key_scope_fact() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // Explicit facts but no key_scope — scp_key_scope must NOT be added.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"role": "member"})),
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        let fct = token.payload.fct.as_ref().expect("fct must be present");
        assert!(
            fct.get("scp_key_scope").is_none(),
            "scp_key_scope must not appear without key_scope"
        );
        assert_eq!(fct.get("role").and_then(|v| v.as_str()), Some("member"));
    }

    // -----------------------------------------------------------------------
    // Bug fix tests: key_scope validation guards (AB-012 review)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_rejects_conflicting_scp_key_scope_in_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // facts already contains scp_key_scope with a DIFFERENT value than key_scope.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"scp_key_scope": "#wrong"})),
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("conflicts")),
            "conflicting scp_key_scope must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_accepts_matching_scp_key_scope_in_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // facts already contains scp_key_scope with the SAME value — should succeed.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: Some(serde_json::json!({"scp_key_scope": "#agent"})),
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        let fct = token.payload.fct.as_ref().expect("fct must be present");
        assert_eq!(
            fct.get("scp_key_scope").and_then(|v| v.as_str()),
            Some("#agent")
        );
    }

    #[tokio::test]
    async fn mint_ucan_rejects_self_delegation_without_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("self-delegation")),
            "self-delegation without key_scope must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_allows_self_delegation_with_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();
        assert_eq!(token.payload.iss, token.payload.aud);
    }

    #[tokio::test]
    async fn mint_ucan_rejects_key_scope_without_hash_prefix() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("agent".to_owned()),
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("'#'")),
            "key_scope without '#' prefix must be rejected: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_key_scope_without_hash_prefix() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let (custody_b, key_b, audience_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // First mint a valid root token.
        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &issuer_did,
                issuer_key: &key_handle,
                audience_did: &audience_did,
                context_id: "ctx-1",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
                caveats: None,
            },
            &custody,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let err = delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &audience_did,
                delegator_key: &key_b,
                delegatee_did: "did:dht:z6MkSomeone",
                attenuated_capabilities: &root_token.payload.att,
                lifetime_secs: 1800,
                facts: None,
                key_scope: Some("no-hash".to_owned()),
                signing_key_id: None,
                ceiling: None,
                caveats: None,
            },
            &custody_b,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("'#'")),
            "delegate_ucan must reject key_scope without '#' prefix: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_self_delegation_without_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let (custody_b, key_b, did_b) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &issuer_did,
                issuer_key: &key_handle,
                audience_did: &did_b,
                context_id: "ctx-1",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
                caveats: None,
            },
            &custody,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let err = delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &did_b,
                delegator_key: &key_b,
                delegatee_did: &did_b,
                attenuated_capabilities: &root_token.payload.att,
                lifetime_secs: 1800,
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
                caveats: None,
            },
            &custody_b,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("self-delegation")),
            "delegate_ucan must reject self-delegation without key_scope: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_rejects_conflicting_scp_key_scope_in_facts() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let (custody_b, key_b, did_b) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let root_token = mint_ucan(
            &MintParams {
                issuer_did: &issuer_did,
                issuer_key: &key_handle,
                audience_did: &did_b,
                context_id: "ctx-1",
                capabilities: &caps,
                lifetime_secs: 3600,
                not_before: None,
                proofs: vec![],
                facts: None,
                key_scope: None,
                signing_key_id: None,
                ceiling: None,
                caveats: None,
            },
            &custody,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap();

        let err = delegate_ucan(
            &DelegateParams {
                parent_token: &root_token,
                delegator_did: &did_b,
                delegator_key: &key_b,
                delegatee_did: "did:dht:z6MkSomeone",
                attenuated_capabilities: &root_token.payload.att,
                lifetime_secs: 1800,
                facts: Some(serde_json::json!({"scp_key_scope": "#wrong"})),
                key_scope: Some("#agent".to_owned()),
                signing_key_id: None,
                ceiling: None,
                caveats: None,
            },
            &custody_b,
            &scp_primitives::SystemClock,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg) if msg.contains("conflicts")),
            "delegate_ucan must reject conflicting scp_key_scope: {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // signing_key_id — Category A enforcement
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_with_agent_signing_key_id_sets_kid_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: Some(SigningKeyId::Agent),
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Header must have kid="#agent" from signing_key_id.
        assert_eq!(
            token.header.kid,
            Some("#agent".to_owned()),
            "signing_key_id=Agent must set kid=#agent in header"
        );
    }

    #[tokio::test]
    async fn mint_ucan_with_active_signing_key_id_sets_kid_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: Some(SigningKeyId::Active),
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Header must have kid="#active" from signing_key_id.
        assert_eq!(
            token.header.kid,
            Some("#active".to_owned()),
            "signing_key_id=Active must set kid=#active in header"
        );
    }

    #[tokio::test]
    async fn mint_ucan_signing_key_id_takes_precedence_over_key_scope() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        // Self-delegation with key_scope="#active" but signing_key_id=Agent.
        // signing_key_id should win for the kid header, while key_scope still
        // populates scp_key_scope in facts.
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: &issuer_did,
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: Some("#active".to_owned()),
            signing_key_id: Some(SigningKeyId::Agent),
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // kid header comes from signing_key_id, not key_scope.
        assert_eq!(
            token.header.kid,
            Some("#agent".to_owned()),
            "signing_key_id must take precedence over key_scope for kid"
        );

        // scp_key_scope in facts comes from key_scope.
        let fct = token.payload.fct.as_ref().unwrap();
        assert_eq!(
            fct.get("scp_key_scope"),
            Some(&serde_json::Value::String("#active".to_owned())),
            "scp_key_scope must come from key_scope parameter"
        );
    }

    #[tokio::test]
    async fn mint_ucan_without_signing_key_id_has_no_kid_header() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // Without signing_key_id or key_scope, kid must be absent.
        assert_eq!(
            token.header.kid, None,
            "kid must be None when neither signing_key_id nor key_scope is set"
        );
    }

    // -------------------------------------------------------------------
    // Ceiling enforcement — mint (#339)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_rejects_capability_outside_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet_call:assistant".to_owned()];
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats: None,
        };

        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "expected CapabilityOutsideCeiling, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mint_ucan_succeeds_within_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet_call:assistant".to_owned()];
        let ceiling: HashSet<String> = [
            "messages:read".to_owned(),
            "messages:write".to_owned(),
            "outlet_call:assistant".to_owned(),
        ]
        .into_iter()
        .collect();

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats: None,
        };

        assert!(
            mint_ucan(&params, &custody, &scp_primitives::SystemClock)
                .await
                .is_ok(),
            "minting with capabilities within the ceiling must succeed"
        );
    }

    #[tokio::test]
    async fn mint_ucan_no_ceiling_applies_default_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        // These capabilities are within the default ceiling:
        // outlet_call:assistant is covered by OutletCallAll (outlet_call:*),
        // messages:write is exact match.
        let caps = vec![
            "outlet_call:assistant".to_owned(),
            "messages:write".to_owned(),
        ];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-no-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        assert!(
            mint_ucan(&params, &custody, &scp_primitives::SystemClock)
                .await
                .is_ok(),
            "minting with ceiling: None must succeed for capabilities within the default ceiling"
        );
    }

    /// When `ceiling` is `None`, the default ceiling is applied as defense-in-depth.
    /// Capabilities outside the default ceiling must be rejected.
    #[tokio::test]
    async fn mint_ucan_no_ceiling_rejects_capability_outside_default() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        // "custom:exotic" is NOT in the default ceiling (which contains only
        // standard SCP capabilities like messages:*, outlet_call:*, etc.).
        let caps = vec!["custom:exotic".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-default-ceiling",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "ceiling: None must apply default ceiling and reject non-standard capabilities, got: {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // Ceiling enforcement — delegate (#339)
    // -------------------------------------------------------------------

    #[tokio::test]
    async fn delegate_ucan_rejects_capability_outside_ceiling() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        // Root token grants messages:read + outlet_call:assistant.
        let caps = vec![
            "messages:read".to_owned(),
            "outlet_call:assistant".to_owned(),
        ];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Ceiling only allows messages:read — outlet_call:assistant is outside.
        let ceiling: HashSet<String> = std::iter::once("messages:read".to_owned()).collect();

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/outlet_call:assistant".to_owned(),
            can: "assistant".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats: None,
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "expected CapabilityOutsideCeiling, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn delegate_ucan_succeeds_narrowing_within_ceiling() {
        let (alice_custody, alice_key, alice_did) = setup_custody().await;
        let (bob_custody, bob_key, bob_did) = setup_custody().await;

        let caps = vec!["messages:read".to_owned(), "messages:write".to_owned()];
        let root_token = mint_root_token(
            &alice_custody,
            &alice_key,
            &alice_did,
            &bob_did,
            "ctx-1",
            &caps,
        )
        .await;

        // Ceiling allows both capabilities.
        let ceiling: HashSet<String> = ["messages:read".to_owned(), "messages:write".to_owned()]
            .into_iter()
            .collect();

        // Delegate only messages:read — narrowing within ceiling.
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-1/messages:read".to_owned(),
            can: "read".to_owned(),
        }];

        let delegate_params = DelegateParams {
            parent_token: &root_token,
            delegator_did: &bob_did,
            delegator_key: &bob_key,
            delegatee_did: "did:dht:z6MkCarol",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats: None,
        };

        assert!(
            delegate_ucan(&delegate_params, &bob_custody, &scp_primitives::SystemClock)
                .await
                .is_ok(),
            "delegation narrowing within ceiling must succeed"
        );
    }

    // -----------------------------------------------------------------------
    // #1293 — UCAN capability URI resource/action split
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_outlet_call_produces_underscore_resource() {
        // Minting with the colon-format name "outlet:call:*" must produce
        // a UCAN URI with resource "outlet_call", not "outlet".
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet:call:*".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        // The attestation URI must use underscore format.
        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/outlet_call:*",
            "outlet:call:* must produce outlet_call:* in UCAN URI"
        );
        assert_eq!(token.payload.att[0].can, "*");
    }

    #[tokio::test]
    async fn mint_ucan_outlet_call_specific_produces_underscore_resource() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet:call:calculator".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/outlet_call:calculator",
            "outlet:call:calculator must produce outlet_call:calculator in UCAN URI"
        );
        assert_eq!(token.payload.att[0].can, "calculator");
    }

    #[tokio::test]
    async fn mint_ucan_child_context_create_produces_underscore_resource() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["context:child:create".to_owned()];

        // context:child:create is NOT in the default ceiling, so provide an
        // explicit ceiling that includes it for this URI format test.
        let ceiling: HashSet<String> = std::iter::once("context_child:create".to_owned()).collect();

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/context_child:create",
            "context:child:create must produce context_child:create in UCAN URI"
        );
        assert_eq!(token.payload.att[0].can, "create");
    }

    #[tokio::test]
    async fn mint_ucan_simple_cap_unchanged() {
        // Capabilities without multi-segment resources should be unchanged.
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats: None,
        };

        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap();

        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/messages:write",
            "simple capabilities must pass through unchanged"
        );
        assert_eq!(token.payload.att[0].can, "write");
    }

    #[tokio::test]
    async fn mint_ucan_outlet_call_passes_ceiling_check() {
        // A ceiling with UCAN-format entries must accept outlet:call:* capabilities.
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet:call:*".to_owned()];

        let mut ceiling = HashSet::new();
        ceiling.insert("outlet_call:*".to_owned());

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats: None,
        };

        assert!(
            mint_ucan(&params, &custody, &scp_primitives::SystemClock)
                .await
                .is_ok(),
            "outlet:call:* must pass ceiling check with outlet_call:* in ceiling"
        );
    }

    #[tokio::test]
    async fn mint_ucan_outlet_call_rejected_when_not_in_ceiling() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet:call:*".to_owned()];

        let mut ceiling = HashSet::new();
        ceiling.insert("messages:write".to_owned());

        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-1293",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats: None,
        };

        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "outlet:call:* must be rejected when not in ceiling: {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // A+A caveat re-materialization: mint-side fold + mint-side reject matrix
    // -------------------------------------------------------------------

    use scp_protocol::context::outlets::OutletKind;
    use scp_protocol::economy::types::Amount;
    use scp_protocol::trust::caveats::{DaysOfWeekMask, HoursOfDayMask};
    use scp_protocol::trust::caveats::{InvocationCaveats, RateWindow};

    const OUTLET_CAP_URI: &str = "scp:ctx:ctx-caveat/outlet_call:assistant";

    /// Mints a root token (Action grant) carrying the given caveats, audienced
    /// to `aud`. Capabilities use the `outlet_call:assistant` stem so the
    /// default ceiling admits it.
    async fn mint_root_with_caveats(
        custody: &InMemoryKeyCustody,
        issuer_key: &KeyHandle,
        issuer_did: &str,
        aud: &str,
        caveats: Option<InvocationCaveats>,
    ) -> UcanToken {
        let caps = vec!["outlet_call:assistant".to_owned()];
        let params = MintParams {
            issuer_did,
            issuer_key,
            audience_did: aud,
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats,
        };
        mint_ucan(&params, custody, &scp_primitives::SystemClock)
            .await
            .unwrap()
    }

    /// Delegates `parent` to `delegatee_did` with the given child caveats,
    /// returning the `delegate_ucan` result (Ok or Err) for assertion.
    async fn try_delegate_with_caveats(
        parent: &UcanToken,
        delegator_custody: &InMemoryKeyCustody,
        delegator_key: &KeyHandle,
        delegator_did: &str,
        delegatee_did: &str,
        caveats: Option<InvocationCaveats>,
    ) -> Result<UcanToken, UcanError> {
        let attenuated = vec![Attenuation {
            with: OUTLET_CAP_URI.to_owned(),
            can: "*".to_owned(),
        }];
        let params = DelegateParams {
            parent_token: parent,
            delegator_did,
            delegator_key,
            delegatee_did,
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: None,
            caveats,
        };
        delegate_ucan(&params, delegator_custody, &scp_primitives::SystemClock).await
    }

    /// MINT-SIDE FOLD: a child that omits a field the parent bound INHERITS
    /// the parent's value (the child `nb` is the COMPLETE self-contained
    /// effective set, not a partial). Confirms the re-materialization.
    #[tokio::test]
    async fn delegate_fold_inherits_omitted_parent_fields() {
        let (root_custody, root_key, root_did) = setup_custody().await;
        let (mid_custody, mid_key, mid_did) = setup_custody().await;

        let root_caveats = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(500)),
            amount_max_cumulative: Some(Amount::new(5000)),
            max_calls: Some(100),
            origin_kind: Some(OutletKind::Action),
            ..InvocationCaveats::empty()
        };
        let root = mint_root_with_caveats(
            &root_custody,
            &root_key,
            &root_did,
            &mid_did,
            Some(root_caveats),
        )
        .await;

        // Child tightens ONLY max_calls; omits the two amount fields and
        // origin_kind. The fold must inherit amount_* from the parent and
        // materialize origin_kind = Action.
        let child = try_delegate_with_caveats(
            &root,
            &mid_custody,
            &mid_key,
            &mid_did,
            "did:dht:z6MkLeaf",
            Some(InvocationCaveats {
                max_calls: Some(10),
                ..InvocationCaveats::empty()
            }),
        )
        .await
        .expect("honest narrowing must mint");

        let nb = child.payload.nb.expect("child carries complete nb");
        assert_eq!(nb.max_calls, Some(10), "tightened field");
        assert_eq!(
            nb.amount_max_per_call,
            Some(Amount::new(500)),
            "omitted field inherited from parent"
        );
        assert_eq!(
            nb.amount_max_cumulative,
            Some(Amount::new(5000)),
            "omitted field inherited from parent"
        );
        assert_eq!(
            nb.origin_kind,
            Some(OutletKind::Action),
            "origin_kind materialized explicitly"
        );
    }

    /// MINT-SIDE FOLD: a caller supplying `None` caveats inherits the
    /// parent's COMPLETE effective set verbatim.
    #[tokio::test]
    async fn delegate_fold_none_inherits_parent_verbatim() {
        let (root_custody, root_key, root_did) = setup_custody().await;
        let (mid_custody, mid_key, mid_did) = setup_custody().await;

        let root_caveats = InvocationCaveats {
            amount_max_per_call: Some(Amount::new(500)),
            max_calls: Some(100),
            origin_kind: Some(OutletKind::Action),
            ..InvocationCaveats::empty()
        };
        let root = mint_root_with_caveats(
            &root_custody,
            &root_key,
            &root_did,
            &mid_did,
            Some(root_caveats.clone()),
        )
        .await;

        let child = try_delegate_with_caveats(
            &root,
            &mid_custody,
            &mid_key,
            &mid_did,
            "did:dht:z6MkLeaf",
            None,
        )
        .await
        .expect("None caveats inherit parent verbatim");

        assert_eq!(
            child.payload.nb,
            Some(root_caveats),
            "None caveats produce the parent's complete set verbatim"
        );
    }

    /// MINT-SIDE FOLD: a root with `origin_kind` = None (permitted) — the
    /// first delegation materializes `origin_kind` inferred from the outlet
    /// stem.
    #[tokio::test]
    async fn delegate_fold_materializes_origin_kind_from_root_none() {
        let (root_custody, root_key, root_did) = setup_custody().await;
        let (mid_custody, mid_key, mid_did) = setup_custody().await;

        // Root carries caveats but NO origin_kind (allowed: single-kind stem
        // set means inference is unambiguous).
        let root_caveats = InvocationCaveats {
            max_calls: Some(100),
            ..InvocationCaveats::empty()
        };
        let root = mint_root_with_caveats(
            &root_custody,
            &root_key,
            &root_did,
            &mid_did,
            Some(root_caveats),
        )
        .await;
        assert_eq!(root.payload.nb.as_ref().unwrap().origin_kind, None);

        let child = try_delegate_with_caveats(
            &root,
            &mid_custody,
            &mid_key,
            &mid_did,
            "did:dht:z6MkLeaf",
            Some(InvocationCaveats {
                max_calls: Some(10),
                ..InvocationCaveats::empty()
            }),
        )
        .await
        .expect("first delegation materializes inferred origin_kind");

        assert_eq!(
            child.payload.nb.unwrap().origin_kind,
            Some(OutletKind::Action),
            "origin_kind inferred from outlet_call stem on first delegation"
        );
    }

    /// Widening matrix data: each tuple is `(label, minimal root caveat with
    /// the single bound under test, child override that WIDENS that field
    /// beyond the parent)`. Extracted from the test body so the test stays
    /// within the `too_many_lines` cap. This builder is itself a flat data
    /// table (one entry per §7.3.8 caveat field) with no decomposable logic,
    /// so the line-count lint does not apply.
    #[allow(clippy::too_many_lines)]
    fn widening_reject_cases() -> Vec<(&'static str, InvocationCaveats, InvocationCaveats)> {
        let action = || InvocationCaveats {
            origin_kind: Some(OutletKind::Action),
            ..InvocationCaveats::empty()
        };
        vec![
            (
                "amount_max_per_call",
                InvocationCaveats {
                    amount_max_per_call: Some(Amount::new(100)),
                    ..action()
                },
                InvocationCaveats {
                    amount_max_per_call: Some(Amount::new(1_000)),
                    ..action()
                },
            ),
            (
                "amount_max_cumulative",
                InvocationCaveats {
                    amount_max_cumulative: Some(Amount::new(1_000)),
                    ..action()
                },
                InvocationCaveats {
                    amount_max_cumulative: Some(Amount::new(100_000)),
                    ..action()
                },
            ),
            (
                "max_calls",
                InvocationCaveats {
                    max_calls: Some(10),
                    ..action()
                },
                InvocationCaveats {
                    max_calls: Some(1_000),
                    ..action()
                },
            ),
            (
                "valid_from_earlier",
                InvocationCaveats {
                    valid_from: Some(1_000),
                    ..action()
                },
                InvocationCaveats {
                    valid_from: Some(0),
                    ..action()
                },
            ),
            (
                "valid_until_later",
                InvocationCaveats {
                    valid_until: Some(10_000),
                    ..action()
                },
                InvocationCaveats {
                    valid_until: Some(1_000_000),
                    ..action()
                },
            ),
            (
                "hours_of_day_superset",
                InvocationCaveats {
                    hours_of_day: Some(HoursOfDayMask::from_bits(0b0000_1100).unwrap()),
                    ..action()
                },
                InvocationCaveats {
                    hours_of_day: Some(HoursOfDayMask::from_bits(0b0011_1100).unwrap()),
                    ..action()
                },
            ),
            (
                "days_of_week_superset",
                InvocationCaveats {
                    days_of_week: Some(DaysOfWeekMask::from_bits(0b0001_1110).unwrap()),
                    ..action()
                },
                InvocationCaveats {
                    days_of_week: Some(DaysOfWeekMask::from_bits(0b0111_1111).unwrap()),
                    ..action()
                },
            ),
            (
                "rate_window_max",
                InvocationCaveats {
                    rate_window: Some(RateWindow {
                        max: 5,
                        window_secs: 60,
                    }),
                    ..action()
                },
                InvocationCaveats {
                    rate_window: Some(RateWindow {
                        max: 50,
                        window_secs: 60,
                    }),
                    ..action()
                },
            ),
            (
                "rate_window_secs",
                InvocationCaveats {
                    rate_window: Some(RateWindow {
                        max: 5,
                        window_secs: 60,
                    }),
                    ..action()
                },
                InvocationCaveats {
                    rate_window: Some(RateWindow {
                        max: 5,
                        window_secs: 600,
                    }),
                    ..action()
                },
            ),
            (
                "allowed_adapters_superset",
                InvocationCaveats {
                    allowed_adapters: Some(vec!["stripe".to_owned()]),
                    ..action()
                },
                InvocationCaveats {
                    allowed_adapters: Some(vec!["stripe".to_owned(), "paypal".to_owned()]),
                    ..action()
                },
            ),
            (
                "allowed_target_dids_superset",
                InvocationCaveats {
                    allowed_target_dids: Some(vec![scp_primitives::DID("did:dht:zA".to_owned())]),
                    ..action()
                },
                InvocationCaveats {
                    allowed_target_dids: Some(vec![
                        scp_primitives::DID("did:dht:zA".to_owned()),
                        scp_primitives::DID("did:dht:zB".to_owned()),
                    ]),
                    ..action()
                },
            ),
            (
                "input_schema_maximum",
                InvocationCaveats {
                    input_schema: Some(serde_json::json!({ "maximum": 10.0 })),
                    ..action()
                },
                InvocationCaveats {
                    input_schema: Some(serde_json::json!({ "maximum": 1000.0 })),
                    ..action()
                },
            ),
            (
                "origin_kind_mismatch",
                InvocationCaveats {
                    max_calls: Some(10),
                    ..action()
                },
                // Child flips origin_kind to Query — disagrees with the
                // parent's Action (and with the outlet_call stem family).
                InvocationCaveats {
                    max_calls: Some(5),
                    origin_kind: Some(OutletKind::Query),
                    ..InvocationCaveats::empty()
                },
            ),
        ]
    }

    /// MINT-SIDE REJECT MATRIX: a child that WIDENS any field beyond the
    /// parent is rejected at MINT (`delegate_ucan` returns Err). One case per
    /// caveat field family. Each case uses a minimal root carrying ONLY the
    /// field under test (plus `origin_kind`) so we stay within the §7.3.8
    /// `MAX_POPULATED_CAVEATS` = 8 mint-limit while still exercising every
    /// narrowing direction independently.
    #[tokio::test]
    async fn delegate_rejects_widening_at_mint_matrix() {
        let (root_custody, root_key, root_did) = setup_custody().await;
        let (mid_custody, mid_key, mid_did) = setup_custody().await;

        for (label, root_caveats, widening) in widening_reject_cases() {
            let root = mint_root_with_caveats(
                &root_custody,
                &root_key,
                &root_did,
                &mid_did,
                Some(root_caveats),
            )
            .await;
            let result = try_delegate_with_caveats(
                &root,
                &mid_custody,
                &mid_key,
                &mid_did,
                "did:dht:z6MkLeaf",
                Some(widening),
            )
            .await;
            assert!(
                matches!(result, Err(UcanError::AttenuationViolation(_))),
                "widening '{label}' must be rejected at mint, got: {result:?}"
            );
        }
    }

    /// MINT-SIDE REJECT: a mixed-stem ROOT (`outlet_query` AND `outlet_call`)
    /// has no unambiguous `origin_kind` and is rejected UNCONDITIONALLY at the
    /// ROOT mint (§7.3.8:868) — even with `caveats = None`. The mint is the
    /// single point where root-signer intent is verified, so the mixed-stem
    /// set never produces a signed root that a later delegation could fold over.
    /// (Previously the mixed-stem root with `caveats = None` minted
    /// successfully and the ambiguity was only caught at the delegation fold;
    /// the guard now fires at the root mint, which is strictly stronger.)
    #[tokio::test]
    async fn delegate_rejects_mixed_stem_origin_kind_at_mint() {
        let (root_custody, root_key, root_did) = setup_custody().await;
        let (_mid_custody, _mid_key, mid_did) = setup_custody().await;

        // Root grants both stems (unconstrained, no caveats).
        let caps = vec![
            "outlet_query:search".to_owned(),
            "outlet_call:assistant".to_owned(),
        ];
        let root_params = MintParams {
            issuer_did: &root_did,
            issuer_key: &root_key,
            audience_did: &mid_did,
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(
                [
                    "outlet_query:search".to_owned(),
                    "outlet_call:assistant".to_owned(),
                ]
                .into_iter()
                .collect(),
            ),
            caveats: None,
        };
        // The mixed-stem root mint itself rejects — there is no signed root to
        // delegate from.
        let err = mint_ucan(&root_params, &root_custody, &scp_primitives::SystemClock)
            .await
            .expect_err("mixed-stem root must reject unconditionally at the root mint");
        match err {
            UcanError::MalformedToken(msg) => {
                assert!(
                    msg.contains("origin-kind-mixed-stem-root"),
                    "expected origin-kind-mixed-stem-root slug, got: {msg}"
                );
            }
            other => panic!("expected MalformedToken(origin-kind-mixed-stem-root), got {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // §7.3.8 outlet-scoping: invocation caveats are OUTLET-scoped. A
    // non-outlet delegation off an outlet-caveat root must NOT inherit the
    // outlet caveats and must mint with child nb = None.
    // -------------------------------------------------------------------

    /// Mints a root carrying BOTH an outlet capability and a non-outlet
    /// capability (`messages:write`) plus invocation caveats. The caveat
    /// fields are outlet-scoped, so a later delegation of ONLY the non-outlet
    /// capability must drop them.
    async fn mint_mixed_cap_root_with_caveats(
        custody: &InMemoryKeyCustody,
        issuer_key: &KeyHandle,
        issuer_did: &str,
        aud: &str,
        caveats: Option<InvocationCaveats>,
    ) -> UcanToken {
        let caps = vec![
            "outlet_call:assistant".to_owned(),
            "messages:write".to_owned(),
        ];
        let ceiling: HashSet<String> = [
            "outlet_call:assistant".to_owned(),
            "messages:write".to_owned(),
        ]
        .into_iter()
        .collect();
        let params = MintParams {
            issuer_did,
            issuer_key,
            audience_did: aud,
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(ceiling),
            caveats,
        };
        mint_ucan(&params, custody, &scp_primitives::SystemClock)
            .await
            .unwrap()
    }

    /// HIGH (a): mixed-cap root `[outlet_call:assistant, messages:write]` with
    /// outlet-scoped caveats. Delegating ONLY the non-outlet `messages:write`
    /// (legit subset) with `caveats = None` must PASS and produce a child with
    /// `nb = None` — the outlet-scoped caveats do not apply to a non-outlet
    /// capability and MUST NOT be folded in (which would otherwise reject the
    /// honest delegation on `OriginKindUnspecified`).
    #[tokio::test]
    async fn delegate_non_outlet_subset_off_outlet_caveat_root_drops_caveats() {
        let (root_custody, root_key, root_did) = setup_custody().await;
        let (mid_custody, mid_key, mid_did) = setup_custody().await;

        let root_caveats = InvocationCaveats {
            max_calls: Some(50),
            origin_kind: Some(OutletKind::Action),
            ..InvocationCaveats::empty()
        };
        let root = mint_mixed_cap_root_with_caveats(
            &root_custody,
            &root_key,
            &root_did,
            &mid_did,
            Some(root_caveats),
        )
        .await;
        assert!(
            root.payload.nb.is_some(),
            "root carries outlet stem so its caveats are retained"
        );

        // Delegate ONLY messages:write (non-outlet).
        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-caveat/messages:write".to_owned(),
            can: "write".to_owned(),
        }];
        let params = DelegateParams {
            parent_token: &root,
            delegator_did: &mid_did,
            delegator_key: &mid_key,
            delegatee_did: "did:dht:z6MkLeaf",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(std::iter::once("messages:write".to_owned()).collect()),
            caveats: None,
        };
        let child = delegate_ucan(&params, &mid_custody, &scp_primitives::SystemClock)
            .await
            .expect("honest non-outlet subset delegation must mint");
        assert_eq!(
            child.payload.nb, None,
            "non-outlet child carries no invocation caveats (nb = None)"
        );
    }

    /// HIGH (b): the SAME mixed-cap outlet-caveat root, delegating the OUTLET
    /// capability `outlet_call:assistant`, still narrows and materializes
    /// `origin_kind` (rule-4 holds for outlet edges). The child nb is present
    /// and carries the inherited outlet-scoped bounds.
    #[tokio::test]
    async fn delegate_outlet_cap_off_outlet_caveat_root_still_narrows() {
        let (root_custody, root_key, root_did) = setup_custody().await;
        let (mid_custody, mid_key, mid_did) = setup_custody().await;

        let root_caveats = InvocationCaveats {
            max_calls: Some(50),
            origin_kind: Some(OutletKind::Action),
            ..InvocationCaveats::empty()
        };
        let root = mint_mixed_cap_root_with_caveats(
            &root_custody,
            &root_key,
            &root_did,
            &mid_did,
            Some(root_caveats),
        )
        .await;

        let attenuated = vec![Attenuation {
            with: "scp:ctx:ctx-caveat/outlet_call:assistant".to_owned(),
            can: "*".to_owned(),
        }];
        let params = DelegateParams {
            parent_token: &root,
            delegator_did: &mid_did,
            delegator_key: &mid_key,
            delegatee_did: "did:dht:z6MkLeaf",
            attenuated_capabilities: &attenuated,
            lifetime_secs: 1800,
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(std::iter::once("outlet_call:assistant".to_owned()).collect()),
            caveats: None,
        };
        let child = delegate_ucan(&params, &mid_custody, &scp_primitives::SystemClock)
            .await
            .expect("outlet-cap delegation must mint");
        let nb = child
            .payload
            .nb
            .expect("outlet edge child carries complete nb");
        assert_eq!(nb.max_calls, Some(50), "outlet caveat inherited");
        assert_eq!(
            nb.origin_kind,
            Some(OutletKind::Action),
            "origin_kind materialized on outlet edge"
        );
    }

    /// MEDIUM: a root minted with ONLY non-outlet caps + caveats produces
    /// `nb = None` (outlet-scoping: there is no outlet stem to which the
    /// invocation caveats could apply). This is the chosen behavior consistent
    /// with the HIGH fix.
    #[tokio::test]
    async fn mint_non_outlet_root_with_caveats_drops_to_none() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(std::iter::once("messages:write".to_owned()).collect()),
            caveats: Some(InvocationCaveats {
                max_calls: Some(50),
                ..InvocationCaveats::empty()
            }),
        };
        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .expect("non-outlet root with caveats mints with nb = None");
        assert_eq!(
            token.payload.nb, None,
            "non-outlet root carries no invocation caveats"
        );
    }

    /// MEDIUM: a root minted with an outlet stem and an explicit `origin_kind`
    /// that CONTRADICTS the stem family is now REJECTED at mint via
    /// `try_new_for_root` (previously unwired — the plain `try_new` path never
    /// ran the stem/kind agreement check).
    #[tokio::test]
    async fn mint_outlet_root_with_contradicting_origin_kind_rejected() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet_call:assistant".to_owned()];
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(std::iter::once("outlet_call:assistant".to_owned()).collect()),
            // origin_kind = Query contradicts the outlet_call (Action) stem.
            caveats: Some(InvocationCaveats {
                max_calls: Some(50),
                origin_kind: Some(OutletKind::Query),
                ..InvocationCaveats::empty()
            }),
        };
        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(_)),
            "root origin_kind contradicting its outlet stem must reject at mint: {err:?}"
        );
    }

    // -------------------------------------------------------------------
    // MEDIUM-1: mixed-family root rejection must be UNCONDITIONAL at mint
    // (§7.3.8:868). The mint is the single point where root-signer intent is
    // verified; a root whose capability stems span BOTH outlet families has an
    // ambiguous origin_kind and is rejected REGARDLESS of whether caveats were
    // supplied. The prior short-circuit (`None => Ok(None)` /
    // `Some(_) if !root_has_outlet_stem => Ok(None)`) let a mixed-family root
    // with `caveats = None` mint successfully.
    // -------------------------------------------------------------------

    /// Builds `MintParams` for a root carrying both outlet families
    /// (`outlet_query:price`, `outlet_call:assistant`).
    fn mixed_family_root_caps() -> Vec<String> {
        vec![
            "outlet_query:price".to_owned(),
            "outlet_call:assistant".to_owned(),
        ]
    }

    /// Ceiling matching [`mixed_family_root_caps`].
    fn mixed_family_root_ceiling() -> HashSet<String> {
        [
            "outlet_query:price".to_owned(),
            "outlet_call:assistant".to_owned(),
        ]
        .into_iter()
        .collect()
    }

    /// MEDIUM-1 (a): a mixed-family root with `caveats = None` must REJECT at
    /// mint (`SCP-TOOL-6114` / `origin-kind-mixed-stem-root`). This is the hole
    /// the fix closes: previously the `None` arm short-circuited to `Ok(None)`
    /// before the mixed-family check ever ran.
    #[tokio::test]
    async fn mint_mixed_family_root_with_no_caveats_rejects() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = mixed_family_root_caps();
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(mixed_family_root_ceiling()),
            caveats: None,
        };
        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .expect_err("mixed-family root with caveats=None must reject unconditionally at mint");
        match err {
            UcanError::MalformedToken(msg) => {
                assert!(
                    msg.contains("origin-kind-mixed-stem-root"),
                    "expected origin-kind-mixed-stem-root slug, got: {msg}"
                );
            }
            other => panic!("expected MalformedToken(origin-kind-mixed-stem-root), got {other:?}"),
        }
    }

    /// MEDIUM-1 (b): the SAME mixed-family root with `caveats = Some(_)` also
    /// rejects (it always did via `try_new_for_root`). Pins that the fix did
    /// not regress the already-covered path.
    #[tokio::test]
    async fn mint_mixed_family_root_with_caveats_rejects() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = mixed_family_root_caps();
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(mixed_family_root_ceiling()),
            caveats: Some(InvocationCaveats {
                max_calls: Some(10),
                ..InvocationCaveats::empty()
            }),
        };
        let err = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .expect_err("mixed-family root with caveats=Some must reject at mint");
        match err {
            UcanError::MalformedToken(msg) => {
                assert!(
                    msg.contains("origin-kind-mixed-stem-root"),
                    "expected origin-kind-mixed-stem-root slug, got: {msg}"
                );
            }
            other => panic!("expected MalformedToken(origin-kind-mixed-stem-root), got {other:?}"),
        }
    }

    /// MEDIUM-1 (c): a SINGLE-family outlet root with `caveats = None` still
    /// mints successfully and carries `nb = None`. The mixed-family gate runs
    /// (over `empty()`) but passes for a single-family set, so the legitimate
    /// no-caveat outlet root is not over-rejected.
    #[tokio::test]
    async fn mint_single_family_outlet_root_with_no_caveats_is_nb_none() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["outlet_call:assistant".to_owned()];
        let params = MintParams {
            issuer_did: &issuer_did,
            issuer_key: &key_handle,
            audience_did: "did:dht:z6MkMember",
            context_id: "ctx-caveat",
            capabilities: &caps,
            lifetime_secs: 3600,
            not_before: None,
            proofs: vec![],
            facts: None,
            key_scope: None,
            signing_key_id: None,
            ceiling: Some(std::iter::once("outlet_call:assistant".to_owned()).collect()),
            caveats: None,
        };
        let token = mint_ucan(&params, &custody, &scp_primitives::SystemClock)
            .await
            .expect("single-family outlet root with caveats=None must mint");
        assert_eq!(
            token.payload.nb, None,
            "single-family outlet root with no caveats carries nb = None"
        );
    }
}
