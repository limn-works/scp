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

use scp_clock::Clock;
use scp_platform::traits::{KeyCustody, KeyHandle};

use std::collections::HashSet;

use scp_did::SigningKeyId;
use scp_protocol::crypto::ucan::capability::{CapabilityUri, verify_ceiling_compliance};
use scp_protocol::crypto::ucan::nonce::generate_nonce;
use scp_protocol::crypto::ucan::{Attenuation, UcanError, UcanHeader, UcanPayload, UcanToken};

/// Maximum token lifetime: 24 hours in seconds (spec section 9.5).
const MAX_EXPIRY_SECS: u64 = 24 * 60 * 60;

/// Decodes `key_scope` into the verification method it names.
///
/// Step 5b of the validation pipeline compares `fct.scp_key_scope` against the
/// `kid` header, and `UcanHeader.kid` is a [`scp_did::SigningKeyId`], so a scope
/// naming anything outside `#active` and `#agent` matches no header any minter
/// can produce. This rejects such a scope here rather than returning a signed
/// token every verifier refuses.
///
/// An earlier version admitted any string starting with `#`, so
/// `key_scope: Some("#0")` minted a token whose header named `#active` — from
/// the default a missing `kid` carries — and whose facts named `#0`. That token
/// reported success at mint time and failed at every verifier.
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] when `key_scope` names no operational
/// verification method.
fn decode_key_scope(
    key_scope: Option<&String>,
) -> Result<Option<scp_did::SigningKeyId>, UcanError> {
    key_scope.map_or(Ok(None), |scope| {
        scp_did::SigningKeyId::from_fragment(scope)
            .map(Some)
            .ok_or_else(|| {
                UcanError::MalformedToken(format!(
                    "key_scope must name an operational verification method \
                     (\"#active\" or \"#agent\"), got: {scope}"
                ))
            })
    })
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

/// Infers the [`OutletKind`](scp_protocol::context::outlets::OutletKind) of a delegation from the stem family of its
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
/// - `outlet_query:*` / `outlet_query:{id}` ⇒ [`OutletKind::Query`](scp_protocol::context::outlets::OutletKind::Query).
/// - `outlet_call:*` / `outlet_call:{id}` ⇒ [`OutletKind::Action`](scp_protocol::context::outlets::OutletKind::Action).
/// - Non-outlet stems contribute nothing (returns `None` when no outlet
///   stems are present — there is no outlet kind to materialize).
///
/// # Errors
///
/// Returns [`UcanError::AttenuationViolation`] when the delegated set is
/// mixed-kind (carries BOTH `outlet_query:*` and `outlet_call:*` stems):
/// such a set has no single unambiguous `origin_kind` and is rejected at
/// mint, matching
/// [`scp_protocol::trust::caveats::CaveatMintError::OriginKindMixedStemRoot`].
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

/// Builds the delegated child's `nb` (invocation caveats) — the §7.3.8
/// rule-4 `origin_kind` materialization half of the canonical model.
///
/// SCOPE (PR-3): this port materializes ONLY the `origin_kind` field plus the
/// per-field narrow against whatever `nb` the parent carries. The value-caveat
/// fields (`max_calls` / `amount_max_*` / `rate_window` / adapter / target /
/// schema / time-box) and their delegation-param plumbing + runtime counter
/// enforcement are a DEFERRED slice — `DelegateParams` carries no caveat
/// params, so there is nothing to overlay. When a parent ever carries a real
/// caveat field, the narrow below still faithfully inherits it (the child is
/// built from `parent_effective`), so this stays correct if a parent gains
/// caveats in a later slice.
///
/// Construction:
///
/// - **Non-outlet child** — invocation caveats are outlet-scoped (§7.3.8), so a
///   delegated set with NO outlet stem carries no `nb`. Returns `None` (the
///   validator's per-edge outlet gate treats such a child symmetrically).
/// - **Outlet child** — the child inherits the parent's effective caveat set
///   verbatim and materializes an explicit `origin_kind`: inherited from the
///   parent when present, otherwise inferred from the delegated capability
///   stems (the first delegation off an unconstrained single-family root pins
///   the kind). The materialized child is then run through
///   [`InvocationCaveats::try_new`](scp_protocol::trust::caveats::InvocationCaveats::try_new) (mint limits) and narrowed against the
///   parent (`parent.narrow(child)` — rejects widening / field removal /
///   `origin_kind` change; `empty().narrow(child)` when the parent is a
///   caveat-free root, which still enforces rule-4's explicit-`origin_kind`
///   requirement).
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] when the materialized child fails
/// [`scp_protocol::trust::caveats::InvocationCaveats::try_new`]. Returns
/// [`UcanError::AttenuationViolation`] when the parent rejects the child via
/// [`scp_protocol::trust::caveats::InvocationCaveats::narrow`], or when
/// `origin_kind` inference fails (mixed-stem set / unparseable URI).
fn build_delegated_caveats(
    params: &DelegateParams<'_>,
) -> Result<Option<scp_protocol::trust::caveats::InvocationCaveats>, UcanError> {
    use scp_protocol::trust::caveats::InvocationCaveats;

    let parent_nb = params.parent_token.payload.nb.as_ref();

    // §7.3.8 outlet-scoping: invocation caveats bind outlet *invocation* and are
    // meaningless on a non-outlet capability. A delegated set with NO outlet
    // stem carries NO `nb`. Do not fold an ancestor's outlet-scoped caveats onto
    // a legitimately-narrowed non-outlet child. Uses the SHARED stem classifier
    // so mint and validator never diverge (symmetric mirror of
    // `verify_edge_attenuation`'s outlet-edge gate). Fail-closed on unparseable.
    let child_is_outlet_edge = scp_protocol::crypto::ucan::capability::att_set_has_outlet_stem(
        params.attenuated_capabilities,
    )
    .map_err(|e| {
        UcanError::AttenuationViolation(format!("outlet-scope classification failed: {e}"))
    })?;
    if !child_is_outlet_edge {
        return Ok(None);
    }

    // The parent's effective set: a root with no nb contributes no field bounds
    // (empty). A non-root parent (or a root minted WITH caveats in a future
    // slice) already carries its complete validated set.
    let parent_effective = parent_nb.map_or_else(InvocationCaveats::empty, Clone::clone);

    // Infer the origin_kind implied by the delegated capability stems. Errors on
    // a mixed-stem set (ambiguous kind).
    let inferred_origin_kind = infer_origin_kind_from_capabilities(params.attenuated_capabilities)?;

    // Materialize an explicit origin_kind: inherit the parent's value when
    // present; otherwise — the parent is a root with origin_kind = None
    // (permitted by §7.3.8 rule 3) — use the inferred stem kind. This is the
    // point at which the chain's origin_kind becomes a signed, explicit,
    // equality-checked value for every hop below the root (rule 4).
    let inherited_origin_kind = parent_effective.origin_kind.or(inferred_origin_kind);

    // The child's effective set is the parent's effective set (no caller-
    // supplied caveat overlay in PR-3) with the materialized origin_kind. This
    // guarantees an outlet child is never silently `origin_kind = None`.
    let materialized = InvocationCaveats {
        origin_kind: inherited_origin_kind,
        ..parent_effective
    };

    // Final gates: mint limits, then per-field attenuation against the parent.
    // narrow() rejects any widening / field removal / origin_kind change and
    // rejects a still-absent origin_kind (OriginKindUnspecified).
    let validated = InvocationCaveats::try_new(materialized)
        .map_err(|e| UcanError::MalformedToken(format!("caveat-mint-limit-exceeded: {e}")))?;
    if let Some(parent_caveats) = parent_nb {
        parent_caveats.narrow(&validated).map_err(|e| {
            UcanError::AttenuationViolation(format!("caveat narrow violation: {e}"))
        })?;
    } else {
        // Root parent (no nb): no parent bound to narrow against, but a non-root
        // child still MUST carry an explicit origin_kind. narrow() against an
        // empty parent enforces exactly this (OriginKindUnspecified when
        // child.origin_kind is None) without imposing any field bound the root
        // never had.
        InvocationCaveats::empty().narrow(&validated).map_err(|e| {
            UcanError::AttenuationViolation(format!("caveat narrow violation: {e}"))
        })?;
    }
    Ok(Some(validated))
}

/// Builds the ROOT token's `nb` (invocation caveats) per §7.3.8 outlet-scoping
/// and the root stem/`origin_kind` agreement gate.
///
/// SCOPE (PR-3): no caveat params exist on `MintParams`, so this never emits a
/// populated caveat set — it exists to run the UNCONDITIONAL root stem/kind
/// agreement gate ([`InvocationCaveats::try_new_for_root`](scp_protocol::trust::caveats::InvocationCaveats::try_new_for_root)) so a mixed-family
/// outlet root can never be signed, then returns `None` (a single-family outlet
/// root legitimately carries `nb = None`; the first delegation materializes the
/// kind). Value-caveat routing on the root is a DEFERRED slice.
///
/// # Errors
///
/// Returns [`UcanError::MalformedToken`] when `try_new_for_root` rejects the
/// stem set (mixed-family outlet root).
fn build_root_caveats(
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

    // Non-outlet root: invocation caveats are outlet-scoped (§7.3.8), and there
    // is no stem family to mix, so the gate does not apply.
    if !root_has_outlet_stem {
        return Ok(None);
    }

    // Outlet root: ALWAYS run the root stem/kind agreement gate. try_new_for_root
    // performs the UNCONDITIONAL mixed-family rejection (§7.3.8) plus the mint-
    // limit check over `empty()`. A single-family root then carries `nb = None`
    // (the validated `empty()` is not a real caveat set — it existed only to run
    // the mixed-family gate).
    InvocationCaveats::try_new_for_root(InvocationCaveats::empty(), parsed_stems)
        .map_err(|e| UcanError::MalformedToken(format!("caveat-mint-limit-exceeded: {e}")))?;
    Ok(None)
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
    let key_scope_id = decode_key_scope(params.key_scope.as_ref())?;
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
    let parsed_stems: Vec<scp_protocol::context::roles::Capability> = params
        .capabilities
        .iter()
        .map(|cap| {
            // `Capability::new` returns `None` for names that fail the strict
            // §5.4.2.1 parser (e.g. hard-rejected `outlet:invoke:*` /
            // `outlet_call:foo`, or malformed outlet stems). Reject rather than
            // silently degrade — SCP-OUT-014 parser-differential guard.
            scp_protocol::context::roles::Capability::new(cap).ok_or_else(|| {
                UcanError::MalformedToken(format!(
                    "invalid capability name {cap:?} (fails §5.4.2.1 parser)"
                ))
            })
        })
        .collect::<Result<Vec<_>, UcanError>>()?;

    let parsed_caps: Vec<(String, String)> = parsed_stems
        .iter()
        .map(|capability| {
            let (resource, action) = capability.ucan_resource_action();
            (resource.into_owned(), action.into_owned())
        })
        .collect();

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

    // `signing_key_id` names the method that signs and reaches the `kid`
    // header; `key_scope` names the method a self-delegation binds to and
    // reaches `fct.scp_key_scope`. `signing_key_id` wins for the header when a
    // caller sets both.
    //
    // OPEN QUESTION — a caller setting both to DIFFERENT methods gets a token
    // no verifier accepts, and two artifacts disagree about which side is
    // wrong. `validate_key_scope` step 5b requires `kid` to EQUAL
    // `fct.scp_key_scope`, and §9.7.4 of the security-model spec agrees: "The
    // agent signs these scoped UCANs with its `#agent` key." But
    // `crates/scp-runtime/tests/agent_binding_integration.rs` mints
    // `{signing_key_id: Active, key_scope: "#agent"}` and asserts "JWT header
    // kid must be #active (the signing key)" — a delegation FROM `#active` TO
    // `#agent`, which is how §9.7.4's own sentence opens. Under step 5b that
    // token verifies nowhere.
    //
    // Rejecting the pair here would pick one reading, so this does not. A human
    // settles whether step 5b compares a signer against a grantee or against
    // itself, and the losing side changes.
    let header = params
        .signing_key_id
        .or(key_scope_id)
        .map_or_else(UcanHeader::new, UcanHeader::with_kid);

    // Build facts — merge scp_key_scope into existing facts when key_scope
    // is present (ADR-039 acceptance criterion 6).
    let fct = build_facts_with_key_scope(params.facts.as_ref(), params.key_scope.as_ref())?;

    // §7.3.8 root stem/origin_kind agreement gate (rejects a mixed-family
    // outlet root). A single-family outlet root legitimately carries `nb =
    // None` — the first delegation materializes the inferred origin_kind.
    let nb = build_root_caveats(&parsed_stems)?;

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
    let key_scope_id = decode_key_scope(params.key_scope.as_ref())?;
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

    // Collect parent proofs and append the parent's own CID.
    let mut proofs = params.parent_token.payload.prf.clone();
    proofs.push(parent_cid);

    // Same pairing as `mint_ucan`, including the open question its comment
    // states about a `signing_key_id` and a `key_scope` that name different
    // methods.
    let header = params
        .signing_key_id
        .or(key_scope_id)
        .map_or_else(UcanHeader::new, UcanHeader::with_kid);

    // Build facts — merge scp_key_scope into existing facts when key_scope
    // is present (ADR-039).
    let fct = build_facts_with_key_scope(params.facts.as_ref(), params.key_scope.as_ref())?;

    // §7.3.8 rule-4: materialize an explicit `origin_kind` on a delegated
    // OUTLET child (inherited from the parent, or inferred from the delegated
    // stem family when the parent is a caveat-free root), narrowed against the
    // parent's `nb`. A non-outlet delegation carries no `nb`. Without this, a
    // delegated outlet token would carry `nb = None` and the shipped validator
    // would reject it (`OriginKindUnspecified`) — the defect this fixes.
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token1 = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();
        let token2 = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        assert!(
            mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token1 = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();
        let token2 = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };
        mint_ucan(&params, custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let d1 = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
            .await
            .unwrap();
        let d2 = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
    async fn delegate_ucan_chained_delegation_accumulates_proof_chain() {
        // Alice -> Bob -> Carol: verify the proof chain grows.
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
        };

        let bob_to_carol =
            delegate_ucan(&bob_delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let carol_to_dave = delegate_ucan(
            &carol_delegate_params,
            &carol_custody,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap();

        // Carol's delegated token should have root CID AND Bob-to-Carol CID.
        assert_eq!(carol_to_dave.payload.prf.len(), 2);
        assert!(carol_to_dave.payload.prf.contains(&root_cid));
        assert!(carol_to_dave.payload.prf.contains(&bob_to_carol_cid));
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
        };

        let err = delegate_ucan(&delegate_params, &eve_custody, &scp_clock::SystemClock)
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
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };
        let mut root_token = mint_ucan(&params, &alice_custody, &scp_clock::SystemClock)
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
        };

        let delegated = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        // Header must have kid="#agent".
        assert_eq!(
            token.header.kid,
            Some(scp_did::SigningKeyId::Agent),
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        assert_eq!(
            token.header.kid,
            Some(scp_did::SigningKeyId::Active),
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        // Verify self-delegation fields.
        assert_eq!(token.payload.iss, issuer_did);
        assert_eq!(token.payload.aud, issuer_did);
        assert_eq!(token.header.kid, Some(scp_did::SigningKeyId::Agent));

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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        // Round-trip: serialize the token, then parse header and payload back.
        let parts: Vec<&str> = token.encoded.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 segments");

        // Parse header.
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).unwrap();
        let parsed_header: UcanHeader = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(parsed_header.kid, Some(scp_did::SigningKeyId::Agent));
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg)
                if msg.contains("operational verification method")),
            "key_scope without a '#' prefix must be rejected: {err:?}"
        );
    }

    /// A `key_scope` naming a verification method outside `#active` and
    /// `#agent` is rejected at mint time.
    ///
    /// An earlier gate admitted any string starting with `#`, so `"#0"` and
    /// `"#retired-1"` minted a signed token whose header named `#active` — the
    /// method a missing `kid` reads — while its facts named the rejected one.
    /// Step 5b then refused that token at every verifier, so minting reported
    /// success for a token nothing accepts.
    #[tokio::test]
    async fn mint_ucan_rejects_a_key_scope_naming_a_non_operational_method() {
        let (custody, key_handle, issuer_did) = setup_custody().await;
        let caps = vec!["messages:write".to_owned()];

        for scope in ["#0", "#retired-1", "#retired-agent-1", "#unknown"] {
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
                key_scope: Some(scope.to_owned()),
                signing_key_id: None,
                ceiling: None,
            };

            let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
                .await
                .expect_err("a key_scope naming a non-operational method must be rejected");
            assert!(
                matches!(err, UcanError::MalformedToken(ref msg)
                    if msg.contains("operational verification method")),
                "key_scope {scope} must be rejected at mint time: {err:?}"
            );
        }
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
            },
            &custody,
            &scp_clock::SystemClock,
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
            },
            &custody_b,
            &scp_clock::SystemClock,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, UcanError::MalformedToken(ref msg)
                if msg.contains("operational verification method")),
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
            },
            &custody,
            &scp_clock::SystemClock,
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
            },
            &custody_b,
            &scp_clock::SystemClock,
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
            },
            &custody,
            &scp_clock::SystemClock,
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
            },
            &custody_b,
            &scp_clock::SystemClock,
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        // Header must have kid="#agent" from signing_key_id.
        assert_eq!(
            token.header.kid,
            Some(scp_did::SigningKeyId::Agent),
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        // Header must have kid="#active" from signing_key_id.
        assert_eq!(
            token.header.kid,
            Some(scp_did::SigningKeyId::Active),
            "signing_key_id=Active must set kid=#active in header"
        );
    }

    /// A `signing_key_id` and a `key_scope` naming different methods mint a
    /// token whose header names the signer and whose facts name the scope.
    ///
    /// **This token verifies nowhere, and that is an open question rather than
    /// a settled behaviour.** `validate_key_scope` step 5b requires the `kid`
    /// header to equal `fct.scp_key_scope`, so it returns `KeyScopeMismatch`
    /// for every token this pair produces. Two artifacts disagree about which
    /// side is wrong:
    ///
    /// - §9.7.4 of the security-model spec says "The agent signs these scoped
    ///   UCANs with its `#agent` key", which matches step 5b's equality.
    /// - The same sentence opens "scoped UCANs delegated from `#active` to
    ///   `#agent`", and
    ///   `crates/scp-runtime/tests/agent_binding_integration.rs` mints exactly
    ///   this pair and asserts "JWT header kid must be #active (the signing
    ///   key)" — a signer and a grantee that legitimately differ.
    ///
    /// This test records what minting does today. It asserts no verdict on
    /// which reading is right, because a human settles that and the losing side
    /// changes.
    #[tokio::test]
    async fn mint_ucan_carries_the_signer_in_the_header_and_the_scope_in_the_facts() {
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
            key_scope: Some("#active".to_owned()),
            signing_key_id: Some(SigningKeyId::Agent),
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .expect("minting records both fields");

        assert_eq!(
            token.header.kid,
            Some(scp_did::SigningKeyId::Agent),
            "the header names signing_key_id"
        );
        let fct = token.payload.fct.as_ref().unwrap();
        assert_eq!(
            fct.get("scp_key_scope"),
            Some(&serde_json::Value::String("#active".to_owned())),
            "the facts name key_scope"
        );
    }

    /// A `signing_key_id` and a `key_scope` naming one method mint a token
    /// whose header and facts agree, which is what step 5b requires. This case
    /// carries no open question.
    #[tokio::test]
    async fn mint_ucan_accepts_a_signing_key_id_that_agrees_with_key_scope() {
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
            signing_key_id: Some(SigningKeyId::Agent),
            ceiling: None,
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .expect("an agreeing pair mints");

        assert_eq!(token.header.kid, Some(scp_did::SigningKeyId::Agent));
        let fct = token.payload.fct.as_ref().unwrap();
        assert_eq!(
            fct.get("scp_key_scope"),
            Some(&serde_json::Value::String("#agent".to_owned())),
            "the facts must name the method the header names"
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        assert!(
            mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        assert!(
            mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let err = delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
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
        };

        assert!(
            delegate_ucan(&delegate_params, &bob_custody, &scp_clock::SystemClock)
                .await
                .is_ok(),
            "delegation narrowing within ceiling must succeed"
        );
    }

    // -----------------------------------------------------------------------
    // #1293 — UCAN capability URI resource/action split
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn mint_ucan_outlet_invoke_produces_underscore_resource() {
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
    async fn mint_ucan_outlet_invoke_specific_produces_underscore_resource() {
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
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
        };

        let token = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap();

        assert_eq!(
            token.payload.att[0].with, "scp:ctx:ctx-1293/messages:write",
            "simple capabilities must pass through unchanged"
        );
        assert_eq!(token.payload.att[0].can, "write");
    }

    #[tokio::test]
    async fn mint_ucan_outlet_invoke_passes_ceiling_check() {
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
        };

        assert!(
            mint_ucan(&params, &custody, &scp_clock::SystemClock)
                .await
                .is_ok(),
            "outlet:call:* must pass ceiling check with outlet_call:* in ceiling"
        );
    }

    #[tokio::test]
    async fn mint_ucan_outlet_invoke_rejected_when_not_in_ceiling() {
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
        };

        let err = mint_ucan(&params, &custody, &scp_clock::SystemClock)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UcanError::CapabilityOutsideCeiling(_)),
            "outlet:call:* must be rejected when not in ceiling: {err:?}"
        );
    }
}
