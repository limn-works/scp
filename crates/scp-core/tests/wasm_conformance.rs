#![allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::unused_async,
    clippy::redundant_field_names
)]
//! WASM conformance tests (RED-014).
//!
//! The WASM bridge (`scp-ffi-wasm/src/runtime.rs`) re-implements scp-core's
//! Merkle tree, inclusion/absence proofs, and schema validation as standalone
//! pure-Rust code (no scp-core dependency). This file cross-validates the
//! two implementations by embedding the WASM algorithms verbatim and running
//! both against identical inputs, asserting identical outputs at every step.
//!
//! If either implementation changes without updating the other, these tests
//! will fail -- providing the minimum viable safety net against silent
//! divergence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

use scp_core::context::tools::schema;
use scp_core::event_log::proof as core_proof;
use scp_core::event_log::tree as core_tree;
use scp_core::event_log::{Event, EventLog, EventPayload, EventType};

// ===========================================================================
// WASM algorithm mirror (verbatim from scp-ffi-wasm/src/runtime.rs)
//
// These types and functions are exact copies of the WASM bridge code.
// If the WASM code changes, these must be updated in lockstep -- that is
// the point: a forced synchronization checkpoint.
// ===========================================================================

mod wasm_mirror {
    use std::collections::BTreeSet;

    use sha2::{Digest, Sha256};

    /// Append-only Merkle tree mirroring `WasmEventLog` in the WASM bridge.
    pub struct WasmEventLog {
        pub leaves: Vec<[u8; 32]>,
        pub tree: Vec<Vec<[u8; 32]>>,
        pub sorted_leaves: BTreeSet<([u8; 32], u64)>,
    }

    impl WasmEventLog {
        pub const fn new() -> Self {
            Self {
                leaves: Vec::new(),
                tree: Vec::new(),
                sorted_leaves: BTreeSet::new(),
            }
        }

        pub fn append_leaf(&mut self, leaf_hash: [u8; 32]) {
            let leaf_index = self.leaves.len() as u64;
            self.leaves.push(leaf_hash);
            self.sorted_leaves.insert((leaf_hash, leaf_index));
            self.recompute_tree();
        }

        pub fn root(&self) -> [u8; 32] {
            if self.leaves.is_empty() {
                return [0u8; 32];
            }
            if self.tree.is_empty() {
                return self.leaves[0];
            }
            let top_layer = &self.tree[self.tree.len() - 1];
            top_layer[0]
        }

        pub const fn event_count(&self) -> u64 {
            self.leaves.len() as u64
        }

        fn recompute_tree(&mut self) {
            self.tree.clear();

            if self.leaves.len() <= 1 {
                return;
            }

            let mut current_layer: &[[u8; 32]] = &self.leaves;
            let mut owned_layer: Vec<[u8; 32]>;

            loop {
                let parent_count = current_layer.len().div_ceil(2);
                let mut parents = Vec::with_capacity(parent_count);

                let mut i = 0;
                while i < current_layer.len() {
                    if i + 1 < current_layer.len() {
                        parents.push(hash_pair(&current_layer[i], &current_layer[i + 1]));
                    } else {
                        parents.push(hash_pair(&current_layer[i], &current_layer[i]));
                    }
                    i += 2;
                }

                self.tree.push(parents.clone());

                if parents.len() == 1 {
                    break;
                }

                owned_layer = parents;
                current_layer = &owned_layer;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Proof types (mirror of WASM bridge types)
    // -----------------------------------------------------------------------

    #[derive(Debug, Clone, Copy)]
    pub enum Direction {
        Left,
        Right,
    }

    #[derive(Debug, Clone)]
    pub struct ProofStep {
        pub sibling_hash: [u8; 32],
        pub direction: Direction,
    }

    #[derive(Debug, Clone)]
    pub struct InclusionProof {
        pub leaf_index: u64,
        pub leaf_hash: [u8; 32],
        pub path: Vec<ProofStep>,
        pub root: [u8; 32],
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)]
    pub struct LeafWithProof {
        pub leaf_hash: [u8; 32],
        pub leaf_index: u64,
        pub inclusion_proof: InclusionProof,
    }

    #[derive(Debug, Clone)]
    pub struct AbsenceProof {
        pub query_hash: [u8; 32],
        pub lower: Option<LeafWithProof>,
        pub upper: Option<LeafWithProof>,
        pub root: [u8; 32],
        pub leaf_count: u64,
    }

    // -----------------------------------------------------------------------
    // Proof functions (verbatim from WASM bridge)
    // -----------------------------------------------------------------------

    pub fn prove_inclusion(log: &WasmEventLog, leaf_index: u64) -> Result<InclusionProof, String> {
        let leaf_count = log.event_count();

        if leaf_count == 0 {
            return Err("event log is empty".to_owned());
        }

        if leaf_index >= leaf_count {
            return Err(format!(
                "leaf index {leaf_index} out of bounds (log has {leaf_count} leaves)"
            ));
        }

        let leaves = &log.leaves;
        #[allow(clippy::cast_possible_truncation)]
        let leaf_idx_usize = leaf_index as usize;
        let leaf_hash = leaves[leaf_idx_usize];
        let current_root = log.root();

        if leaf_count == 1 {
            return Ok(InclusionProof {
                leaf_index,
                leaf_hash,
                path: Vec::new(),
                root: current_root,
            });
        }

        let tree_layers = &log.tree;
        let mut path = Vec::new();
        let mut idx = leaf_idx_usize;

        let sibling_idx = idx ^ 1;
        if sibling_idx < leaves.len() {
            let direction = if idx.is_multiple_of(2) {
                Direction::Right
            } else {
                Direction::Left
            };
            path.push(ProofStep {
                sibling_hash: leaves[sibling_idx],
                direction,
            });
        } else {
            path.push(ProofStep {
                sibling_hash: leaves[idx],
                direction: Direction::Right,
            });
        }

        idx /= 2;

        for layer in tree_layers.iter().take(tree_layers.len().saturating_sub(1)) {
            let sibling_idx = idx ^ 1;
            if sibling_idx < layer.len() {
                let direction = if idx.is_multiple_of(2) {
                    Direction::Right
                } else {
                    Direction::Left
                };
                path.push(ProofStep {
                    sibling_hash: layer[sibling_idx],
                    direction,
                });
            } else {
                path.push(ProofStep {
                    sibling_hash: layer[idx],
                    direction: Direction::Right,
                });
            }
            idx /= 2;
        }

        Ok(InclusionProof {
            leaf_index,
            leaf_hash,
            path,
            root: current_root,
        })
    }

    pub fn prove_absence(
        log: &WasmEventLog,
        event_hash: &[u8; 32],
    ) -> Result<AbsenceProof, String> {
        let leaf_count = log.event_count();

        if leaf_count == 0 {
            return Err("event log is empty".to_owned());
        }

        let sorted = &log.sorted_leaves;
        let current_root = log.root();

        let exact_match = sorted
            .range((*event_hash, 0)..=(*event_hash, u64::MAX))
            .next();

        if exact_match.is_some() {
            return Err(
                "absence proof requested for event hash that is present in the log".to_owned(),
            );
        }

        let lower = sorted
            .range(..(*event_hash, 0))
            .next_back()
            .map(|(hash, index)| (*hash, *index));

        let upper = sorted
            .range((*event_hash, u64::MAX)..)
            .next()
            .map(|(hash, index)| (*hash, *index));

        let lower_proof: Option<LeafWithProof> = lower
            .map(|(hash, index)| {
                let inclusion_proof = prove_inclusion(log, index)?;
                Ok::<LeafWithProof, String>(LeafWithProof {
                    leaf_hash: hash,
                    leaf_index: index,
                    inclusion_proof,
                })
            })
            .transpose()?;

        let upper_proof: Option<LeafWithProof> = upper
            .map(|(hash, index)| {
                let inclusion_proof = prove_inclusion(log, index)?;
                Ok::<LeafWithProof, String>(LeafWithProof {
                    leaf_hash: hash,
                    leaf_index: index,
                    inclusion_proof,
                })
            })
            .transpose()?;

        Ok(AbsenceProof {
            query_hash: *event_hash,
            lower: lower_proof,
            upper: upper_proof,
            root: current_root,
            leaf_count,
        })
    }

    pub fn verify_inclusion(proof: &InclusionProof) -> bool {
        let mut current_hash = proof.leaf_hash;

        for step in &proof.path {
            current_hash = match step.direction {
                Direction::Left => hash_pair(&step.sibling_hash, &current_hash),
                Direction::Right => hash_pair(&current_hash, &step.sibling_hash),
            };
        }

        current_hash == proof.root
    }

    // -----------------------------------------------------------------------
    // Schema validation (verbatim from WASM bridge)
    // -----------------------------------------------------------------------

    pub fn validate_schema(schema: &serde_json::Value) -> Result<(), String> {
        let obj = schema
            .as_object()
            .ok_or_else(|| "schema must be a JSON object".to_owned())?;

        let type_field = obj
            .get("type")
            .ok_or_else(|| "schema is missing the required \"type\" field".to_owned())?;

        let type_str = type_field
            .as_str()
            .ok_or_else(|| "schema \"type\" field must be a string".to_owned())?;

        const VALID_TYPES: &[&str] = &[
            "object", "array", "string", "number", "integer", "boolean", "null",
        ];

        if !VALID_TYPES.contains(&type_str) {
            return Err(format!("unrecognized JSON Schema type: \"{type_str}\""));
        }

        Ok(())
    }

    pub fn validate_value_against_schema(
        value: &serde_json::Value,
        schema: &serde_json::Value,
    ) -> Result<(), String> {
        if !schema.is_object() {
            return Err("schema is not a JSON object".to_owned());
        }

        let validator =
            jsonschema::validator_for(schema).map_err(|e| format!("invalid schema: {e}"))?;

        validator
            .validate(value)
            .map_err(|e| format!("schema validation failed: {e}"))
    }

    // -----------------------------------------------------------------------
    // hash_pair helper (verbatim from WASM bridge)
    // -----------------------------------------------------------------------

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([0x01]);
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}

// ===========================================================================
// Test helpers
// ===========================================================================

fn test_keypair() -> (ed25519_dalek::VerifyingKey, ed25519_dalek::SigningKey) {
    let mut rng = rand::thread_rng();
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key, signing_key)
}

fn did_from_pubkey(verifying_key: &ed25519_dalek::VerifyingKey) -> String {
    let hex: String = verifying_key
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            use std::fmt::Write;
            let _ = write!(acc, "{b:02x}");
            acc
        });
    format!("did:key:{hex}")
}

fn compute_event_canonical_hash(event: &Event) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"SCP-EVENT-V1:");
    #[allow(clippy::cast_possible_truncation)]
    let length_prefix = |hasher: &mut Sha256, bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_be_bytes());
        hasher.update(bytes);
    };
    hasher.update(event_type_tag(&event.event_type).to_be_bytes());
    length_prefix(&mut hasher, event.actor_did.as_bytes());
    hasher.update(event.timestamp.to_be_bytes());
    hasher.update(event.sequence.to_be_bytes());
    length_prefix(&mut hasher, &event.payload.data);
    hasher.update(event.prev_hash);
    hasher.finalize().to_vec()
}

const fn event_type_tag(event_type: &EventType) -> u16 {
    match event_type {
        EventType::ContextCreated => 0,
        EventType::ContextClosing => 1,
        EventType::ContextClosed => 2,
        EventType::ContextExpired => 3,
        EventType::MemberJoined => 4,
        EventType::MemberLeft => 5,
        EventType::RoleAssigned => 6,
        EventType::TokenRevoked => 7,
        EventType::MessageSent => 8,
        EventType::ToolRegistered => 9,
        EventType::ToolUpdated => 10,
        EventType::ToolInvoked => 11,
        EventType::ToolVerified => 12,
        EventType::ToolInterfaceEstablished => 13,
        EventType::GovernanceAction => 14,
        EventType::ConsistencyCheckpoint => 15,
        EventType::AbsenceProofRequested => 16,
        EventType::MemberBlocked => 17,
        EventType::KeyEpochAdvance => 18,
        EventType::MediaSessionStarted => 19,
        EventType::MediaSessionEnded => 20,
        EventType::PaymentReceived => 21,
        EventType::EconomicPolicyChanged => 22,
        EventType::SpendingUcanGranted => 23,
        EventType::SpendingUcanRevoked => 24,
    }
}

const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

fn sign_event(
    event_type: EventType,
    actor_did: &str,
    timestamp: u64,
    sequence: u64,
    payload: Vec<u8>,
    prev_hash: [u8; 32],
    signing_key: &ed25519_dalek::SigningKey,
) -> Event {
    let mut event = Event {
        event_type,
        actor_did: actor_did.into(),
        timestamp,
        sequence,
        payload: EventPayload { data: payload },
        prev_hash,
        signature: Vec::new(),
    };

    let canonical_hash = compute_event_canonical_hash(&event);
    let signature = signing_key.sign(&canonical_hash);
    event.signature = signature.to_bytes().to_vec();

    event
}

fn leaf_hash_from_event(event: &Event) -> [u8; 32] {
    let serialized = rmp_serde::to_vec(event).unwrap();
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(&serialized);
    hasher.finalize().into()
}

/// Builds both an scp-core `EventLog` and a WASM mirror log with `n` events,
/// returning both logs and the leaf hashes.
fn build_dual_logs(n: u64) -> (EventLog, wasm_mirror::WasmEventLog, Vec<[u8; 32]>) {
    let (verifying_key, signing_key) = test_keypair();
    let did = did_from_pubkey(&verifying_key);

    let mut core_log = EventLog::new("ctx-conformance".to_owned());
    let mut wasm_log = wasm_mirror::WasmEventLog::new();

    let mut prev_hash = GENESIS_PREV_HASH;
    let mut leaf_hashes = Vec::new();

    for i in 0..n {
        let event = sign_event(
            EventType::MessageSent,
            &did,
            1_000_000 + i,
            i,
            format!("message {i}").into_bytes(),
            prev_hash,
            &signing_key,
        );

        core_tree::append(&mut core_log, &event).unwrap();

        let leaf_hash = leaf_hash_from_event(&event);
        wasm_log.append_leaf(leaf_hash);

        leaf_hashes.push(leaf_hash);
        prev_hash = leaf_hash;
    }

    (core_log, wasm_log, leaf_hashes)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

// ===========================================================================
// Test 1: Merkle roots are identical at each step
// ===========================================================================

#[test]
fn merkle_roots_identical_at_each_step() {
    let (verifying_key, signing_key) = test_keypair();
    let did = did_from_pubkey(&verifying_key);

    let mut core_log = EventLog::new("ctx-conformance".to_owned());
    let mut wasm_log = wasm_mirror::WasmEventLog::new();

    // Both empty logs should return the same zero root.
    assert_eq!(
        core_tree::root(&core_log),
        wasm_log.root(),
        "empty log roots differ"
    );

    let mut prev_hash = GENESIS_PREV_HASH;

    for i in 0..20u64 {
        let event = sign_event(
            EventType::MessageSent,
            &did,
            1_000_000 + i,
            i,
            format!("message {i}").into_bytes(),
            prev_hash,
            &signing_key,
        );

        core_tree::append(&mut core_log, &event).unwrap();

        let leaf_hash = leaf_hash_from_event(&event);
        wasm_log.append_leaf(leaf_hash);

        prev_hash = leaf_hash;

        let core_root = core_tree::root(&core_log);
        let wasm_root = wasm_log.root();

        assert_eq!(
            core_root,
            wasm_root,
            "ROOT DIVERGENCE at event {i}: core={} wasm={}",
            encode_hex(&core_root),
            encode_hex(&wasm_root),
        );
    }
}

// ===========================================================================
// Test 2: Merkle roots identical for various tree sizes (power-of-two and odd)
// ===========================================================================

#[test]
fn merkle_roots_identical_various_sizes() {
    for size in [1, 2, 3, 4, 5, 7, 8, 9, 13, 15, 16, 17, 31, 32, 33] {
        let (core_log, wasm_log, _) = build_dual_logs(size);

        let core_root = core_tree::root(&core_log);
        let wasm_root = wasm_log.root();

        assert_eq!(
            core_root,
            wasm_root,
            "ROOT DIVERGENCE at size {size}: core={} wasm={}",
            encode_hex(&core_root),
            encode_hex(&wasm_root),
        );
    }
}

// ===========================================================================
// Test 3: Interior tree layers are identical
// ===========================================================================

#[test]
fn interior_tree_layers_identical() {
    for size in [2, 3, 5, 8, 13, 16] {
        let (core_log, wasm_log, _) = build_dual_logs(size);

        let core_layers = core_log.tree_layers();
        let wasm_layers = &wasm_log.tree;

        assert_eq!(
            core_layers.len(),
            wasm_layers.len(),
            "layer count differs at size {size}: core={} wasm={}",
            core_layers.len(),
            wasm_layers.len(),
        );

        for (layer_idx, (core_layer, wasm_layer)) in
            core_layers.iter().zip(wasm_layers.iter()).enumerate()
        {
            assert_eq!(
                core_layer.len(),
                wasm_layer.len(),
                "layer {layer_idx} node count differs at size {size}"
            );

            for (node_idx, (core_node, wasm_node)) in
                core_layer.iter().zip(wasm_layer.iter()).enumerate()
            {
                assert_eq!(
                    core_node,
                    wasm_node,
                    "TREE DIVERGENCE at size {size}, layer {layer_idx}, node {node_idx}: \
                     core={} wasm={}",
                    encode_hex(core_node),
                    encode_hex(wasm_node),
                );
            }
        }
    }
}

// ===========================================================================
// Test 4: Inclusion proofs are identical for every leaf
// ===========================================================================

#[test]
fn inclusion_proofs_identical_for_every_leaf() {
    for size in [1, 2, 3, 5, 8, 10, 13, 16] {
        let (core_log, wasm_log, _leaf_hashes) = build_dual_logs(size);

        for i in 0..size {
            let core_proof = core_proof::prove_inclusion(&core_log, i).unwrap();
            let wasm_proof = wasm_mirror::prove_inclusion(&wasm_log, i).unwrap();

            assert_eq!(
                core_proof.leaf_index, wasm_proof.leaf_index,
                "leaf_index differs at size {size}, leaf {i}"
            );
            assert_eq!(
                core_proof.leaf_hash, wasm_proof.leaf_hash,
                "leaf_hash differs at size {size}, leaf {i}"
            );
            assert_eq!(
                core_proof.root, wasm_proof.root,
                "root differs at size {size}, leaf {i}"
            );

            assert_eq!(
                core_proof.path.len(),
                wasm_proof.path.len(),
                "PROOF PATH LENGTH DIVERGENCE at size {size}, leaf {i}: \
                 core={} wasm={}",
                core_proof.path.len(),
                wasm_proof.path.len(),
            );

            for (step_idx, (core_step, wasm_step)) in core_proof
                .path
                .iter()
                .zip(wasm_proof.path.iter())
                .enumerate()
            {
                assert_eq!(
                    core_step.sibling_hash,
                    wasm_step.sibling_hash,
                    "PROOF STEP HASH DIVERGENCE at size {size}, leaf {i}, step {step_idx}: \
                     core={} wasm={}",
                    encode_hex(&core_step.sibling_hash),
                    encode_hex(&wasm_step.sibling_hash),
                );

                let core_dir = match core_step.direction {
                    core_proof::Direction::Left => "Left",
                    core_proof::Direction::Right => "Right",
                };
                let wasm_dir = match wasm_step.direction {
                    wasm_mirror::Direction::Left => "Left",
                    wasm_mirror::Direction::Right => "Right",
                };
                assert_eq!(
                    core_dir, wasm_dir,
                    "PROOF STEP DIRECTION DIVERGENCE at size {size}, leaf {i}, step {step_idx}: \
                     core={core_dir} wasm={wasm_dir}",
                );
            }

            // Both proofs must verify.
            assert!(
                core_proof::verify_inclusion(&core_proof),
                "scp-core proof fails verification at size {size}, leaf {i}"
            );
            assert!(
                wasm_mirror::verify_inclusion(&wasm_proof),
                "WASM mirror proof fails verification at size {size}, leaf {i}"
            );
        }
    }
}

// ===========================================================================
// Test 5: verify_inclusion is symmetric (core proof verified by WASM, vice versa)
// ===========================================================================

#[test]
fn verify_inclusion_cross_validated() {
    for size in [2, 5, 8, 13] {
        let (core_log, wasm_log, _) = build_dual_logs(size);

        for i in 0..size {
            let core_proof = core_proof::prove_inclusion(&core_log, i).unwrap();
            let wasm_proof = wasm_mirror::prove_inclusion(&wasm_log, i).unwrap();

            // Convert core proof to WASM format and verify with WASM verifier.
            let core_as_wasm = wasm_mirror::InclusionProof {
                leaf_index: core_proof.leaf_index,
                leaf_hash: core_proof.leaf_hash,
                path: core_proof
                    .path
                    .iter()
                    .map(|step| wasm_mirror::ProofStep {
                        sibling_hash: step.sibling_hash,
                        direction: match step.direction {
                            core_proof::Direction::Left => wasm_mirror::Direction::Left,
                            core_proof::Direction::Right => wasm_mirror::Direction::Right,
                        },
                    })
                    .collect(),
                root: core_proof.root,
            };
            assert!(
                wasm_mirror::verify_inclusion(&core_as_wasm),
                "core proof fails WASM verification at size {size}, leaf {i}"
            );

            // Convert WASM proof to core format and verify with core verifier.
            let wasm_as_core = core_proof::InclusionProof {
                leaf_index: wasm_proof.leaf_index,
                leaf_hash: wasm_proof.leaf_hash,
                path: wasm_proof
                    .path
                    .iter()
                    .map(|step| core_proof::ProofStep {
                        sibling_hash: step.sibling_hash,
                        direction: match step.direction {
                            wasm_mirror::Direction::Left => core_proof::Direction::Left,
                            wasm_mirror::Direction::Right => core_proof::Direction::Right,
                        },
                    })
                    .collect(),
                root: wasm_proof.root,
            };
            assert!(
                core_proof::verify_inclusion(&wasm_as_core),
                "WASM proof fails core verification at size {size}, leaf {i}"
            );
        }
    }
}

// ===========================================================================
// Test 6: Absence proofs are identical
// ===========================================================================

#[test]
fn absence_proofs_identical() {
    for size in [3, 5, 8, 10] {
        let (core_log, wasm_log, _) = build_dual_logs(size);

        // Test with hashes known to be absent: all-zeros and all-0xFF.
        let test_hashes: Vec<[u8; 32]> = vec![[0x00; 32], [0xFF; 32], [0x42; 32], [0x80; 32]];

        for query_hash in &test_hashes {
            // Skip if the hash happens to be present (unlikely but possible).
            if core_log
                .sorted_leaves()
                .iter()
                .map(|(h, _)| *h)
                .any(|x| x == *query_hash)
            {
                continue;
            }

            let core_absence = core_proof::prove_absence(&core_log, query_hash).unwrap();
            let wasm_absence = wasm_mirror::prove_absence(&wasm_log, query_hash).unwrap();

            assert_eq!(
                core_absence.query_hash, wasm_absence.query_hash,
                "query_hash differs at size {size}"
            );
            assert_eq!(
                core_absence.root, wasm_absence.root,
                "root differs in absence proof at size {size}"
            );
            assert_eq!(
                core_absence.leaf_count, wasm_absence.leaf_count,
                "leaf_count differs in absence proof at size {size}"
            );

            // Lower bound.
            match (&core_absence.lower, &wasm_absence.lower) {
                (Some(core_lower), Some(wasm_lower)) => {
                    assert_eq!(
                        core_lower.leaf_hash,
                        wasm_lower.leaf_hash,
                        "ABSENCE LOWER HASH DIVERGENCE at size {size}, query={}",
                        encode_hex(query_hash),
                    );
                    assert_eq!(
                        core_lower.leaf_index, wasm_lower.leaf_index,
                        "absence lower index differs at size {size}"
                    );
                }
                (None, None) => {}
                _ => panic!(
                    "ABSENCE LOWER DIVERGENCE at size {size}: \
                     core has lower={} wasm has lower={}",
                    core_absence.lower.is_some(),
                    wasm_absence.lower.is_some(),
                ),
            }

            // Upper bound.
            match (&core_absence.upper, &wasm_absence.upper) {
                (Some(core_upper), Some(wasm_upper)) => {
                    assert_eq!(
                        core_upper.leaf_hash,
                        wasm_upper.leaf_hash,
                        "ABSENCE UPPER HASH DIVERGENCE at size {size}, query={}",
                        encode_hex(query_hash),
                    );
                    assert_eq!(
                        core_upper.leaf_index, wasm_upper.leaf_index,
                        "absence upper index differs at size {size}"
                    );
                }
                (None, None) => {}
                _ => panic!(
                    "ABSENCE UPPER DIVERGENCE at size {size}: \
                     core has upper={} wasm has upper={}",
                    core_absence.upper.is_some(),
                    wasm_absence.upper.is_some(),
                ),
            }
        }
    }
}

// ===========================================================================
// Test 7: Sorted leaf index is identical
// ===========================================================================

#[test]
fn sorted_leaf_index_identical() {
    for size in [1, 5, 10, 16] {
        let (core_log, wasm_log, _) = build_dual_logs(size);

        let core_sorted: Vec<([u8; 32], u64)> = core_log.sorted_leaves().iter().copied().collect();
        let wasm_sorted: Vec<([u8; 32], u64)> = wasm_log.sorted_leaves.iter().copied().collect();

        assert_eq!(
            core_sorted.len(),
            wasm_sorted.len(),
            "sorted index size differs at size {size}"
        );

        for (i, (core_entry, wasm_entry)) in core_sorted.iter().zip(wasm_sorted.iter()).enumerate()
        {
            assert_eq!(
                core_entry.0,
                wasm_entry.0,
                "SORTED INDEX HASH DIVERGENCE at size {size}, entry {i}: \
                 core={} wasm={}",
                encode_hex(&core_entry.0),
                encode_hex(&wasm_entry.0),
            );
            assert_eq!(
                core_entry.1, wasm_entry.1,
                "SORTED INDEX LEAF_INDEX DIVERGENCE at size {size}, entry {i}: \
                 core={} wasm={}",
                core_entry.1, wasm_entry.1,
            );
        }
    }
}

// ===========================================================================
// Test 8: Schema structural validation produces identical accept/reject
// ===========================================================================

#[test]
fn schema_validation_identical_accept_reject() {
    let test_cases: Vec<(serde_json::Value, bool)> = vec![
        // Valid schemas: all 7 JSON Schema types.
        (serde_json::json!({"type": "object"}), true),
        (serde_json::json!({"type": "array"}), true),
        (serde_json::json!({"type": "string"}), true),
        (serde_json::json!({"type": "number"}), true),
        (serde_json::json!({"type": "integer"}), true),
        (serde_json::json!({"type": "boolean"}), true),
        (serde_json::json!({"type": "null"}), true),
        // Valid schemas with extra fields.
        (
            serde_json::json!({"type": "object", "properties": {"a": {"type": "string"}}}),
            true,
        ),
        // Invalid: not an object.
        (serde_json::json!("not an object"), false),
        (serde_json::json!(42), false),
        (serde_json::json!(null), false),
        (serde_json::json!([1, 2, 3]), false),
        (serde_json::json!(true), false),
        // Invalid: missing type field.
        (serde_json::json!({"properties": {}}), false),
        (serde_json::json!({}), false),
        // Invalid: type field is not a string.
        (serde_json::json!({"type": 42}), false),
        (serde_json::json!({"type": true}), false),
        (serde_json::json!({"type": null}), false),
        (serde_json::json!({"type": ["object"]}), false),
        // Invalid: unrecognized type.
        (serde_json::json!({"type": "foobar"}), false),
        (serde_json::json!({"type": "Object"}), false),
        (serde_json::json!({"type": ""}), false),
    ];

    for (i, (schema, expected_ok)) in test_cases.iter().enumerate() {
        let core_result = schema::validate_schema(schema).is_ok();
        let wasm_result = wasm_mirror::validate_schema(schema).is_ok();

        assert_eq!(
            core_result, wasm_result,
            "SCHEMA VALIDATION DIVERGENCE at test case {i}: \
             schema={schema}, core_ok={core_result}, wasm_ok={wasm_result}",
        );
        assert_eq!(
            core_result, *expected_ok,
            "unexpected result at test case {i}: schema={schema}, expected_ok={expected_ok}",
        );
    }
}

// ===========================================================================
// Test 9: Value-against-schema validation produces identical accept/reject
// ===========================================================================

#[test]
fn value_against_schema_validation_identical() {
    let test_cases: Vec<(serde_json::Value, serde_json::Value, bool)> = vec![
        // Type matching.
        (
            serde_json::json!({"key": "val"}),
            serde_json::json!({"type": "object"}),
            true,
        ),
        (
            serde_json::json!("hello"),
            serde_json::json!({"type": "string"}),
            true,
        ),
        (
            serde_json::json!(42),
            serde_json::json!({"type": "integer"}),
            true,
        ),
        (
            serde_json::json!(2.72),
            serde_json::json!({"type": "number"}),
            true,
        ),
        (
            serde_json::json!(true),
            serde_json::json!({"type": "boolean"}),
            true,
        ),
        (
            serde_json::json!(null),
            serde_json::json!({"type": "null"}),
            true,
        ),
        (
            serde_json::json!([1, 2, 3]),
            serde_json::json!({"type": "array", "items": {"type": "integer"}}),
            true,
        ),
        // Type mismatches.
        (
            serde_json::json!("not an object"),
            serde_json::json!({"type": "object"}),
            false,
        ),
        (
            serde_json::json!(42),
            serde_json::json!({"type": "string"}),
            false,
        ),
        (
            serde_json::json!(2.72),
            serde_json::json!({"type": "integer"}),
            false,
        ),
        // Required fields.
        (
            serde_json::json!({"name": "Alice", "age": 30}),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "integer"}
                },
                "required": ["name", "age"]
            }),
            true,
        ),
        (
            serde_json::json!({"name": "Alice"}),
            serde_json::json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "age": {"type": "integer"}
                },
                "required": ["name", "age"]
            }),
            false,
        ),
        // additionalProperties: false.
        (
            serde_json::json!({"name": "Alice", "extra": "bad"}),
            serde_json::json!({
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "additionalProperties": false
            }),
            false,
        ),
        // Numeric constraints.
        (
            serde_json::json!(5),
            serde_json::json!({"type": "number", "minimum": 10}),
            false,
        ),
        (
            serde_json::json!(50),
            serde_json::json!({"type": "number", "minimum": 10, "maximum": 100}),
            true,
        ),
        // String constraints.
        (
            serde_json::json!("abc"),
            serde_json::json!({"type": "string", "minLength": 5}),
            false,
        ),
        (
            serde_json::json!("hello"),
            serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}),
            true,
        ),
        (
            serde_json::json!("ABC123"),
            serde_json::json!({"type": "string", "pattern": "^[a-z]+$"}),
            false,
        ),
        // Enum.
        (
            serde_json::json!("green"),
            serde_json::json!({"type": "string", "enum": ["red", "green", "blue"]}),
            true,
        ),
        (
            serde_json::json!("yellow"),
            serde_json::json!({"type": "string", "enum": ["red", "green", "blue"]}),
            false,
        ),
        // Array item validation.
        (
            serde_json::json!([1, 2, "three"]),
            serde_json::json!({"type": "array", "items": {"type": "integer"}}),
            false,
        ),
        // Non-object schema rejected.
        (
            serde_json::json!(42),
            serde_json::json!("not an object"),
            false,
        ),
    ];

    for (i, (value, test_schema, expected_ok)) in test_cases.iter().enumerate() {
        let core_result = schema::validate_value_against_schema(value, test_schema).is_ok();
        let wasm_result = wasm_mirror::validate_value_against_schema(value, test_schema).is_ok();

        assert_eq!(
            core_result, wasm_result,
            "VALUE-SCHEMA VALIDATION DIVERGENCE at test case {i}: \
             value={value}, schema={test_schema}, core_ok={core_result}, wasm_ok={wasm_result}",
        );
        assert_eq!(
            core_result, *expected_ok,
            "unexpected validation result at test case {i}: \
             value={value}, schema={test_schema}, expected_ok={expected_ok}",
        );
    }
}

// ===========================================================================
// Test 10: Event count is identical
// ===========================================================================

#[test]
fn event_count_identical() {
    for size in [0, 1, 5, 10, 20] {
        let (core_log, wasm_log, _) = if size == 0 {
            (
                EventLog::new("ctx-empty".to_owned()),
                wasm_mirror::WasmEventLog::new(),
                Vec::new(),
            )
        } else {
            build_dual_logs(size)
        };

        assert_eq!(
            core_tree::event_count(&core_log),
            wasm_log.event_count(),
            "event count differs at size {size}"
        );
    }
}

// ===========================================================================
// Test 11: Empty log edge cases match
// ===========================================================================

#[test]
fn empty_log_edge_cases_match() {
    let core_log = EventLog::new("ctx-empty".to_owned());
    let wasm_log = wasm_mirror::WasmEventLog::new();

    // Root of empty log.
    assert_eq!(
        core_tree::root(&core_log),
        wasm_log.root(),
        "empty log root differs"
    );
    assert_eq!(core_tree::root(&core_log), [0u8; 32]);

    // Event count of empty log.
    assert_eq!(core_tree::event_count(&core_log), 0);
    assert_eq!(wasm_log.event_count(), 0);

    // Inclusion proof on empty log: both should error.
    let core_err = core_proof::prove_inclusion(&core_log, 0);
    let wasm_err = wasm_mirror::prove_inclusion(&wasm_log, 0);
    assert!(
        core_err.is_err(),
        "core should reject inclusion on empty log"
    );
    assert!(
        wasm_err.is_err(),
        "wasm should reject inclusion on empty log"
    );

    // Absence proof on empty log: both should error.
    let query = [0x42; 32];
    let core_absence_err = core_proof::prove_absence(&core_log, &query);
    let wasm_absence_err = wasm_mirror::prove_absence(&wasm_log, &query);
    assert!(
        core_absence_err.is_err(),
        "core should reject absence on empty log"
    );
    assert!(
        wasm_absence_err.is_err(),
        "wasm should reject absence on empty log"
    );
}

// ===========================================================================
// Test 12: Out-of-bounds leaf index errors match
// ===========================================================================

#[test]
fn out_of_bounds_leaf_index_errors_match() {
    for size in [1, 5, 10] {
        let (core_log, wasm_log, _) = build_dual_logs(size);

        // At the boundary (index == size).
        let core_err = core_proof::prove_inclusion(&core_log, size);
        let wasm_err = wasm_mirror::prove_inclusion(&wasm_log, size);
        assert!(
            core_err.is_err(),
            "core should reject index {size} with {size} leaves"
        );
        assert!(
            wasm_err.is_err(),
            "wasm should reject index {size} with {size} leaves"
        );

        // Well past the boundary.
        let core_err = core_proof::prove_inclusion(&core_log, size + 100);
        let wasm_err = wasm_mirror::prove_inclusion(&wasm_log, size + 100);
        assert!(core_err.is_err());
        assert!(wasm_err.is_err());
    }
}

// ===========================================================================
// Test 13: Absence proof for present hash: both reject
// ===========================================================================

#[test]
fn absence_proof_for_present_hash_both_reject() {
    for size in [1, 5, 10] {
        let (core_log, wasm_log, leaf_hashes) = build_dual_logs(size);

        for leaf_hash in &leaf_hashes {
            let core_result = core_proof::prove_absence(&core_log, leaf_hash);
            let wasm_result = wasm_mirror::prove_absence(&wasm_log, leaf_hash);

            assert!(
                core_result.is_err(),
                "core should reject absence for present hash at size {size}"
            );
            assert!(
                wasm_result.is_err(),
                "wasm should reject absence for present hash at size {size}"
            );
        }
    }
}

// ===========================================================================
// Test 14: Inclusion proof verification interoperability
//
// Generates proofs with one implementation and verifies with the other.
// ===========================================================================

#[test]
fn inclusion_proof_interoperable_verification() {
    let (core_log, wasm_log, _) = build_dual_logs(10);

    for i in 0..10u64 {
        // Core generates proof, convert to WASM format, WASM verifies.
        let core_proof = core_proof::prove_inclusion(&core_log, i).unwrap();

        let converted_to_wasm = wasm_mirror::InclusionProof {
            leaf_index: core_proof.leaf_index,
            leaf_hash: core_proof.leaf_hash,
            path: core_proof
                .path
                .iter()
                .map(|step| wasm_mirror::ProofStep {
                    sibling_hash: step.sibling_hash,
                    direction: match step.direction {
                        core_proof::Direction::Left => wasm_mirror::Direction::Left,
                        core_proof::Direction::Right => wasm_mirror::Direction::Right,
                    },
                })
                .collect(),
            root: core_proof.root,
        };
        assert!(
            wasm_mirror::verify_inclusion(&converted_to_wasm),
            "core-generated proof fails WASM verification at leaf {i}"
        );

        // WASM generates proof, convert to core format, core verifies.
        let wasm_proof = wasm_mirror::prove_inclusion(&wasm_log, i).unwrap();

        let converted_to_core = core_proof::InclusionProof {
            leaf_index: wasm_proof.leaf_index,
            leaf_hash: wasm_proof.leaf_hash,
            path: wasm_proof
                .path
                .iter()
                .map(|step| core_proof::ProofStep {
                    sibling_hash: step.sibling_hash,
                    direction: match step.direction {
                        wasm_mirror::Direction::Left => core_proof::Direction::Left,
                        wasm_mirror::Direction::Right => core_proof::Direction::Right,
                    },
                })
                .collect(),
            root: wasm_proof.root,
        };
        assert!(
            core_proof::verify_inclusion(&converted_to_core),
            "WASM-generated proof fails core verification at leaf {i}"
        );
    }
}

// ===========================================================================
// WASM context registry mirror (verbatim from scp-ffi-wasm/src/runtime.rs)
//
// Mirrors the registry functions to validate registration, lookup, and
// removal semantics. See issue #137.
// ===========================================================================

mod wasm_registry_mirror {
    use std::cell::RefCell;
    use std::collections::{HashMap, HashSet};

    /// Minimal mirror of `WasmContextRuntime` — only the fields needed to
    /// validate registry semantics.
    pub struct WasmContextRuntime {
        pub creator_did: String,
        pub ceiling_strings: HashSet<String>,
    }

    thread_local! {
        static CONTEXT_REGISTRY: RefCell<HashMap<String, WasmContextRuntime>> =
            RefCell::new(HashMap::new());
    }

    /// Mirrors `runtime::register_context` from `scp-ffi-wasm/src/runtime.rs`.
    pub fn register_context(context_id: &str, creator_did: &str) -> Result<(), String> {
        CONTEXT_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            if map.contains_key(context_id) {
                return Err(format!("context '{context_id}' is already registered"));
            }

            let ceiling_strings: HashSet<String> = [
                "messages:read",
                "messages:write",
                "tool_register:*",
                "tool_invoke:*",
                "role_assign:*",
                "member_invite:*",
                "member_remove:*",
                "governance_propose:*",
                "governance_vote:*",
                "context_close:*",
            ]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();

            let runtime = WasmContextRuntime {
                creator_did: creator_did.to_owned(),
                ceiling_strings,
            };

            map.insert(context_id.to_owned(), runtime);
            Ok(())
        })
    }

    /// Mirrors `runtime::remove_context` from `scp-ffi-wasm/src/runtime.rs`.
    pub fn remove_context(context_id: &str) {
        CONTEXT_REGISTRY.with(|reg| {
            reg.borrow_mut().remove(context_id);
        });
    }

    /// Mirrors `runtime::with_context` from `scp-ffi-wasm/src/runtime.rs`.
    pub fn with_context<T, F>(context_id: &str, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut WasmContextRuntime) -> Result<T, String>,
    {
        CONTEXT_REGISTRY.with(|reg| {
            let mut map = reg.borrow_mut();
            let rt = map.get_mut(context_id).ok_or_else(|| {
                format!(
                    "context '{context_id}' not found in runtime registry \
                     — was it created with context_create?"
                )
            })?;
            f(rt)
        })
    }
}

// ===========================================================================
// Test 15: context_create registers context in runtime registry
// ===========================================================================

#[test]
fn context_registry_register_then_lookup_succeeds() {
    let context_id = "ctx-test-register-001";
    let creator_did = "did:key:test-creator-001";

    // Register the context (mirrors what context_create now does).
    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    // with_context should succeed and return the creator DID.
    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert_eq!(result.unwrap(), creator_did);
}

// ===========================================================================
// Test 16: context_close removes context from runtime registry
// ===========================================================================

#[test]
fn context_registry_remove_then_lookup_fails() {
    let context_id = "ctx-test-remove-001";
    let creator_did = "did:key:test-creator-002";

    // Register.
    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    // Verify it exists.
    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert!(result.is_ok());

    // Remove (mirrors what context_close now does).
    wasm_registry_mirror::remove_context(context_id);

    // with_context should now fail.
    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("not found in runtime registry"),
        "error message should indicate context not found"
    );
}

// ===========================================================================
// Test 17: with_context on nonexistent context fails with appropriate error
// ===========================================================================

#[test]
fn context_registry_nonexistent_lookup_fails() {
    let context_id = "ctx-nonexistent-999";

    let result = wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.creator_did.clone()));
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .contains("not found in runtime registry"),
        "error message should indicate context not found"
    );
}

// ===========================================================================
// Test 18: duplicate registration is rejected
// ===========================================================================

#[test]
fn context_registry_duplicate_registration_rejected() {
    let context_id = "ctx-test-dup-001";
    let creator_did = "did:key:test-creator-003";

    // First registration succeeds.
    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    // Second registration with same ID fails.
    let result = wasm_registry_mirror::register_context(context_id, creator_did);
    assert!(result.is_err());
    assert!(
        result.unwrap_err().contains("already registered"),
        "error message should indicate duplicate"
    );
}

// ===========================================================================
// Test 19: register populates default capability ceiling
// ===========================================================================

#[test]
fn context_registry_default_ceiling_populated() {
    let context_id = "ctx-test-ceiling-001";
    let creator_did = "did:key:test-creator-004";

    wasm_registry_mirror::register_context(context_id, creator_did).unwrap();

    let ceiling =
        wasm_registry_mirror::with_context(context_id, |rt| Ok(rt.ceiling_strings.clone()))
            .unwrap();

    // Verify the 10 default capabilities.
    assert!(ceiling.contains("messages:read"));
    assert!(ceiling.contains("messages:write"));
    assert!(ceiling.contains("tool_register:*"));
    assert!(ceiling.contains("tool_invoke:*"));
    assert!(ceiling.contains("role_assign:*"));
    assert!(ceiling.contains("member_invite:*"));
    assert!(ceiling.contains("member_remove:*"));
    assert!(ceiling.contains("governance_propose:*"));
    assert!(ceiling.contains("governance_vote:*"));
    assert!(ceiling.contains("context_close:*"));
    assert_eq!(ceiling.len(), 10);
}
