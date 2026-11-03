//! The node's public-record store over a running node's WebSocket listener
//! (`09-security-model.md` §9.10.12, §9.18.B; `10-infrastructure-and-self-hosting.md`
//! §10.4.1): per-kind admission and selection, the `4040` and `4044` codes,
//! the `retain` refusals, the `after_blob` refusal, and the quota classes.
//!
//! Every fixture is built on the crates' public encoders: each identity's
//! log is a P-256 inception signed by its one root key, and every record is
//! signed by the key its admission rule names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use scp_crypto::p256::{P256SecretKey, SeedLabel, sign_prehash_rfc6979};
use scp_dht::InMemoryDhtClient;
use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole, NodeUrl,
};
use scp_identity::DidCache;
use scp_identity::dht::DidDht;
use scp_kel::{
    Continuation, EventPreimage, InceptionFields, KeyStateFields, KeyStateSnapshot, RoutingKind,
    SignatureForm, SignerGroup, derive_node_id, encode_preimage, node_list_routing_id,
    prerotation_commitment, routing_id,
};
use scp_node::public_records::{NodeListSource, PublicRecordTerms, QuotaLimit, QuotaLimits};
use scp_node::{ApplicationNode, DhtMode, IdentitySource, Node, NodeConfig, Reach};
use scp_platform::in_memory::InMemoryStorage;
use scp_platform::testing::InMemoryKeyCustody;
use scp_protocol::node::{
    ConflictStatement, NodeBinding, NodeListEntry, NodeListRecord, ServiceEntry,
    encode_conflict_frame, encode_key_event_frame, encode_node_list_frame,
    encode_service_record_frame, node_url_hash, service_record_fields,
    service_record_signing_digest,
};
use scp_relay_client::{BlobLifetime, ClientMessage, RelayMessage, code};
use scp_transport::native::storage::BlobStorageBackend;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

const CONTEXT_ID: &str = "public-record-test-context";

fn key(seed: u8) -> P256SecretKey {
    P256SecretKey::from_seed(SeedLabel::TestVectorKey, &[seed; 32])
}

fn point(key: &P256SecretKey) -> [u8; 33] {
    key.public_key().to_compressed()
}

fn sign(key: &P256SecretKey, digest: &[u8; 32]) -> [u8; 64] {
    sign_prehash_rfc6979(key, digest).unwrap()
}

const fn entry(key: [u8; 33], role: KeyRole) -> KeyEntry {
    KeyEntry {
        key,
        role,
        condition: KeyCondition::Current,
        compromised_from: 0,
        custody_type: CustodyType::Passkey,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    }
}

fn root_group() -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: vec![SignatureForm::Raw],
    }
}

/// One signed event: its unit, its digest and its sequence.
#[derive(Clone)]
struct Event {
    unit: Vec<u8>,
    digest: [u8; 32],
    sequence: u64,
}

/// `BE32(len) ‖ signed preimage ‖ the signer's raw signature`.
fn signed_event(
    preimage: &EventPreimage,
    signer: &P256SecretKey,
) -> (Vec<u8>, [u8; 32], Identifier) {
    let encoded = encode_preimage(preimage).unwrap();
    let preimage_bytes = encoded.signed_preimage();
    let digest: [u8; 32] = Sha256::digest(&preimage_bytes).into();
    let mut unit = u32::try_from(preimage_bytes.len())
        .unwrap()
        .to_be_bytes()
        .to_vec();
    unit.extend_from_slice(&preimage_bytes);
    unit.extend_from_slice(&sign(signer, &digest));
    let identifier = encoded
        .inception_identifier()
        .unwrap_or(preimage.identifier);
    (unit, encoded.event_digest(), identifier)
}

/// An identity whose log is one inception: a 1-of-1 root, one `#active`
/// key that also signs its service record, and `witnesses`.
struct Identity {
    root: P256SecretKey,
    active: P256SecretKey,
    id: Identifier,
    inception: Event,
    snapshot: KeyStateSnapshot,
}

impl Identity {
    fn new(seed: u8, witnesses: Vec<Identifier>) -> Self {
        let root = key(seed);
        let active = key(seed.wrapping_add(1));
        let next = key(seed.wrapping_add(2));
        let snapshot = KeyStateSnapshot {
            root_threshold: 1,
            keys: vec![
                entry(point(&root), KeyRole::RootMember),
                entry(point(&active), KeyRole::Active),
            ],
            witnesses,
            witnessing_interval: 3600,
            service_key_role: KeyRole::Active,
            delegator: Identifier::ZERO,
        };
        let preimage = EventPreimage::inception(InceptionFields {
            root_group: root_group(),
            key_state: snapshot.clone(),
            continuation: Continuation::FixesCommitment(FixedCommitment {
                commitments: vec![CommitmentEntry {
                    commitment: prerotation_commitment(&point(&next)),
                    custody_type: CustodyType::Passkey,
                    key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
                }],
                next_threshold: 1,
            }),
        });
        let (unit, digest, id) = signed_event(&preimage, &root);
        Self {
            root,
            active,
            id,
            inception: Event {
                unit,
                digest,
                sequence: 0,
            },
            snapshot,
        }
    }

    /// A `KeyState` at sequence 1 that changes only the witnessing interval
    /// to `interval`, signed by `signer` in the root slot.
    fn key_state(&self, interval: u32, signer: &P256SecretKey) -> Event {
        let mut snapshot = self.snapshot.clone();
        snapshot.witnessing_interval = interval;
        let preimage = EventPreimage::key_state(KeyStateFields {
            identifier: self.id,
            sequence: 1,
            predecessor_digest: self.inception.digest,
            root_group: root_group(),
            key_state: snapshot,
            seals: Vec::new(),
        });
        let (unit, digest, _) = signed_event(&preimage, signer);
        Event {
            unit,
            digest,
            sequence: 1,
        }
    }

    /// A `KeyState` at sequence 1, signed by the root, that installs
    /// `successor` as `#active` and drops the inception's `#active` as
    /// `dropped`: `Superseded` for a rotation, `Compromised` (from the
    /// inception) for a compromise.
    fn replace_active(&self, successor: &P256SecretKey, dropped: KeyCondition) -> Event {
        let mut snapshot = self.snapshot.clone();
        snapshot.keys = vec![
            entry(point(&self.root), KeyRole::RootMember),
            entry(point(successor), KeyRole::Active),
            KeyEntry {
                condition: dropped,
                ..entry(point(&self.active), KeyRole::Active)
            },
        ];
        let preimage = EventPreimage::key_state(KeyStateFields {
            identifier: self.id,
            sequence: 1,
            predecessor_digest: self.inception.digest,
            root_group: root_group(),
            key_state: snapshot,
            seals: Vec::new(),
        });
        let (unit, digest, _) = signed_event(&preimage, &self.root);
        Event {
            unit,
            digest,
            sequence: 1,
        }
    }

    fn did_routing(&self) -> [u8; 32] {
        routing_id(RoutingKind::KeyEvents, &self.id)
    }

    /// A key-event frame under this identity carrying `events`.
    fn frame(&self, events: &[&Event]) -> Vec<u8> {
        let units: Vec<&[u8]> = events.iter().map(|event| event.unit.as_slice()).collect();
        encode_key_event_frame(&self.id, events[0].sequence, &units).unwrap()
    }

    /// A service record at `sequence`, signed by `signer`.
    fn service_record(&self, sequence: u64, signer: &P256SecretKey) -> Vec<u8> {
        let fields = service_record_fields(
            &self.id,
            sequence,
            &[ServiceEntry {
                id: "#node".to_owned(),
                entry_type: "SCPNode".to_owned(),
                service_endpoint: format!("wss://node{sequence}.example.com/scp/v1"),
                derivation_id: None,
            }],
        )
        .unwrap();
        let signature = sign(signer, &service_record_signing_digest(&fields));
        encode_service_record_frame(&self.id, &fields, &signature).unwrap()
    }
}

/// A governor, an operator and a node key it binds, and a subject that
/// names the operator as its witness.
struct World {
    governor: Identity,
    operator: Identity,
    subject: Identity,
    node_key: P256SecretKey,
}

impl World {
    fn new() -> Self {
        let governor = Identity::new(0x10, vec![Identifier::from_bytes([0x77; 32])]);
        let operator = Identity::new(0x20, vec![Identifier::from_bytes([0x77; 32])]);
        let subject = Identity::new(0x30, vec![operator.id]);
        Self {
            governor,
            operator,
            subject,
            node_key: key(0x40),
        }
    }

    fn terms(&self, quotas: QuotaLimits) -> PublicRecordTerms {
        PublicRecordTerms {
            quotas,
            node_list: NodeListSource::Context {
                context_id: CONTEXT_ID.to_owned(),
                governor: self.governor.id,
            },
        }
    }

    /// The operator's binding of `node_key`, at the operator's inception.
    fn entry(&self, node_key: &P256SecretKey) -> NodeListEntry {
        let url = NodeUrl::new("wss://witness.example.com/scp/v1").unwrap();
        let mut binding = NodeBinding {
            operator: self.operator.id,
            node_key: point(node_key),
            url_hash: node_url_hash(&url),
            key_state_head: self.operator.inception.digest,
            operator_sig: [0; 64],
            possession_sig: [0; 64],
        };
        let digest = binding.digest();
        binding.operator_sig = sign(&self.operator.active, &digest);
        binding.possession_sig = sign(node_key, &digest);
        NodeListEntry {
            binding,
            url,
            free: true,
        }
    }

    /// A node list at `sequence`, anchored at the governor's inception and
    /// signed by `signer`.
    fn node_list(&self, sequence: u64, signer: &P256SecretKey) -> Vec<u8> {
        self.node_list_at(sequence, &self.governor.inception.digest, signer)
    }

    /// A node list at `sequence` naming the governor, anchored at `head` and
    /// signed by `signer`.
    fn node_list_at(&self, sequence: u64, head: &[u8; 32], signer: &P256SecretKey) -> Vec<u8> {
        let mut record = NodeListRecord {
            context_id: CONTEXT_ID.to_owned(),
            sequence,
            governor: self.governor.id,
            signing_key_state_head: *head,
            entries: vec![self.entry(&self.node_key)],
            signature: [0; 64],
        };
        record.signature = sign(signer, &record.digest().unwrap());
        encode_node_list_frame(&record).unwrap()
    }

    /// A conflict statement about the subject's two sequence-1 events,
    /// signed by `node_key`.
    fn conflict(&self, held: &Event, offered: &Event, node_key: &P256SecretKey) -> Vec<u8> {
        let mut statement = ConflictStatement {
            witness: derive_node_id(&point(node_key)).unwrap(),
            subject: self.subject.id,
            held_sequence: held.sequence,
            held_digest: held.digest,
            offered_sequence: offered.sequence,
            offered_digest: offered.digest,
            observed_at: 1_700_000_000,
            signature: [0; 64],
        };
        statement.signature = sign(node_key, &statement.signing_digest());
        encode_conflict_frame(&self.subject.id, &[statement]).unwrap()
    }
}

async fn start_node(terms: PublicRecordTerms) -> ApplicationNode<InMemoryStorage> {
    let custody = Arc::new(InMemoryKeyCustody::new());
    let dht_client = Arc::new(InMemoryDhtClient::new());
    let sign_fn =
        DidDht::<InMemoryDhtClient, scp_clock::SystemClock>::make_sign_fn(Arc::clone(&custody));
    let did_dht = DidDht::with_client_and_signer(dht_client, Arc::new(DidCache::new()), sign_fn);
    Node::start_for_testing(NodeConfig {
        bind_addr: Some(SocketAddr::from(([127, 0, 0, 1], 0))),
        dht: DhtMode::Production,
        public_records: terms,
        ..NodeConfig::defaults(
            Reach::Domain {
                domain: "records.example.com".to_owned(),
            },
            IdentitySource::Generate {
                custody,
                did_method: Arc::new(did_dht),
            },
            InMemoryStorage::new(),
            BlobStorageBackend::in_memory(),
        )
    })
    .await
    .expect("the node starts")
}

/// One WebSocket connection to a running node's listener.
struct Client {
    ws: WebSocketStream<MaybeTlsStream<TcpStream>>,
    next_ref: u32,
}

/// What a PUBLISH was answered with.
#[derive(Debug, PartialEq, Eq)]
enum Reply {
    Ok,
    Err(u16),
}

impl Client {
    async fn connect(node: &ApplicationNode<InMemoryStorage>) -> Self {
        let mut request = format!("ws://{}/", node.relay().bound_addr())
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {}", node.bridge_token_hex().as_str())
                .parse()
                .unwrap(),
        );
        let (ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();
        Self { ws, next_ref: 0 }
    }

    fn reference(&mut self) -> String {
        self.next_ref += 1;
        format!("r{}", self.next_ref)
    }

    async fn send(&mut self, message: &ClientMessage) {
        self.ws
            .send(Message::Binary(message.to_bytes().unwrap()))
            .await
            .unwrap();
    }

    async fn receive(&mut self) -> RelayMessage {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(10), self.ws.next())
                .await
                .expect("a reply within the timeout")
                .expect("the stream stays open")
                .expect("a well-formed frame");
            if let Message::Binary(bytes) = frame {
                return RelayMessage::from_bytes(&bytes).unwrap();
            }
        }
    }

    /// The reply to the request carrying `reference`, skipping deliveries.
    async fn reply(&mut self, reference: &str) -> Reply {
        loop {
            match self.receive().await {
                RelayMessage::Ok { ref_id, .. } if ref_id.as_deref() == Some(reference) => {
                    return Reply::Ok;
                }
                RelayMessage::Err { ref_id, code, .. } if ref_id.as_deref() == Some(reference) => {
                    return Reply::Err(code);
                }
                _ => {}
            }
        }
    }

    async fn publish_with(
        &mut self,
        routing_id: [u8; 32],
        lifetime: BlobLifetime,
        blob: Vec<u8>,
    ) -> Reply {
        let reference = self.reference();
        self.send(&ClientMessage::Publish {
            ref_id: Some(reference.clone()),
            routing_id,
            recipient_hint: None,
            lifetime,
            blob,
        })
        .await;
        self.reply(&reference).await
    }

    /// A PUBLISH carrying both `retain: true` and `blob_ttl: 3600`, which no
    /// `ClientMessage` can hold: the encoding of a retained PUBLISH with the
    /// `blob_ttl` pair appended and the map header raised by one.
    async fn publish_retain_and_ttl(&mut self, routing_id: [u8; 32], blob: Vec<u8>) -> Reply {
        let reference = self.reference();
        let mut bytes = ClientMessage::Publish {
            ref_id: Some(reference.clone()),
            routing_id,
            recipient_hint: None,
            lifetime: BlobLifetime::Retained,
            blob,
        }
        .to_bytes()
        .unwrap();
        // fixmap of five entries: op, ref, routing_id, retain, blob.
        assert_eq!(bytes[0], 0x85);
        bytes[0] = 0x86;
        bytes.extend_from_slice(b"\xa8blob_ttl\xcd\x0e\x10");
        self.ws.send(Message::Binary(bytes)).await.unwrap();
        self.reply(&reference).await
    }

    async fn retain(&mut self, routing_id: [u8; 32], blob: Vec<u8>) -> Reply {
        self.publish_with(routing_id, BlobLifetime::Retained, blob)
            .await
    }

    async fn ttl(&mut self, routing_id: [u8; 32], blob: Vec<u8>) -> Reply {
        self.publish_with(routing_id, BlobLifetime::Ttl(3600), blob)
            .await
    }

    /// The blobs a QUERY at `routing_id` is served, in served order.
    async fn query(&mut self, routing_id: [u8; 32]) -> Vec<Vec<u8>> {
        let reference = self.reference();
        self.send(&ClientMessage::Query {
            ref_id: Some(reference.clone()),
            routing_id,
            since: None,
            after_blob: None,
            limit: None,
        })
        .await;
        let mut blobs = Vec::new();
        loop {
            match self.receive().await {
                RelayMessage::Blob {
                    routing_id: at,
                    blob,
                    ..
                } if at == routing_id => blobs.push(blob),
                RelayMessage::Event { ref_id, .. } if ref_id.as_deref() == Some(&reference) => {
                    return blobs;
                }
                RelayMessage::Err { ref_id, code, .. } if ref_id.as_deref() == Some(&reference) => {
                    panic!("QUERY refused with {code}");
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------------------
// scp:did:
// ---------------------------------------------------------------------------

/// The did row: an inception that recomputes to the identifier is stored, an
/// extension whose predecessor the node holds is stored, a fork beside it is
/// kept as a divergent chain, and a frame opening on an event the node holds,
/// or on an event whose predecessor it does not hold, is refused with `4040`.
#[tokio::test]
async fn did_admits_logs_by_r10_and_keeps_every_held_chain() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    let routing = subject.did_routing();
    let fork_a = subject.key_state(7200, &subject.root);
    let fork_b = subject.key_state(10_800, &subject.root);

    // An extension before the node holds its predecessor.
    assert_eq!(
        client.retain(routing, subject.frame(&[&fork_a])).await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    let inception = subject.frame(&[&subject.inception]);
    assert_eq!(client.retain(routing, inception.clone()).await, Reply::Ok);
    // The inception again: its first event is one the node holds.
    assert_eq!(
        client.retain(routing, inception.clone()).await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client.retain(routing, subject.frame(&[&fork_a])).await,
        Reply::Ok
    );
    assert_eq!(
        client.retain(routing, subject.frame(&[&fork_b])).await,
        Reply::Ok
    );

    // Served in (`stored_at`, `blob_id`) order, so compare as sets.
    let mut served = client.query(routing).await;
    served.sort();
    let mut expected = vec![
        inception,
        subject.frame(&[&fork_a]),
        subject.frame(&[&fork_b]),
    ];
    expected.sort();
    assert_eq!(served, expected);
}

/// An inception served under an identifier it does not recompute to fails
/// R2's binding: `4040`, and the node stores nothing.
#[tokio::test]
async fn did_refuses_an_inception_under_another_identifier_with_4040() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let other = &world.operator;
    let units: Vec<&[u8]> = vec![world.subject.inception.unit.as_slice()];
    let frame = encode_key_event_frame(&other.id, 0, &units).unwrap();
    assert_eq!(
        client.retain(other.did_routing(), frame).await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert!(client.query(other.did_routing()).await.is_empty());
}

/// An event of the frame that fails R3, here a `KeyState` signed by a key
/// outside the root, refuses the whole frame with `4044`: the valid
/// inception before it is not stored either.
#[tokio::test]
async fn did_refuses_a_frame_with_an_r3_failure_with_4044() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    let forged = subject.key_state(7200, &world.node_key);
    assert_eq!(
        client
            .retain(
                subject.did_routing(),
                subject.frame(&[&subject.inception, &forged])
            )
            .await,
        Reply::Err(code::KEY_EVENT_ILLEGAL)
    );
    assert!(client.query(subject.did_routing()).await.is_empty());
}

// ---------------------------------------------------------------------------
// scp:svc:
// ---------------------------------------------------------------------------

/// The svc row: a record signed by the key the held log designates is
/// stored, a higher sequence replaces it, and a record of an identity whose
/// log the node does not hold, one signed by another key, or one the
/// selection would not keep is refused with `4040`.
#[tokio::test]
async fn svc_admits_the_designated_key_and_keeps_the_highest_sequence() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    let routing = routing_id(RoutingKind::ServiceRecord, &subject.id);

    // No log held yet.
    assert_eq!(
        client
            .retain(routing, subject.service_record(1, &subject.active))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client
            .retain(subject.did_routing(), subject.frame(&[&subject.inception]))
            .await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, subject.service_record(1, &subject.active))
            .await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, subject.service_record(2, &subject.active))
            .await,
        Reply::Ok
    );
    // The root key is not the designated service key.
    assert_eq!(
        client
            .retain(routing, subject.service_record(3, &subject.root))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    // Sequence 1 again: the selection keeps sequence 2 in its place.
    assert_eq!(
        client
            .retain(routing, subject.service_record(1, &subject.active))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client.query(routing).await,
        vec![subject.service_record(2, &subject.active)]
    );
}

// ---------------------------------------------------------------------------
// scp:nls:
// ---------------------------------------------------------------------------

/// The nls row: a record the governor's `#active` at
/// `signing_key_state_head` signs is stored, a higher sequence replaces it,
/// and a record signed by another key is refused with `4040`.
#[tokio::test]
async fn nls_admits_the_governor_attribution_key_and_keeps_the_highest_sequence() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let governor = &world.governor;
    let routing = node_list_routing_id(CONTEXT_ID);

    assert_eq!(
        client
            .retain(
                governor.did_routing(),
                governor.frame(&[&governor.inception])
            )
            .await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, world.node_list(1, &governor.active))
            .await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, world.node_list(2, &governor.active))
            .await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, world.node_list(3, &governor.root))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client
            .retain(routing, world.node_list(1, &governor.active))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client.query(routing).await,
        vec![world.node_list(2, &governor.active)]
    );
}

/// `03-identity.md` §3.10.10 and the nls row: the key is the `#active` the
/// held governor chain names at `signing_key_state_head`, not the head's.
/// After a rotation, the inception's `#active` signing at the inception is
/// admitted, the rotated key signing at the inception is refused with
/// `4040`, and the rotated key signing at the rotation is admitted.
#[tokio::test]
async fn nls_admits_the_key_the_held_governor_chain_names_at_signing_key_state_head() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let governor = &world.governor;
    let routing = node_list_routing_id(CONTEXT_ID);
    let successor = key(0x1A);
    let rotation = governor.replace_active(&successor, KeyCondition::Superseded);

    assert_eq!(
        client
            .retain(
                governor.did_routing(),
                governor.frame(&[&governor.inception, &rotation])
            )
            .await,
        Reply::Ok
    );
    let inception = governor.inception.digest;
    assert_eq!(
        client
            .retain(routing, world.node_list_at(1, &inception, &governor.active))
            .await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, world.node_list_at(2, &inception, &successor))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client
            .retain(routing, world.node_list_at(2, &rotation.digest, &successor))
            .await,
        Reply::Ok
    );
    assert_eq!(
        client.query(routing).await,
        vec![
            world.node_list_at(1, &inception, &governor.active),
            world.node_list_at(2, &rotation.digest, &successor),
        ]
    );
}

/// The nls row reads "the governor key state the node holds": with no
/// key-event log of the governor held, and another identity's log held, a
/// record its governor's `#active` signs is refused with `4040`, the code
/// the `scp:svc:` row uses where the node holds no log of the identity.
#[tokio::test]
async fn nls_refuses_a_record_with_4040_when_no_governor_log_is_held() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let operator = &world.operator;
    let routing = node_list_routing_id(CONTEXT_ID);

    assert_eq!(
        client
            .retain(
                operator.did_routing(),
                operator.frame(&[&operator.inception])
            )
            .await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, world.node_list(1, &world.governor.active))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert!(client.query(routing).await.is_empty());
}

/// A record naming the governor but signed under another identity is
/// refused with `4040`, both where it anchors at the other identity's own
/// event (a head off every governor chain) and where it anchors at the
/// governor's inception (a signature the governor's `#active` did not make),
/// though the node holds both identities' logs.
#[tokio::test]
async fn nls_refuses_a_record_under_another_identity_with_4040() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let (governor, operator) = (&world.governor, &world.operator);
    let routing = node_list_routing_id(CONTEXT_ID);

    for identity in [governor, operator] {
        assert_eq!(
            client
                .retain(
                    identity.did_routing(),
                    identity.frame(&[&identity.inception])
                )
                .await,
            Reply::Ok
        );
    }
    assert_eq!(
        client
            .retain(
                routing,
                world.node_list_at(1, &operator.inception.digest, &operator.active)
            )
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client
            .retain(
                routing,
                world.node_list_at(1, &governor.inception.digest, &operator.active)
            )
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert!(client.query(routing).await.is_empty());
}

/// The nls row: "The node drops each record whose signing key a later
/// governor event marks `Compromised`." A record admitted under the
/// inception's `#active` is deleted once the governor's next event marks
/// that key `Compromised`, and the same record is then refused with `4040`.
#[tokio::test]
async fn nls_drops_a_record_after_a_later_compromised_event() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let governor = &world.governor;
    let routing = node_list_routing_id(CONTEXT_ID);
    let record = world.node_list(1, &governor.active);

    assert_eq!(
        client
            .retain(
                governor.did_routing(),
                governor.frame(&[&governor.inception])
            )
            .await,
        Reply::Ok
    );
    assert_eq!(client.retain(routing, record.clone()).await, Reply::Ok);
    assert_eq!(client.query(routing).await, vec![record.clone()]);

    let compromise = governor.replace_active(&key(0x1B), KeyCondition::Compromised);
    assert_eq!(
        client
            .retain(governor.did_routing(), governor.frame(&[&compromise]))
            .await,
        Reply::Ok
    );
    assert!(client.query(routing).await.is_empty());
    assert_eq!(
        client.retain(routing, record).await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
}

// ---------------------------------------------------------------------------
// scp:wcf:
// ---------------------------------------------------------------------------

/// The wcf row: a statement signed by a node key the configured node list
/// binds to an operator the subject names as witness, over two heads on
/// chains the node holds, is stored; one signed by an unbound node key is
/// refused with `4040`.
#[tokio::test]
async fn wcf_admits_a_bound_witness_statement_over_held_heads() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    let fork_a = subject.key_state(7200, &subject.root);
    let fork_b = subject.key_state(10_800, &subject.root);
    for (identity, events) in [
        (&world.governor, vec![&world.governor.inception]),
        (&world.operator, vec![&world.operator.inception]),
        (subject, vec![&subject.inception]),
        (subject, vec![&fork_a]),
        (subject, vec![&fork_b]),
    ] {
        assert_eq!(
            client
                .retain(identity.did_routing(), identity.frame(&events))
                .await,
            Reply::Ok
        );
    }
    let routing = routing_id(RoutingKind::ConflictStatements, &subject.id);
    let statement = world.conflict(&fork_a, &fork_b, &world.node_key);

    // Before the node holds the node list, no node key is bound.
    assert_eq!(
        client.retain(routing, statement.clone()).await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(
        client
            .retain(
                node_list_routing_id(CONTEXT_ID),
                world.node_list(1, &world.governor.active)
            )
            .await,
        Reply::Ok
    );
    assert_eq!(client.retain(routing, statement.clone()).await, Reply::Ok);
    assert_eq!(
        client
            .retain(routing, world.conflict(&fork_a, &fork_b, &key(0x50)))
            .await,
        Reply::Err(code::DID_RECORD_REJECTED)
    );
    assert_eq!(client.query(routing).await, vec![statement]);
}

// ---------------------------------------------------------------------------
// retain, after_blob
// ---------------------------------------------------------------------------

/// A retained kind published with `blob_ttl` alone is refused with `4003`.
#[tokio::test]
async fn a_retained_kind_without_retain_is_refused_with_4003() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    assert_eq!(
        client
            .ttl(subject.did_routing(), subject.frame(&[&subject.inception]))
            .await,
        Reply::Err(code::INVALID_FIELD)
    );
    assert!(client.query(subject.did_routing()).await.is_empty());
}

/// `retain` on a blob of no retained kind is refused with `4003`.
#[tokio::test]
async fn retain_on_another_kind_is_refused_with_4003() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    assert_eq!(
        client
            .retain([0x42; 32], b"an opaque context blob".to_vec())
            .await,
        Reply::Err(code::INVALID_FIELD)
    );
    assert!(client.query([0x42; 32]).await.is_empty());
}

/// `retain` together with `blob_ttl` is refused with `4003` when the frame
/// decodes, echoing the PUBLISH's `ref`, and nothing is stored.
#[tokio::test]
async fn retain_with_blob_ttl_is_refused_with_4003() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    assert_eq!(
        client
            .publish_retain_and_ttl(subject.did_routing(), subject.frame(&[&subject.inception]))
            .await,
        Reply::Err(code::INVALID_FIELD)
    );
    assert!(client.query(subject.did_routing()).await.is_empty());
}

/// A QUERY carrying `after_blob` without `since` is refused with `4002`.
#[tokio::test]
async fn after_blob_without_since_is_refused_with_4002() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits::UNBOUNDED)).await;
    let mut client = Client::connect(&node).await;
    client
        .send(&ClientMessage::Query {
            ref_id: Some("q".to_owned()),
            routing_id: [0x42; 32],
            since: None,
            after_blob: Some([0x01; 32]),
            limit: None,
        })
        .await;
    assert_eq!(client.reply("q").await, Reply::Err(code::MISSING_FIELD));
}

// ---------------------------------------------------------------------------
// quota classes
// ---------------------------------------------------------------------------

/// A full retained-records class refuses the write past it with `5001` and
/// leaves the TTL class at the same routing id writable.
#[tokio::test]
async fn a_full_retained_class_refuses_with_5001_and_leaves_ttl_writes() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits {
        retained_public_records: QuotaLimit::Blobs(1),
        ..QuotaLimits::UNBOUNDED
    }))
    .await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    let routing = subject.did_routing();
    assert_eq!(
        client
            .retain(routing, subject.frame(&[&subject.inception]))
            .await,
        Reply::Ok
    );
    let fork = subject.key_state(7200, &subject.root);
    assert_eq!(
        client.retain(routing, subject.frame(&[&fork])).await,
        Reply::Err(code::STORAGE_FULL)
    );
    assert_eq!(client.ttl(routing, b"a ttl blob".to_vec()).await, Reply::Ok);
    assert_eq!(client.query(routing).await.len(), 2);
}

/// A full TTL class refuses the write past it with `5001` at that routing id
/// only, and leaves retained writes at it admitted.
#[tokio::test]
async fn a_full_ttl_class_refuses_with_5001_and_leaves_retained_writes() {
    let world = World::new();
    let node = start_node(world.terms(QuotaLimits {
        ttl_blobs: QuotaLimit::Blobs(1),
        ..QuotaLimits::UNBOUNDED
    }))
    .await;
    let mut client = Client::connect(&node).await;
    let subject = &world.subject;
    let routing = subject.did_routing();
    assert_eq!(client.ttl(routing, b"first".to_vec()).await, Reply::Ok);
    assert_eq!(
        client.ttl(routing, b"second".to_vec()).await,
        Reply::Err(code::STORAGE_FULL)
    );
    assert_eq!(
        client.ttl([0x43; 32], b"elsewhere".to_vec()).await,
        Reply::Ok
    );
    assert_eq!(
        client
            .retain(routing, subject.frame(&[&subject.inception]))
            .await,
        Reply::Ok
    );
    assert_eq!(client.query(routing).await.len(), 2);
}
