//! Spec 25 §25.26 and §25.29 fixtures shared by the scp-kel integration
//! tests and by scp-client-wasm's cross-target known-answer test.
//!
//! Every hex constant is copied from `.docs/specs/25-test-vectors.md` and
//! names its vector; none is produced by this crate. The preimage builders
//! assemble each vector's fields from the values that vector prints.

use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use scp_did::{
    CommitmentEntry, CustodyType, FixedCommitment, Identifier, KeyAlgorithm, KeyCondition,
    KeyEntry, KeyRole,
};
use scp_kel::{
    CommitmentRolloverFields, Continuation, EventPreimage, EventUnit, InceptionFields,
    KeyStateFields, KeyStateSnapshot, NamedSigner, ReadUnit, SignatureForm, SignerGroup,
    decode_event, decode_preimage, encode_preimage, prerotation_commitment,
};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Spec 25 Vector 41's preimage (364 bytes, separator included).
pub const V41_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a010000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000100",
    "00000001010000000000000001033b1cac23f45cf1cdfdf0b32f8f777b99166c",
    "1b69649c2295b1517883d47f3027000000010000000100000002033b1cac23f4",
    "5cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30270101000000",
    "000000000001010223702a648232f2d00713de9289753c2fbd4c4efa7e1e3390",
    "5e3723a412b20aea02010000000000000000010100000001575d27a9d81af87b",
    "505b07f00c00031382c4ca1f3b9bf03e874f25179e21bcae00000e1002000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a51",
    "5de80a3e43eb010100000001",
);
/// Spec 25 Vector 41's preimage digest D.
pub const V41_DIGEST: &str = "fcd42118a68664c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763";
/// Spec 25 Vector 41's identifier.
pub const V41_IDENTIFIER: &str = "d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3";
/// Spec 25 Vector 41's routing id, `SHA-256("scp:did:" || identifier)`.
pub const V41_ROUTING_DID: &str =
    "4102ed70d1c4b106466149a7d129630c11a20554683ae012fdffa56341d1c323";
/// Spec 25 Vector 41's cosigned-head routing id, `"scp:wit:"`.
pub const V41_ROUTING_WIT: &str =
    "9657e71d4386119cea08ca7633e0ebf1a3e0accb144ac5647e6b55e8d76fd7e2";
/// Spec 25 Vector 41's conflict-statement routing id, `"scp:wcf:"`.
pub const V41_ROUTING_WCF: &str =
    "e80d6af5d9d96d80a1fb45e46201be77d6b9742f4beb250b85418db0cd9e7e71";
/// Spec 25 Vector 41's service-record routing id, `"scp:svc:"`, which is
/// Vector 48's address.
pub const V41_ROUTING_SVC: &str =
    "933ebf03763a5098fcf7424eec522b574753d08ad7bd4d660adfbe683e2a012c";
/// Spec 25 Vector 48's address, `SHA-256("scp:svc:" || identifier)`.
pub const V48_ADDRESS: &str = "933ebf03763a5098fcf7424eec522b574753d08ad7bd4d660adfbe683e2a012c";
/// Spec 25 Vector 48's identifier, which is Vector 41's.
pub const V48_IDENTIFIER: &str = "d5adb473c01283dc9a7e7e998c1d312b3a353acf4863c13fe77efe304ad38bb3";

/// Spec 25 Vector 41's root-set member 0.
pub const V41_ROOT: &str = "033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027";
/// Spec 25 Vector 47b's point, §25.2's secondary key: Vector 41's `#active`
/// key.
pub const V41_ACTIVE: &str = "0223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aea";
/// Spec 25 Vector 41's witness, the `NodeId` of §25.2's secondary key.
pub const V41_WITNESS: &str = "575d27a9d81af87b505b07f00c00031382c4ca1f3b9bf03e874f25179e21bcae";

/// Spec 25 Vector 41's raw-form indexed signature over D (64 bytes).
pub const V41_SIGNATURE: &str = concat!(
    "0f53fa982d5dedc4e0f7b0c0216098ee17e8fa0e0c42609a976c4b1d444a9ba1",
    "5f6fe6f9cbc80d4f37cf39e620b9ae7ff4e022e3810beab421655170ec4ddd07",
);

/// Spec 25 Vector 42's preimage (364 bytes): Vector 41's with form `0x02`.
pub const V42_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a010000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000100",
    "00000001020000000000000001033b1cac23f45cf1cdfdf0b32f8f777b99166c",
    "1b69649c2295b1517883d47f3027000000010000000100000002033b1cac23f4",
    "5cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f30270101000000",
    "000000000001010223702a648232f2d00713de9289753c2fbd4c4efa7e1e3390",
    "5e3723a412b20aea02010000000000000000010100000001575d27a9d81af87b",
    "505b07f00c00031382c4ca1f3b9bf03e874f25179e21bcae00000e1002000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a51",
    "5de80a3e43eb010100000001",
);
/// Spec 25 Vector 42's preimage digest D.
pub const V42_DIGEST: &str = "386f6c642383574c5a6cb2910158aa41619e2c91a0058b5125f9c70b7079dadc";
/// Spec 25 Vector 42's identifier.
pub const V42_IDENTIFIER: &str = "43394f9e8833f2a4dac9604f929c2a6bb13219e5f451d9addedc335d3545820c";
/// Spec 25 Vector 42's challenge bytes, `"SCP-KEY-EVENT-V1:" || D` (49 bytes).
pub const V42_CHALLENGE_BYTES: &str = concat!(
    "5343502d4b45592d4556454e542d56313a386f6c642383574c5a6cb2910158aa",
    "41619e2c91a0058b5125f9c70b7079dadc",
);
/// Spec 25 Vector 42's challenge, unpadded base64url as clientDataJSON
/// carries it.
pub const V42_CHALLENGE: &str =
    "U0NQLUtFWS1FVkVOVC1WMTo4b2xkI4NXTFpsspEBWKpBYZ4skaAFi1El-ccLcHna3A";
/// Spec 25 Vector 42's authenticatorData (37 bytes): rpIdHash, flags 0x05,
/// signCount 0.
pub const V42_AUTHENTICATOR_DATA: &str = concat!(
    "aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d11689d76",
    "0500000000",
);
/// Spec 25 Vector 42's clientDataJSON (155 bytes), as its printed text.
pub const V42_CLIENT_DATA_JSON: &str = concat!(
    r#"{"type":"webauthn.get","challenge":"#,
    r#""U0NQLUtFWS1FVkVOVC1WMTo4b2xkI4NXTFpsspEBWKpBYZ4skaAFi1El-ccLcHna3A","#,
    r#""origin":"https://ctx.network","crossOrigin":false}"#,
);
/// Spec 25 Vector 42's clientDataJSON bytes, as printed in hex.
pub const V42_CLIENT_DATA_JSON_HEX: &str = concat!(
    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e67",
    "65223a2255304e514c55744657533146566b564f564331574d546f346232786b",
    "49344e585446707373704542574b7042595a34736b6141466931456c2d63634c",
    "63486e613341222c226f726967696e223a2268747470733a2f2f6374782e6e65",
    "74776f726b222c2263726f73734f726967696e223a66616c73657d",
);
/// Spec 25 Vector 42's `SHA-256(clientDataJSON)`.
pub const V42_CLIENT_DATA_HASH: &str =
    "035e3fb00ac00e96b7003f45c4acb263d0d751d76e1ee9a5d146f21168627420";
/// Spec 25 Vector 42's relying-party identifier, whose SHA-256 is the
/// `rpIdHash` that opens its authenticatorData.
pub const V42_RP_ID: &str = "ctx.network";
/// Spec 25 Vector 42's signed message (69 bytes),
/// `authenticatorData || SHA-256(clientDataJSON)`.
pub const V42_SIGNED_MESSAGE: &str = concat!(
    "aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d11689d76",
    "0500000000035e3fb00ac00e96b7003f45c4acb263d0d751d76e1ee9a5d146f2",
    "1168627420",
);
/// Spec 25 Vector 42's ECDSA message digest,
/// `SHA-256(authenticatorData || SHA-256(clientDataJSON))`.
pub const V42_SIGNED_DIGEST: &str =
    "201ce67c1b0826ae8a57b5649b8893bc1ff95e49ba532baba6e6ae9d106b5bce";
/// Spec 25 Vector 42's 64-byte low-s signature.
pub const V42_SIGNATURE: &str = concat!(
    "56594bcea202cce44d7a4587ad15f5e2629a42a11b2f68b99c7833c33ac5143a",
    "739f7439120872390466883124368fa5200b86df15e25155f9746492320f3225",
);
/// Spec 25 Vector 42's assertion-form indexed signature (264 bytes).
pub const V42_INDEXED_SIGNATURE: &str = concat!(
    "00000025aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d",
    "11689d7605000000000000009b7b2274797065223a22776562617574686e2e67",
    "6574222c226368616c6c656e6765223a2255304e514c55744657533146566b56",
    "4f564331574d546f346232786b49344e585446707373704542574b7042595a34",
    "736b6141466931456c2d63634c63486e613341222c226f726967696e223a2268",
    "747470733a2f2f6374782e6e6574776f726b222c2263726f73734f726967696e",
    "223a66616c73657d56594bcea202cce44d7a4587ad15f5e2629a42a11b2f68b9",
    "9c7833c33ac5143a739f7439120872390466883124368fa5200b86df15e25155",
    "f9746492320f3225",
);

/// Spec 25 Vector 47a's point, §25.2's tertiary key.
pub const V47A_POINT: &str = "026fc6523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a670";
/// Spec 25 Vector 47a's commitment.
pub const V47A_COMMITMENT: &str =
    "421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a515de80a3e43eb";
/// Spec 25 Vector 47b's point, §25.2's secondary key.
pub const V47B_POINT: &str = "0223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aea";
/// Spec 25 Vector 47b's commitment.
pub const V47B_COMMITMENT: &str =
    "6ae81c4de7106cbed412d5061d235b5d41f648e69e8be1077224cbafd5a6cfcc";

/// Spec 25 Vector 50's preimage (320 bytes, separator included).
pub const V50_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a02d5adb473c01283dc9a7e7e998c1d",
    "312b3a353acf4863c13fe77efe304ad38bb30000000000000001fcd42118a686",
    "64c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763000000000100",
    "000000010100000000000000000000000100000002033b1cac23f45cf1cdfdf0",
    "b32f8f777b99166c1b69649c2295b1517883d47f302701010000000000000000",
    "01010223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412",
    "b20aea02010000000000000000010100000001575d27a9d81af87b505b07f00c",
    "00031382c4ca1f3b9bf03e874f25179e21bcae00001c20020000000000000000",
    "00000000000000000000000000000000000000000000000000000001caf80a0c",
    "2332b8a2e1454c355f84142f34d24e92b45db3c0948d90adbd76248800000000",
);
/// Spec 25 Vector 50's sealed event digest.
pub const V50_SEALED_DIGEST: &str =
    "1c7f9fb5d17d8773900e072f0fea733baf4fc5e2ce240107df69072646e775a2";
/// Spec 25 Vector 50's key-event seal.
pub const V50_SEAL: &str = "caf80a0c2332b8a2e1454c355f84142f34d24e92b45db3c0948d90adbd762488";
/// Spec 25 Vector 50's preimage digest.
pub const V50_DIGEST: &str = "e611d466860ac8a09de2b4ce6b608c9c5b9d624429e8b250babbb7506004738e";
/// Spec 25 Vector 50's raw-form indexed signature, by Vector 41's root
/// member 0.
pub const V50_SIGNATURE: &str = concat!(
    "0a596e82f96824f07c0189c11f6967d158eb5dadb71752ba57f79c7649392fad",
    "0dfd431fbbda2e184f741318e5d4bc17b52648159d0f3c4e56a0d9f22aaa4b7a",
);

/// Spec 25 Vector 51's nine keys in table order: root members 0 to 7, then
/// `#active`. Entry `i` carries custody byte `i + 1`.
pub const V51_KEYS: [&str; 9] = [
    "02b86554ca49a9bb429e555454b0e81c69242defbed440f7dde65e3fd8aabdf33d",
    "02f0c2c400b1a26dc597eba50c752ba083ee6f3add7cdbf8049e3024b6c3851e87",
    "02c3d4e2a5c319b9869bef14077411afe34743396ee96376b9e07ce907eceb428b",
    "0278210550385ce3b0449d868909adf411a9531e886d4909063453347d58c2f437",
    "028669c107174e5219e9a66b15c6d2805610135b853eafad7e0c6f513d4f4b02b7",
    "03849d444571033da6292bc75f5561eeed6fc4ee8787400ac6ce9daed756203614",
    "03b8d687792d2f1ccbe5cca25609a949fa39ef2c3c2b50c48aeb0ee954c2b96635",
    "026656dfeb9ed86ebd1e0b2740d52e9a8f4d69fef61d4157f254dce2fbcd3d2144",
    "02db931079de36ba5f17d6450a9e26378b05fc89704c32e6f9bc2ea14597fee282",
];
/// Spec 25 Vector 51's pre-rotation key.
pub const V51_PREROTATION: &str =
    "03f559598152c9e3b313ce1f8c4c606ba94de210265c85490239af871bbadfd52c";
/// Spec 25 Vector 51's witness, the `NodeId` of §25.2's reference key.
pub const V51_WITNESS: &str = "e77d53354271e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f15610";
/// Spec 25 Vector 51's inception preimage (910 bytes, separator included).
pub const V51_INCEPTION_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a010000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000100",
    "0000000101000000000000000802b86554ca49a9bb429e555454b0e81c69242d",
    "efbed440f7dde65e3fd8aabdf33d02f0c2c400b1a26dc597eba50c752ba083ee",
    "6f3add7cdbf8049e3024b6c3851e8702c3d4e2a5c319b9869bef14077411afe3",
    "4743396ee96376b9e07ce907eceb428b0278210550385ce3b0449d868909adf4",
    "11a9531e886d4909063453347d58c2f437028669c107174e5219e9a66b15c6d2",
    "805610135b853eafad7e0c6f513d4f4b02b703849d444571033da6292bc75f55",
    "61eeed6fc4ee8787400ac6ce9daed75620361403b8d687792d2f1ccbe5cca256",
    "09a949fa39ef2c3c2b50c48aeb0ee954c2b96635026656dfeb9ed86ebd1e0b27",
    "40d52e9a8f4d69fef61d4157f254dce2fbcd3d21440000000100000001000000",
    "0902b86554ca49a9bb429e555454b0e81c69242defbed440f7dde65e3fd8aabd",
    "f33d01010000000000000000010102f0c2c400b1a26dc597eba50c752ba083ee",
    "6f3add7cdbf8049e3024b6c3851e8701010000000000000000020102c3d4e2a5",
    "c319b9869bef14077411afe34743396ee96376b9e07ce907eceb428b01010000",
    "00000000000003010278210550385ce3b0449d868909adf411a9531e886d4909",
    "063453347d58c2f437010100000000000000000401028669c107174e5219e9a6",
    "6b15c6d2805610135b853eafad7e0c6f513d4f4b02b701010000000000000000",
    "050103849d444571033da6292bc75f5561eeed6fc4ee8787400ac6ce9daed756",
    "20361401010000000000000000060103b8d687792d2f1ccbe5cca25609a949fa",
    "39ef2c3c2b50c48aeb0ee954c2b96635010100000000000000000701026656df",
    "eb9ed86ebd1e0b2740d52e9a8f4d69fef61d4157f254dce2fbcd3d2144010100",
    "00000000000000080102db931079de36ba5f17d6450a9e26378b05fc89704c32",
    "e6f9bc2ea14597fee28202010000000000000000090100000001e77d53354271",
    "e4c1c3c319cf7b5cfcc23be431c2ec795d5b6ecf549355f1561000000e100200",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000001000000016644cc0e3ef3eae7dd1274d305e48fb593acce69ed4e4cef",
    "a9c63683174ed0ac010100000001",
);
/// Spec 25 Vector 51's inception digest.
pub const V51_INCEPTION_DIGEST: &str =
    "5d23919df0fa99fb5076951e9b98aba559d7fb0dcab48cb0bbc40fe5df4ff568";
/// Spec 25 Vector 51's identifier.
pub const V51_IDENTIFIER: &str = "ccf037a6ebea7cc7bbe5f45f1390916a32f6658db9ee918dae9782dae760fcba";
/// Spec 25 Vector 51's routing id.
pub const V51_ROUTING_DID: &str =
    "52bdf6be43c50e63600032a63e5485671333af3ca412171a65e5130afb296127";
/// Spec 25 Vector 51's preimage (603 bytes, separator included).
pub const V51_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a02ccf037a6ebea7cc7bbe5f45f1390",
    "916a32f6658db9ee918dae9782dae760fcba00000000000000015d23919df0fa",
    "99fb5076951e9b98aba559d7fb0dcab48cb0bbc40fe5df4ff568000000000100",
    "00000001010000000000000000000000010000000902b86554ca49a9bb429e55",
    "5454b0e81c69242defbed440f7dde65e3fd8aabdf33d01010000000000000000",
    "010102f0c2c400b1a26dc597eba50c752ba083ee6f3add7cdbf8049e3024b6c3",
    "851e8701010000000000000000020102c3d4e2a5c319b9869bef14077411afe3",
    "4743396ee96376b9e07ce907eceb428b01010000000000000000030102782105",
    "50385ce3b0449d868909adf411a9531e886d4909063453347d58c2f437010100",
    "000000000000000401028669c107174e5219e9a66b15c6d2805610135b853eaf",
    "ad7e0c6f513d4f4b02b701010000000000000000050103849d444571033da629",
    "2bc75f5561eeed6fc4ee8787400ac6ce9daed756203614010100000000000000",
    "00060103b8d687792d2f1ccbe5cca25609a949fa39ef2c3c2b50c48aeb0ee954",
    "c2b96635010100000000000000000701026656dfeb9ed86ebd1e0b2740d52e9a",
    "8f4d69fef61d4157f254dce2fbcd3d214401010000000000000000080102db93",
    "1079de36ba5f17d6450a9e26378b05fc89704c32e6f9bc2ea14597fee2820201",
    "0000000000000000090100000001e77d53354271e4c1c3c319cf7b5cfcc23be4",
    "31c2ec795d5b6ecf549355f1561000001c200200000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000",
);
/// Spec 25 Vector 51's preimage digest.
pub const V51_DIGEST: &str = "4c41e671344680f1bbc389346617366f56d67c3c3a4461a40bb964b92ffb98cb";
/// Spec 25 Vector 51's `KeyState` raw-form indexed signature.
pub const V51_SIGNATURE: &str = concat!(
    "e06a292f1bb82840708833e72107fee5e97c7344feb53fd37e0a963351c87e9d",
    "7de07af8245b601ad02ef7543bb55769cb281609cc4d63270c7570535c1bb747",
);

/// Spec 25 Vector 51's inception signature: root member 0, raw form, over
/// the inception digest.
pub const V51_INCEPTION_SIGNATURE: &str = concat!(
    "335b62a56c8a0b2c5da1e467bf074138cdf829115e7aeb50a0725fcb394a797b",
    "460d3e8a0d48d189c881befb4338e546459a8b89c7d0015b1967f62bbfbcb00f",
);

/// Spec 25 Vector 68's preimage (161 bytes): Vector 53's rollover with
/// field 12 the one byte `0x00`.
pub const V68_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a03d5adb473c01283dc9a7e7e998c1d",
    "312b3a353acf4863c13fe77efe304ad38bb30000000000000001fcd42118a686",
    "64c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763000000000100",
    "00000001000000000101000000010100000001026fc6523b7b1e22ff3fbce874",
    "0cfbb7cbc816501864bf40f683db69c860d1a670000000000000000000000000",
    "00",
);
/// Spec 25 Vector 68's preimage digest.
pub const V68_DIGEST: &str = "94957e48500142f337a8e91476e95b5cefbc0c5fe830848971417b67282ef582";
/// Spec 25 Vector 68's reveal signature, by the revealed key.
pub const V68_REVEAL_SIGNATURE: &str = concat!(
    "d784e57af2600d34e29d5cfdb1bf3c3ff49286588997dc01b7875fd5a2d66a4e",
    "1c9b29985ed8b296943698fd802d61b7ef30ca129a7dc45431ee058ab62ff7b0",
);
/// Spec 25 Vector 68's standing-root signature, by Vector 41's root member 0.
pub const V68_ROOT_SIGNATURE: &str = concat!(
    "c11b36fd78eff5615c9f50510a1d06e0881aa38d42dc95d9cb774461683cb790",
    "69436c753a77d6e51b82afa7b91429fa26c393c6e2d3172f895bc62ad203599f",
);

/// Spec 25 Vector 69's preimage (333 bytes).
pub const V69_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a02d5adb473c01283dc9a7e7e998c1d",
    "312b3a353acf4863c13fe77efe304ad38bb30000000000000001fcd42118a686",
    "64c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763000000000100",
    "000000010100000000000000000000000100000003033b1cac23f45cf1cdfdf0",
    "b32f8f777b99166c1b69649c2295b1517883d47f302701010000000000000000",
    "010103111dadf2081befb113b3e43ce763df7d1c34b64f01778fb108087894ac",
    "ae761c0201000000000000000001010223702a648232f2d00713de9289753c2f",
    "bd4c4efa7e1e33905e3723a412b20aea02040000000000000001010100000001",
    "575d27a9d81af87b505b07f00c00031382c4ca1f3b9bf03e874f25179e21bcae",
    "00000e1002000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000",
);
/// Spec 25 Vector 69's preimage digest.
pub const V69_DIGEST: &str = "a0aa6350c98715abc80bad900de1c7149504158114ba5ef53b6563a8b5c209d5";
/// Spec 25 Vector 69's installed `#active` key.
pub const V69_ACTIVE: &str = "03111dadf2081befb113b3e43ce763df7d1c34b64f01778fb108087894acae761c";
/// Spec 25 Vector 69's root signature, by Vector 41's root member 0.
pub const V69_ROOT_SIGNATURE: &str = concat!(
    "7bb039c6433e786100e5b63a0f4843f0e0c46d688b8a16f707baf5c7e402847b",
    "5025e6c36e9824e5b680158a67a2fdad943653246a419f506ae425c6a8f4353a",
);

/// Spec 25 Vector 53's preimage (203 bytes): a `CommitmentRollover` on
/// Vector 41 with a reveal group and a standing-root group.
pub const V53_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a03d5adb473c01283dc9a7e7e998c1d",
    "312b3a353acf4863c13fe77efe304ad38bb30000000000000001fcd42118a686",
    "64c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763000000000100",
    "00000001000000000101000000010100000001026fc6523b7b1e22ff3fbce874",
    "0cfbb7cbc816501864bf40f683db69c860d1a670000000000000000000000000",
    "0100000001bf945a74e57e4b861cdba9a78df32004adc443e983e957b9aa9749",
    "ade24be4bd010100000001",
);
/// Spec 25 Vector 53's preimage digest.
pub const V53_DIGEST: &str = "95c08ab437ecd8ec02999d65aa65accb3a021a13905ee74e1b3392556fe3b7f8";
/// Spec 25 Vector 53's signature field (128 bytes): the reveal group's
/// signature, then the standing-root group's.
pub const V53_SIGNATURE_FIELD: &str = concat!(
    "b9d4c7fda9d729d46cec50231a28f04c039963007ae5782810ceca6d5876b723",
    "1c3829fbb118d4705a75008325dbdc0b6778b4be50b8b85a338cd6fe6eb89b68",
    "21c8199381fa3f983ec7dfe1fc1c876c31983bb4ee53aa7c9b625b556d099afc",
    "4b0bc382ec2712be91acdce76b36b878dfa3cb146e899ffd71675c7a05a3942b",
);

/// Spec 25 Vector 54's preimage (507 bytes): a `RootRecovery{CoSigns}` on
/// Vector 41 with the reveal, K′ and standing-root groups.
pub const V54_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a04d5adb473c01283dc9a7e7e998c1d",
    "312b3a353acf4863c13fe77efe304ad38bb30000000000000001fcd42118a686",
    "64c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763010000000100",
    "0000000100000000010000000001010000000101000000010100000001026fc6",
    "523b7b1e22ff3fbce8740cfbb7cbc816501864bf40f683db69c860d1a6700000",
    "0001034c3e84e8da62f05b0a280d5a0426e24bde13c6fa023c567333bece3bc1",
    "497c53000000010000000100000004034c3e84e8da62f05b0a280d5a0426e24b",
    "de13c6fa023c567333bece3bc1497c53010100000000000000000101026188be",
    "77992cb98024f995da162f844f534e4a7f8fca8dc7b1d0cb4b54ce4c64020100",
    "000000000000000101033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c",
    "2295b1517883d47f30270102000000000000000001010223702a648232f2d007",
    "13de9289753c2fbd4c4efa7e1e33905e3723a412b20aea020200000000000000",
    "00010100000001575d27a9d81af87b505b07f00c00031382c4ca1f3b9bf03e87",
    "4f25179e21bcae00000e10020000000000000000000000000000000000000000",
    "00000000000000000000000000000000010000000141def207e7438655edf276",
    "6aa2fe0c96ef5f898233fb5ba16c56a3f7765aa8bd010100000001",
);
/// Spec 25 Vector 54's preimage digest.
pub const V54_DIGEST: &str = "def5c651f10869551388b2386814a85361211d296348171e3384f950daaa9c38";
/// Spec 25 Vector 54's signature field (192 bytes): the reveal, K′ and
/// standing-root groups' signatures in that order.
pub const V54_SIGNATURE_FIELD: &str = concat!(
    "3ae8d98da909527445761e7eeee8068d1568ee197c71289234f17d5ce108d208",
    "1457e23f7ba0d97a5bd86f2c96812bc493010f18d513e2589e533f2d3c008e96",
    "225f97e673654105abfd3730019960b5200cc01cb95746e0ab7cfcb4ffbce286",
    "0c5dc26b9e49120cfcc9d481b87c0541f5dcf43e108bdd6e42e7e19ae0b433ae",
    "442e7b7634e870dbcc45233d27d82927237e1e8a99864b1a3317a98f8c129d09",
    "41188b5791e4b9e54cc23937b06b3d35cbe16db9f2c41189167c9d6a1bfb88bf",
);

/// Spec 25 Vector 55's preimage (497 bytes): a `RootRecovery{Lost}` on
/// Vector 41 with the reveal and K′ groups.
pub const V55_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a04d5adb473c01283dc9a7e7e998c1d",
    "312b3a353acf4863c13fe77efe304ad38bb30000000000000001fcd42118a686",
    "64c30ff6b44a74aa21fcee2e248e863b973dcad7c75dead5a763020000000100",
    "00000001000000000101000000010100000001026fc6523b7b1e22ff3fbce874",
    "0cfbb7cbc816501864bf40f683db69c860d1a67000000001026bf1355bb40ab8",
    "6b1f3d2e776e08da67e754a5dfeeb706b67d7483d09451c4ce00000001000000",
    "0100000004026bf1355bb40ab86b1f3d2e776e08da67e754a5dfeeb706b67d74",
    "83d09451c4ce01010000000000000000010103b7fe460356f0d94ff2bb085ed1",
    "6157ae327b7769f2823ca829077110f05fb4a502010000000000000000010103",
    "3b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027",
    "0102000000000000000001010223702a648232f2d00713de9289753c2fbd4c4e",
    "fa7e1e33905e3723a412b20aea02020000000000000000010100000001575d27",
    "a9d81af87b505b07f00c00031382c4ca1f3b9bf03e874f25179e21bcae00000e",
    "1002000000000000000000000000000000000000000000000000000000000000",
    "0000000000000100000001cb05862aec3a89bd73c5e2d10a61d6483d945c7203",
    "6bdf62dd880a9ff7d4d6f0010100000001",
);
/// Spec 25 Vector 55's preimage digest.
pub const V55_DIGEST: &str = "e73390a905e9675c3b39deea4a90b6ddc7cafb15e05c576a999dd46d176f0857";
/// Spec 25 Vector 55's signature field (128 bytes): the reveal and K′
/// groups' signatures in that order.
pub const V55_SIGNATURE_FIELD: &str = concat!(
    "0afa8c4cc4b76f2b9ae4804169e52becdde501b9f5773f5e41b23d371c70e2c2",
    "0e404b8a208a90f456959beca8d4b780bb026f5c80edc8233fc83c16dbdae9f7",
    "45752f12ecdd906b572a9c3b2971589860d3bd681756dc9b8d0a0876cb38b01c",
    "39b32960177e369f0c5ce0edbe9c90c0c55293d4f6f75321b8093bbe8c965cda",
);

/// The 17-byte `"SCP-KEL-EVENT-V1:"` separator every signed preimage
/// begins with.
pub const SEPARATOR_LEN: usize = 17;

pub fn bytes(hex_text: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(hex_text)
}

pub fn array<const N: usize>(hex_text: &str) -> Result<[u8; N], Box<dyn std::error::Error>> {
    Ok(<[u8; N]>::try_from(hex::decode(hex_text)?.as_slice())?)
}

/// One §9.10.12 event unit: `BE32(len)` over a spec 25 signed preimage,
/// the preimage, then the signature field.
pub fn event_unit(
    preimage_hex: &str,
    signature_field_hex: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let preimage = bytes(preimage_hex)?;
    let mut unit = u32::try_from(preimage.len())?.to_be_bytes().to_vec();
    unit.extend_from_slice(&preimage);
    unit.extend_from_slice(&bytes(signature_field_hex)?);
    Ok(unit)
}

/// The unit at offset 0 of `value`, which must have passed step 4.
pub fn read_unit(value: &[u8]) -> Result<ReadUnit, Box<dyn std::error::Error>> {
    match decode_event(value, 0) {
        EventUnit::Read(read) => Ok(*read),
        stopped => Err(format!("the unit stopped before its walk: {stopped:?}").into()),
    }
}

/// Asserts that `decode_event` reads a spec 25 event's unit whole, with
/// every stage succeeding: the raw preimage is the printed bytes and its
/// digest the printed digest, the walk consumed the whole unit, each walked
/// signature is by its signer's index in its signer's form and re-encodes
/// to the printed signature field, the body re-encodes to the printed
/// bytes, and the header agrees with the body. Returns the decoded
/// preimage.
pub fn assert_event_round_trip(
    preimage_hex: &str,
    digest_hex: &str,
    signature_field_hex: &str,
) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    let unit = event_unit(preimage_hex, signature_field_hex)?;
    let printed = bytes(preimage_hex)?;
    let read = read_unit(&unit)?;
    assert_eq!(read.raw().signed_preimage(), printed.as_slice());
    assert_eq!(read.raw().event_digest(), array::<32>(digest_hex)?);
    let field = read.signature_field().map_err(Clone::clone)?;
    assert_eq!(field.consumed(), unit.len());
    let preimage = read.preimage().map_err(Clone::clone)?;
    assert_eq!(
        encode_preimage(preimage)?.signed_preimage(),
        printed.as_slice()
    );

    let header = read.header();
    assert_eq!(header.kind(), preimage.kind);
    assert_eq!(header.identifier_field(), preimage.identifier);
    assert_eq!(header.sequence(), preimage.sequence);
    assert_eq!(header.predecessor_digest(), &preimage.predecessor_digest);
    assert_eq!(header.standing_root(), preimage.standing_root);
    assert_eq!(header.groups().len(), preimage.signer_groups.len());
    let walked_groups = read.walked_groups().map_err(Clone::clone)?;
    assert_eq!(walked_groups.len(), header.groups().len());
    let mut walked = Vec::new();
    for ((group, signer_group), walked_group) in header
        .groups()
        .iter()
        .zip(&preimage.signer_groups)
        .zip(walked_groups)
    {
        let indices: Vec<u8> = group.signers().iter().map(NamedSigner::index).collect();
        let forms: Vec<SignatureForm> = group.signers().iter().map(NamedSigner::form).collect();
        assert_eq!(indices, signer_group.indices);
        assert_eq!(forms, signer_group.forms);
        assert_eq!(walked_group.group(), group);
        assert_eq!(walked_group.signatures().len(), group.signers().len());
        for (signature, signer) in walked_group.signatures().iter().zip(group.signers()) {
            assert_eq!(signature.index(), signer.index());
            assert_eq!(signature.signature().form(), signer.form());
            walked.extend_from_slice(&signature.signature().to_bytes());
        }
    }
    assert_eq!(walked, bytes(signature_field_hex)?);
    Ok(preimage.clone())
}

pub fn identifier(hex_text: &str) -> Result<Identifier, Box<dyn std::error::Error>> {
    Ok(Identifier::from_bytes(array(hex_text)?))
}

/// A spec 25 preimage's field bytes: the printed bytes after the separator.
pub fn fields(preimage_hex: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let printed = bytes(preimage_hex)?;
    Ok(printed
        .get(SEPARATOR_LEN..)
        .ok_or("preimage shorter than its separator")?
        .to_vec())
}

/// Asserts a preimage's signed bytes, field bytes and digest against a spec
/// 25 vector, and that the printed field bytes decode back to the preimage
/// with the same signed bytes and digest.
pub fn assert_vector(preimage: &EventPreimage, printed_hex: &str, digest_hex: &str) -> TestResult {
    let printed = bytes(printed_hex)?;
    let field_bytes = fields(printed_hex)?;
    let digest = array::<32>(digest_hex)?;
    let encoded = encode_preimage(preimage)?;
    assert_eq!(encoded.signed_preimage(), printed.as_slice());
    assert_eq!(encoded.fields(), field_bytes.as_slice());
    assert_eq!(encoded.event_digest(), digest);
    let decoded = decode_preimage(&field_bytes)?;
    assert_eq!(decoded.preimage(), preimage);
    assert_eq!(decoded.signed_preimage(), printed.as_slice());
    assert_eq!(decoded.event_digest(), digest);
    Ok(())
}

/// Verifies a spec 25 raw-form indexed signature with the §9.5.1 strict
/// verifier.
pub fn assert_signature(key_hex: &str, digest_hex: &str, signature_hex: &str) -> TestResult {
    let key = P256PublicKey::from_sec1(&bytes(key_hex)?)?;
    verify_prehash_strict(&key, &array(digest_hex)?, &bytes(signature_hex)?)?;
    Ok(())
}

const fn current(key: [u8; 33], role: KeyRole, custody_type: CustodyType) -> KeyEntry {
    KeyEntry {
        key,
        role,
        condition: KeyCondition::Current,
        compromised_from: 0,
        custody_type,
        key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
    }
}

fn raw_root_group() -> SignerGroup {
    SignerGroup {
        indices: vec![0],
        forms: vec![SignatureForm::Raw],
    }
}

/// Vector 41's key-state snapshot at a witnessing interval: root member 0
/// and `#active`, both `Passkey`, one witness, undelegated.
pub fn v41_snapshot(
    witnessing_interval: u32,
) -> Result<KeyStateSnapshot, Box<dyn std::error::Error>> {
    Ok(KeyStateSnapshot {
        root_threshold: 1,
        keys: vec![
            current(array(V41_ROOT)?, KeyRole::RootMember, CustodyType::Passkey),
            current(array(V41_ACTIVE)?, KeyRole::Active, CustodyType::Passkey),
        ],
        witnesses: vec![identifier(V41_WITNESS)?],
        witnessing_interval,
        service_key_role: KeyRole::Active,
        delegator: Identifier::ZERO,
    })
}

/// Vector 41 (form `Raw`) or Vector 42 (form `WebAuthnAssertion`).
pub fn v41_inception(form: SignatureForm) -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::inception(InceptionFields {
        root_group: SignerGroup {
            indices: vec![0],
            forms: vec![form],
        },
        key_state: v41_snapshot(3600)?,
        continuation: Continuation::FixesCommitment(FixedCommitment {
            commitments: vec![CommitmentEntry {
                commitment: array(V47A_COMMITMENT)?,
                custody_type: CustodyType::Passkey,
                key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
            }],
            next_threshold: 1,
        }),
    }))
}

/// Vector 50: Vector 41's identity at sequence 1, interval 7200, one seal.
pub fn v50_key_state() -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::key_state(KeyStateFields {
        identifier: identifier(V41_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V41_DIGEST)?,
        root_group: raw_root_group(),
        key_state: v41_snapshot(7200)?,
        seals: vec![array(V50_SEAL)?],
    }))
}

const V51_CUSTODY: [CustodyType; 9] = [
    CustodyType::Passkey,
    CustodyType::Fido2Token,
    CustodyType::Hsm,
    CustodyType::SecureEnclave,
    CustodyType::AndroidKeystore,
    CustodyType::EncryptedOfflineBackup,
    CustodyType::ShamirShares,
    CustodyType::PaperBackup,
    CustodyType::Software,
];

/// Vector 51's snapshot at a witnessing interval: eight root members and
/// `#active`, one per registered custody type.
pub fn v51_snapshot(
    witnessing_interval: u32,
) -> Result<KeyStateSnapshot, Box<dyn std::error::Error>> {
    let mut keys = Vec::new();
    for (index, (key, custody_type)) in V51_KEYS.iter().zip(V51_CUSTODY).enumerate() {
        let role = if index < 8 {
            KeyRole::RootMember
        } else {
            KeyRole::Active
        };
        keys.push(current(array(key)?, role, custody_type));
    }
    Ok(KeyStateSnapshot {
        root_threshold: 1,
        keys,
        witnesses: vec![identifier(V51_WITNESS)?],
        witnessing_interval,
        service_key_role: KeyRole::Active,
        delegator: Identifier::ZERO,
    })
}

/// Vector 51's inception, as its text states: the same snapshot at interval
/// 3600, whose eight root members the inception installs 1-of-8, one raw root
/// signature, and one `Passkey` `EcdsaP256Sha256` commitment to the
/// pre-rotation key with next threshold 1.
pub fn v51_inception() -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::inception(InceptionFields {
        root_group: raw_root_group(),
        key_state: v51_snapshot(3600)?,
        continuation: Continuation::FixesCommitment(FixedCommitment {
            commitments: vec![CommitmentEntry {
                commitment: prerotation_commitment(&array(V51_PREROTATION)?),
                custody_type: CustodyType::Passkey,
                key_algorithm: KeyAlgorithm::EcdsaP256Sha256,
            }],
            next_threshold: 1,
        }),
    }))
}

/// Vector 51's `KeyState` at sequence 1.
pub fn v51_key_state() -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::key_state(KeyStateFields {
        identifier: identifier(V51_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V51_INCEPTION_DIGEST)?,
        root_group: raw_root_group(),
        key_state: v51_snapshot(7200)?,
        seals: Vec::new(),
    }))
}

/// Vector 68: an abandoning `CommitmentRollover` at sequence 1 over Vector 41.
pub fn v68_rollover() -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::commitment_rollover(
        CommitmentRolloverFields {
            identifier: identifier(V41_IDENTIFIER)?,
            sequence: 1,
            predecessor_digest: array(V41_DIGEST)?,
            reveal_group: raw_root_group(),
            standing_root_group: raw_root_group(),
            revealed_keys: vec![array(V47A_POINT)?],
            continuation: Continuation::Abandons,
        },
    ))
}

/// Vector 69: a `KeyState` at sequence 1 over Vector 41 that keeps the root,
/// installs a new `#active` key, and drops Vector 41's `#active` key as
/// `Compromised{from: 1}`.
pub fn v69_key_state() -> Result<EventPreimage, Box<dyn std::error::Error>> {
    Ok(EventPreimage::key_state(KeyStateFields {
        identifier: identifier(V41_IDENTIFIER)?,
        sequence: 1,
        predecessor_digest: array(V41_DIGEST)?,
        root_group: raw_root_group(),
        key_state: KeyStateSnapshot {
            root_threshold: 1,
            keys: vec![
                current(array(V41_ROOT)?, KeyRole::RootMember, CustodyType::Passkey),
                current(array(V69_ACTIVE)?, KeyRole::Active, CustodyType::Passkey),
                KeyEntry {
                    condition: KeyCondition::Compromised,
                    compromised_from: 1,
                    ..current(array(V41_ACTIVE)?, KeyRole::Active, CustodyType::Passkey)
                },
            ],
            witnesses: vec![identifier(V41_WITNESS)?],
            witnessing_interval: 3600,
            service_key_role: KeyRole::Active,
            delegator: Identifier::ZERO,
        },
        seals: Vec::new(),
    }))
}
