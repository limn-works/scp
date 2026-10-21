//! Spec 25 §25.26 and §25.29 fixtures shared by the scp-kel integration
//! tests and by scp-client-wasm's cross-target known-answer test.
//!
//! Every hex constant is copied from `.docs/specs/25-test-vectors.md` and
//! names its vector; none is produced by this crate. The preimage builders
//! assemble each vector's fields from the values that vector prints.

use scp_crypto::p256::{P256PublicKey, verify_prehash_strict};
use scp_did::{
    CommitmentEntry, CustodyType, Identifier, KeyAlgorithm, KeyCondition, KeyEntry, KeyRole,
    StandingCommitment,
};
use scp_kel::{
    CommitmentRolloverFields, Continuation, EventPreimage, InceptionFields, KeyStateFields,
    KeyStateSnapshot, SignatureForm, SignerGroup, decode_preimage, encode_preimage,
    prerotation_commitment,
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
    "5e3723a412b20aea020100000000000000000101000000019d94df95bc0a13f1",
    "963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e1002000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a51",
    "5de80a3e43eb010100000001",
);
/// Spec 25 Vector 41's preimage digest D.
pub const V41_DIGEST: &str = "d8ba4ebad52657208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7";
/// Spec 25 Vector 41's identifier.
pub const V41_IDENTIFIER: &str = "2c0f7f4478be94db0078311ef51ba3cc9934362b0f154dcbf9c597572e46cf32";
/// Spec 25 Vector 41's routing id, `SHA-256("scp:did:" || identifier)`.
pub const V41_ROUTING_DID: &str =
    "f8affd47ab024cae9489a63fa1c632914c16f7329441b8fca65b32c78d86a4eb";
/// Spec 25 Vector 41's cosigned-head routing id, `"scp:wit:"`.
pub const V41_ROUTING_WIT: &str =
    "e278b66a7481f608d58a5f11b5fa7c4221f23071172ffd0d7ec1fd94494970fe";
/// Spec 25 Vector 41's conflict-statement routing id, `"scp:wcf:"`.
pub const V41_ROUTING_WCF: &str =
    "31f18999c7207845a6ac3b85ce774a6f9eff1a8da300b37d2b54ff8688e07744";
/// Spec 25 Vector 41's service-record routing id, `"scp:svc:"`, which is
/// Vector 48's address.
pub const V41_ROUTING_SVC: &str =
    "415152a878481430157966302b508188f6715a49e2bc7072bad1c4a54af24f17";
/// Spec 25 Vector 48's address, `SHA-256("scp:svc:" || identifier)`.
pub const V48_ADDRESS: &str = "415152a878481430157966302b508188f6715a49e2bc7072bad1c4a54af24f17";
/// Spec 25 Vector 48's identifier, which is Vector 41's.
pub const V48_IDENTIFIER: &str = "2c0f7f4478be94db0078311ef51ba3cc9934362b0f154dcbf9c597572e46cf32";

/// Spec 25 Vector 41's root-set member 0.
pub const V41_ROOT: &str = "033b1cac23f45cf1cdfdf0b32f8f777b99166c1b69649c2295b1517883d47f3027";
/// Spec 25 Vector 47b's point, §25.2's secondary key: Vector 41's `#active`
/// key.
pub const V41_ACTIVE: &str = "0223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412b20aea";
/// Spec 25 Vector 41's witness operator, as its preimage carries it.
pub const V41_WITNESS: &str = "9d94df95bc0a13f1963f484414c320354c73c75bb86e96559e97765f5bc2d313";

/// Spec 25 Vector 41's raw-form indexed signature over D (64 bytes).
pub const V41_SIGNATURE: &str = concat!(
    "274e7cf73b6807ec53619491a1cc094a5fa2a649b4a04a043965597c7faa5e96",
    "7e7b499be2e9750521b4bfec6fa65bfdd14c8e5c940bb60884d040da9d1e70a0",
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
    "5e3723a412b20aea020100000000000000000101000000019d94df95bc0a13f1",
    "963f484414c320354c73c75bb86e96559e97765f5bc2d31300000e1002000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "000100000001421be508c6ed135a9737895007e5ba16f9542e1b3440f6d00a51",
    "5de80a3e43eb010100000001",
);
/// Spec 25 Vector 42's preimage digest D.
pub const V42_DIGEST: &str = "9a41b0fdb978014730ab7d8d56b9a77745b4ff4824affc096bbd923d14a569a6";
/// Spec 25 Vector 42's identifier.
pub const V42_IDENTIFIER: &str = "bb8f96731d62d4cc81b811c1ce47246bdaa7f8765ca43e62ded190bd38e65c3d";
/// Spec 25 Vector 42's challenge bytes, `"SCP-KEY-EVENT-V1:" || D` (49 bytes).
pub const V42_CHALLENGE_BYTES: &str = concat!(
    "5343502d4b45592d4556454e542d56313a9a41b0fdb978014730ab7d8d56b9a7",
    "7745b4ff4824affc096bbd923d14a569a6",
);
/// Spec 25 Vector 42's challenge, unpadded base64url as clientDataJSON
/// carries it.
pub const V42_CHALLENGE: &str =
    "U0NQLUtFWS1FVkVOVC1WMTqaQbD9uXgBRzCrfY1Wuad3RbT_SCSv_AlrvZI9FKVppg";
/// Spec 25 Vector 42's authenticatorData (37 bytes): rpIdHash, flags 0x05,
/// signCount 0.
pub const V42_AUTHENTICATOR_DATA: &str = concat!(
    "aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d11689d76",
    "0500000000",
);
/// Spec 25 Vector 42's clientDataJSON (155 bytes), as its printed text.
pub const V42_CLIENT_DATA_JSON: &str = concat!(
    r#"{"type":"webauthn.get","challenge":"#,
    r#""U0NQLUtFWS1FVkVOVC1WMTqaQbD9uXgBRzCrfY1Wuad3RbT_SCSv_AlrvZI9FKVppg","#,
    r#""origin":"https://ctx.network","crossOrigin":false}"#,
);
/// Spec 25 Vector 42's clientDataJSON bytes, as printed in hex.
pub const V42_CLIENT_DATA_JSON_HEX: &str = concat!(
    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e67",
    "65223a2255304e514c55744657533146566b564f564331574d54716151624439",
    "75586742527a437266593157756164335262545f534353765f416c72765a4939",
    "464b56707067222c226f726967696e223a2268747470733a2f2f6374782e6e65",
    "74776f726b222c2263726f73734f726967696e223a66616c73657d",
);
/// Spec 25 Vector 42's `SHA-256(clientDataJSON)`.
pub const V42_CLIENT_DATA_HASH: &str =
    "0b33b76a4ecb79e15753a17147ac39f6964ae20523e7e001c258e67d2562c236";
/// Spec 25 Vector 42's relying-party identifier, whose SHA-256 is the
/// `rpIdHash` that opens its authenticatorData.
pub const V42_RP_ID: &str = "ctx.network";
/// Spec 25 Vector 42's signed message (69 bytes),
/// `authenticatorData || SHA-256(clientDataJSON)`.
pub const V42_SIGNED_MESSAGE: &str = concat!(
    "aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d11689d76",
    "05000000000b33b76a4ecb79e15753a17147ac39f6964ae20523e7e001c258e6",
    "7d2562c236",
);
/// Spec 25 Vector 42's ECDSA message digest,
/// `SHA-256(authenticatorData || SHA-256(clientDataJSON))`.
pub const V42_SIGNED_DIGEST: &str =
    "1f63ea5226c20ce261b3243ad941ef8834b0678cf4681b2f914963b0bffe4d6b";
/// Spec 25 Vector 42's 64-byte low-s signature.
pub const V42_SIGNATURE: &str = concat!(
    "6aee5c6f9b367f8a886fb996c2f08d77fefcddee6399f1b928cf1110cef786d0",
    "315de3e854e0669d355b4968b5c2bc8075a5630e3c980844049ebcbf9716c424",
);
/// Spec 25 Vector 42's assertion-form indexed signature (264 bytes).
pub const V42_INDEXED_SIGNATURE: &str = concat!(
    "00000025aee39d05bf6e1cbe288aedd7ead156f1d67399382d7a110e8f6c495d",
    "11689d7605000000000000009b7b2274797065223a22776562617574686e2e67",
    "6574222c226368616c6c656e6765223a2255304e514c55744657533146566b56",
    "4f564331574d5471615162443975586742527a43726659315775616433526254",
    "5f534353765f416c72765a4939464b56707067222c226f726967696e223a2268",
    "747470733a2f2f6374782e6e6574776f726b222c2263726f73734f726967696e",
    "223a66616c73657d6aee5c6f9b367f8a886fb996c2f08d77fefcddee6399f1b9",
    "28cf1110cef786d0315de3e854e0669d355b4968b5c2bc8075a5630e3c980844",
    "049ebcbf9716c424",
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
    "5343502d4b454c2d4556454e542d56313a022c0f7f4478be94db0078311ef51b",
    "a3cc9934362b0f154dcbf9c597572e46cf320000000000000001d8ba4ebad526",
    "57208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7000000000100",
    "000000010100000000000000000000000100000002033b1cac23f45cf1cdfdf0",
    "b32f8f777b99166c1b69649c2295b1517883d47f302701010000000000000000",
    "01010223702a648232f2d00713de9289753c2fbd4c4efa7e1e33905e3723a412",
    "b20aea020100000000000000000101000000019d94df95bc0a13f1963f484414",
    "c320354c73c75bb86e96559e97765f5bc2d31300001c20020000000000000000",
    "00000000000000000000000000000000000000000000000000000001caf80a0c",
    "2332b8a2e1454c355f84142f34d24e92b45db3c0948d90adbd76248800000000",
);
/// Spec 25 Vector 50's sealed event digest.
pub const V50_SEALED_DIGEST: &str =
    "1c7f9fb5d17d8773900e072f0fea733baf4fc5e2ce240107df69072646e775a2";
/// Spec 25 Vector 50's key-event seal.
pub const V50_SEAL: &str = "caf80a0c2332b8a2e1454c355f84142f34d24e92b45db3c0948d90adbd762488";
/// Spec 25 Vector 50's preimage digest.
pub const V50_DIGEST: &str = "4b56f7b97027fdcd5e480ecb88528441e30186b5e2b54db0fefd7b53ad1a120d";

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
/// Spec 25 Vector 51's witness operator.
pub const V51_WITNESS: &str = "edc22d251051440536a8fb98bf3183ad90a8e0a1b8dec9ca340c24182e550fa0";
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
    "e6f9bc2ea14597fee28202010000000000000000090100000001edc22d251051",
    "440536a8fb98bf3183ad90a8e0a1b8dec9ca340c24182e550fa000000e100200",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000001000000016644cc0e3ef3eae7dd1274d305e48fb593acce69ed4e4cef",
    "a9c63683174ed0ac010100000001",
);
/// Spec 25 Vector 51's inception digest.
pub const V51_INCEPTION_DIGEST: &str =
    "d979b6ff80c44e340ae48ffd16f9748f234226c7a5aaf00c9465fb3e982e4645";
/// Spec 25 Vector 51's identifier.
pub const V51_IDENTIFIER: &str = "9e52f5402e1437a8358eb96f7187bfec7f3f4976d00bdfb999dd2ca8373d30c6";
/// Spec 25 Vector 51's routing id.
pub const V51_ROUTING_DID: &str =
    "4e904d784a879f4829dde870dedc1b99a9e8d144669b2c2861193be71d902cc4";
/// Spec 25 Vector 51's preimage (603 bytes, separator included).
pub const V51_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a029e52f5402e1437a8358eb96f7187",
    "bfec7f3f4976d00bdfb999dd2ca8373d30c60000000000000001d979b6ff80c4",
    "4e340ae48ffd16f9748f234226c7a5aaf00c9465fb3e982e4645000000000100",
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
    "0000000000000000090100000001edc22d251051440536a8fb98bf3183ad90a8",
    "e0a1b8dec9ca340c24182e550fa000001c200200000000000000000000000000",
    "000000000000000000000000000000000000000000000000000000",
);
/// Spec 25 Vector 51's preimage digest.
pub const V51_DIGEST: &str = "0347480558d3cb54f5f6fa1dda9f538cdd750b47aaf5b6de7bdc29c8b6c647fb";

/// Spec 25 Vector 51's inception signature: root member 0, raw form, over
/// the inception digest.
pub const V51_INCEPTION_SIGNATURE: &str = concat!(
    "d7104ac11c070044300192427fa05d9ed127ae5d9544067240e3216da92145f3",
    "4c408c2b1ebdbe3db03f6c81700003f24f3a474ea18352af47a12b461fe6fcf6",
);

/// Spec 25 Vector 68's preimage (161 bytes): Vector 53's rollover with
/// field 12 the one byte `0x00`.
pub const V68_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a032c0f7f4478be94db0078311ef51b",
    "a3cc9934362b0f154dcbf9c597572e46cf320000000000000001d8ba4ebad526",
    "57208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7000000000100",
    "00000001000000000101000000010100000001026fc6523b7b1e22ff3fbce874",
    "0cfbb7cbc816501864bf40f683db69c860d1a670000000000000000000000000",
    "00",
);
/// Spec 25 Vector 68's preimage digest.
pub const V68_DIGEST: &str = "9c6a3dcdcff0e73c03859c375debc8ec3e3c70c5834fd111b9f94e055a28b22e";
/// Spec 25 Vector 68's reveal signature, by the revealed key.
pub const V68_REVEAL_SIGNATURE: &str = concat!(
    "87c8850628e69a3e77bf240285c240fd6a38c0149091f380a447c51b2d8da510",
    "058f10913c5fa2f6abe1345defd0ba55627a1b447f05f22e89f4a9e7233ccf61",
);
/// Spec 25 Vector 68's standing-root signature, by Vector 41's root member 0.
pub const V68_ROOT_SIGNATURE: &str = concat!(
    "c5f3d73bf438c4f3503a1b33c239934d62819ac8d319079b466b02892b273cf6",
    "3ee408b9f697d1c5ebac883cde74139dfda09c4fcba7800415bc110bcb57e8dd",
);

/// Spec 25 Vector 69's preimage (333 bytes).
pub const V69_PREIMAGE: &str = concat!(
    "5343502d4b454c2d4556454e542d56313a022c0f7f4478be94db0078311ef51b",
    "a3cc9934362b0f154dcbf9c597572e46cf320000000000000001d8ba4ebad526",
    "57208736f4cac675352f5f9cc0aa837620f8d742dbf42aeedbd7000000000100",
    "000000010100000000000000000000000100000003033b1cac23f45cf1cdfdf0",
    "b32f8f777b99166c1b69649c2295b1517883d47f302701010000000000000000",
    "010103111dadf2081befb113b3e43ce763df7d1c34b64f01778fb108087894ac",
    "ae761c0201000000000000000001010223702a648232f2d00713de9289753c2f",
    "bd4c4efa7e1e33905e3723a412b20aea02040000000000000001010100000001",
    "9d94df95bc0a13f1963f484414c320354c73c75bb86e96559e97765f5bc2d313",
    "00000e1002000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000",
);
/// Spec 25 Vector 69's preimage digest.
pub const V69_DIGEST: &str = "12f301331515b7108969e5649b025e98847a14d290fe9ee093dfecc9a5355168";
/// Spec 25 Vector 69's installed `#active` key.
pub const V69_ACTIVE: &str = "03111dadf2081befb113b3e43ce763df7d1c34b64f01778fb108087894acae761c";
/// Spec 25 Vector 69's root signature, by Vector 41's root member 0.
pub const V69_ROOT_SIGNATURE: &str = concat!(
    "b622e40aa201d477309172165de6cc4fa7ae83f72efc349152e5e5d82d5bf32c",
    "0ea4c8119dc25851f952fbd9f8e5607a8b021a4061fbb0219bb70efa3f35d81c",
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
        continuation: Continuation::FixesCommitment(StandingCommitment {
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
        continuation: Continuation::FixesCommitment(StandingCommitment {
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
