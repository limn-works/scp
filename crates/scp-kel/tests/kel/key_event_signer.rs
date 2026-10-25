//! `KeyEventSigner`'s futures are `Send` off wasm32 (§9.7.4.2 R10), and
//! `SigningChange` hands a signer the change's digest and challenge.

use std::future::{Future, ready};
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use scp_kel::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, MaybeSend, ProbeSignature,
    SigningChange, key_event_challenge,
};

use crate::fixtures::{TestResult, V41_DIGEST, V41_PREIMAGE, array, bytes};

/// A raw-arm signer whose signature is the 32 bytes it was handed, twice.
struct EchoSigner;

fn echo_bytes(digest: [u8; 32]) -> [u8; 64] {
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&digest);
    signature[32..].copy_from_slice(&digest);
    signature
}

fn echo(digest: [u8; 32]) -> IndexedSignature {
    IndexedSignature::Raw {
        signature: echo_bytes(digest),
    }
}

impl KeyEventSigner for EchoSigner {
    type Member = ();

    fn sign_change(
        &self,
        (): &(),
        change: &SigningChange,
    ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
        ready(Ok(echo(change.digest())))
    }

    fn sign_probe(
        &self,
        (): &(),
        probe: &CustodyProbe,
    ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
        ready(Ok(ProbeSignature::raw(echo_bytes(probe.raw_digest()))))
    }
}

const fn assert_send<T: Send>(_: &T) {}

/// Compiles only when every `KeyEventSigner`'s futures are `Send`, whatever
/// the implementor: the bound comes from the trait, not from `EchoSigner`.
fn futures_are_send<S: KeyEventSigner>(
    signer: &S,
    member: &S::Member,
    change: &SigningChange,
    probe: &CustodyProbe,
) {
    assert_send(&signer.sign_change(member, change));
    assert_send(&signer.sign_probe(member, probe));
}

fn v41_change() -> Result<SigningChange, Box<dyn std::error::Error>> {
    SigningChange::inception(&bytes(V41_PREIMAGE)?)
        .map_err(|refusal| format!("Vector 41 refused: {refusal:?}").into())
}

fn ready_value<F: Future>(future: F) -> Option<F::Output> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

#[test]
fn futures_are_send_natively() -> TestResult {
    futures_are_send(&EchoSigner, &(), &v41_change()?, &CustodyProbe::fresh()?);
    Ok(())
}

#[test]
fn signing_change_hands_the_signer_vector_41_digest_and_challenge() -> TestResult {
    let change = v41_change()?;
    let digest: [u8; 32] = array(V41_DIGEST)?;
    assert_eq!(change.digest(), digest);
    assert_eq!(change.key_event_challenge(), key_event_challenge(&digest));
    let signed = ready_value(EchoSigner.sign_change(&(), &change)).ok_or("future pending")??;
    assert_eq!(signed, echo(digest));
    Ok(())
}
