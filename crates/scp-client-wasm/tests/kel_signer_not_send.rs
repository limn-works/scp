//! On wasm32, `scp_kel::KeyEventSigner` admits a signer whose futures are not
//! `Send` (`09-security-model.md` §9.7.4.2 R10). The ADR-057 browser client
//! signs by awaiting a wasm-bindgen `JsFuture`, which is not `Send`, so a
//! `Send` bound on wasm32 would leave it no implementation.
//!
//! `RcSigner`'s future holds an `Rc`. The file compiles only when
//! `MaybeSend` puts no bound on wasm32. Off wasm32 the trait requires `Send`
//! futures and this impl cannot compile, so the file compiles for wasm32
//! alone; `wasm-pack test --node crates/scp-client-wasm` builds and runs it.
#![cfg(target_arch = "wasm32")]

use std::future::Future;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

use scp_kel::{
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, MaybeSend, ProbeSignature,
    SigningChange,
};
use wasm_bindgen_test::wasm_bindgen_test;

/// A signer whose future holds an `Rc`, as a signer awaiting a `JsFuture`
/// holds its `JsValue`s.
struct RcSigner;

/// A future that is not `Send`, because it holds an `Rc`. It resolves to the
/// 64 bytes whose first 32 are the digest it was handed, wrapped by `wrap`.
struct RcFuture<T>(Rc<[u8; 32]>, fn([u8; 64]) -> T);

impl<T> Future for RcFuture<T> {
    type Output = Result<T, KeyEventSignError>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(self.0.as_ref());
        Poll::Ready(Ok((self.1)(signature)))
    }
}

const fn raw_indexed(signature: [u8; 64]) -> IndexedSignature {
    IndexedSignature::Raw { signature }
}

impl KeyEventSigner for RcSigner {
    type Member = ();

    fn sign_change(
        &self,
        (): &(),
        change: &SigningChange,
    ) -> impl Future<Output = Result<IndexedSignature, KeyEventSignError>> + MaybeSend {
        RcFuture(Rc::new(change.digest()), raw_indexed)
    }

    fn sign_probe(
        &self,
        (): &(),
        probe: &CustodyProbe,
    ) -> impl Future<Output = Result<ProbeSignature, KeyEventSignError>> + MaybeSend {
        RcFuture(Rc::new(probe.raw_digest()), ProbeSignature::raw)
    }
}

#[wasm_bindgen_test]
fn a_signer_holding_an_rc_signs_a_probe_on_wasm32() -> Result<(), scp_kel::ProbeNonceError> {
    let probe = CustodyProbe::fresh()?;
    let mut future = pin!(RcSigner.sign_probe(&(), &probe));
    let signed = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    let mut expected = [0u8; 64];
    expected[..32].copy_from_slice(&probe.raw_digest());
    assert_eq!(signed, Poll::Ready(Ok(ProbeSignature::raw(expected))));
    Ok(())
}
