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
    CustodyProbe, IndexedSignature, KeyEventSignError, KeyEventSigner, MaybeSend, SigningChange,
};

type Signed = Result<IndexedSignature, KeyEventSignError>;
use wasm_bindgen_test::wasm_bindgen_test;

/// A signer whose future holds an `Rc`, as a signer awaiting a `JsFuture`
/// holds its `JsValue`s.
struct RcSigner;

/// A future that is not `Send`, because it holds an `Rc`. It resolves to a
/// raw signature whose first 32 bytes are the digest it was handed.
struct RcFuture(Rc<[u8; 32]>);

impl Future for RcFuture {
    type Output = Signed;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(self.0.as_ref());
        Poll::Ready(Ok(IndexedSignature::Raw { signature }))
    }
}

impl KeyEventSigner for RcSigner {
    type Member = ();

    fn sign_change(
        &self,
        (): &(),
        change: &SigningChange,
    ) -> impl Future<Output = Signed> + MaybeSend {
        RcFuture(Rc::new(change.digest()))
    }

    fn sign_probe(
        &self,
        (): &(),
        probe: &CustodyProbe,
    ) -> impl Future<Output = Signed> + MaybeSend {
        RcFuture(Rc::new(probe.raw_digest()))
    }
}

#[wasm_bindgen_test]
fn a_signer_holding_an_rc_signs_a_probe_on_wasm32() {
    let probe = CustodyProbe::new([0x5a; 32]);
    let mut future = pin!(RcSigner.sign_probe(&(), &probe));
    let signed = future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()));
    let mut expected = [0u8; 64];
    expected[..32].copy_from_slice(&probe.raw_digest());
    assert_eq!(
        signed,
        Poll::Ready(Ok(IndexedSignature::Raw {
            signature: expected
        }))
    );
}
