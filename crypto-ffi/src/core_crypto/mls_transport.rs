//! Implement the MLS Transport interface.
//!
//! Unfortunately, there is no good way to reuse code between uniffi and wasm for an interface
//! like this; the fundamental techniques in use are very different. So we just have to feature-gate
//! everything.
#[cfg(target_family = "wasm")]
use js_sys::{Promise, Uint8Array};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(target_family = "wasm")]
use wasm_bindgen_futures::JsFuture;

#[cfg(not(target_family = "wasm"))]
use std::fmt;
use std::sync::Arc;

use core_crypto::prelude::MlsCommitBundle;

#[cfg(target_family = "wasm")]
use crate::CoreCryptoError;
use crate::{CommitBundle, CoreCrypto, CoreCryptoResult};

#[cfg(not(target_family = "wasm"))]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MlsTransportResponse {
    /// The message was accepted by the distribution service
    Success,
    /// A client should have consumed all incoming messages before re-trying.
    Retry,
    /// The message was rejected by the delivery service and there's no recovery.
    Abort { reason: String },
}

#[cfg(not(target_family = "wasm"))]
impl From<MlsTransportResponse> for core_crypto::MlsTransportResponse {
    fn from(value: MlsTransportResponse) -> Self {
        match value {
            MlsTransportResponse::Success => Self::Success,
            MlsTransportResponse::Retry => Self::Retry,
            MlsTransportResponse::Abort { reason } => Self::Abort { reason },
        }
    }
}

/// Used by core crypto to send commits or application messages to the delivery service.
/// This trait must be implemented before calling any functions that produce commits.
#[cfg(not(target_family = "wasm"))]
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MlsTransport: Send + Sync {
    /// Send a commit bundle to the corresponding endpoint.
    async fn send_commit_bundle(&self, commit_bundle: CommitBundle) -> MlsTransportResponse;
    /// Send a message to the corresponding endpoint.
    async fn send_message(&self, mls_message: Vec<u8>) -> MlsTransportResponse;
}

#[cfg(not(target_family = "wasm"))]
#[derive(derive_more::Constructor)]
struct MlsTransportShim(Arc<dyn MlsTransport>);

#[cfg(not(target_family = "wasm"))]
impl fmt::Debug for MlsTransportShim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MlsTransportShim")
            .field(&"Arc<dyn MlsTransport>")
            .finish()
    }
}

#[cfg(not(target_family = "wasm"))]
#[async_trait::async_trait]
impl core_crypto::prelude::MlsTransport for MlsTransportShim {
    async fn send_commit_bundle(
        &self,
        commit_bundle: MlsCommitBundle,
    ) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        let commit_bundle = CommitBundle::try_from(commit_bundle)
            .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(e.to_string()))?;
        Ok(self.0.send_commit_bundle(commit_bundle).await.into())
    }

    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        Ok(self.0.send_message(mls_message).await.into())
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize, strum::FromRepr)]
#[serde(try_from = "u8")]
#[repr(u8)]
pub enum MlsTransportResponseVariant {
    Success = 1,
    Retry = 2,
    Abort = 3,
}

#[cfg(target_family = "wasm")]
impl TryFrom<u8> for MlsTransportResponseVariant {
    type Error = core_crypto::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_repr(value).ok_or_else(|| {
            core_crypto::Error::ErrorDuringMlsTransport(format!("unknown MlsTransportResponseVariant: {value}"))
        })
    }
}

#[cfg(target_family = "wasm")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[wasm_bindgen(inspectable)]
pub struct MlsTransportResponse {
    pub variant: MlsTransportResponseVariant,
    #[wasm_bindgen(getter_with_clone)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_reason: Option<String>,
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl MlsTransportResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(variant: MlsTransportResponseVariant, abort_reason: Option<String>) -> MlsTransportResponse {
        MlsTransportResponse { variant, abort_reason }
    }
}

#[cfg(target_family = "wasm")]
impl From<MlsTransportResponse> for core_crypto::MlsTransportResponse {
    fn from(response: MlsTransportResponse) -> Self {
        match response.variant {
            MlsTransportResponseVariant::Success => core_crypto::MlsTransportResponse::Success,
            MlsTransportResponseVariant::Retry => core_crypto::MlsTransportResponse::Retry,
            MlsTransportResponseVariant::Abort => core_crypto::MlsTransportResponse::Abort {
                reason: response.abort_reason.unwrap_or_default(),
            },
        }
    }
}

/// Used by core crypto to send commits or application messages to the delivery service.
/// This must be instantiated and set before calling any functions which produce commits.
#[cfg(target_family = "wasm")]
#[derive(Debug)]
#[wasm_bindgen]
pub struct MlsTransport {
    this_context: JsValue,
    send_commit_bundle: js_sys::Function,
    send_message: js_sys::Function,
}

#[cfg(target_family = "wasm")]
// SAFETY: we promise that we're only ever using this in a single-threaded context
unsafe impl Send for MlsTransport {}
#[cfg(target_family = "wasm")]
// SAFETY: we promise that we're only ever using this in a single-threaded context
unsafe impl Sync for MlsTransport {}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl MlsTransport {
    /// Create a new MLS Transport instance.
    ///
    /// This function should be hidden on the JS side of things! The JS bindings should have an `interface MlsTransport`
    /// which has the two methods defined, and the bindings themselves should destructure an instance implementing that
    /// interface appropriately to construct this.
    ///
    /// - `this_context` is the instance itself, which will be bound to `this` within the function bodies
    /// - `send_commit_bundle`: A function of the form `(CommitBundle) -> Promise<MlsTransportResponse>`.
    ///   Sends a commit bundle to the corresponding endpoint.
    /// - `send_message`: A function of the form `(Uint8Array) -> Promise<MlsTransportResponse>`
    ///   Sends a message to the corresponding endpoint.
    #[wasm_bindgen(constructor)]
    pub fn new(
        this_context: JsValue,
        send_commit_bundle: js_sys::Function,
        send_message: js_sys::Function,
    ) -> CoreCryptoResult<Self> {
        // we can't do much type-checking here unfortunately, but we can at least validate that the incoming functions have the right length
        if send_commit_bundle.length() != 1 {
            return Err(CoreCryptoError::ad_hoc(format!(
                "`send_commit_bundle` must accept 1 argument but accepts {}",
                send_commit_bundle.length()
            )));
        }
        if send_message.length() != 1 {
            return Err(CoreCryptoError::ad_hoc(format!(
                "`send_message` must accept 1 argument but accepts {}",
                send_message.length()
            )));
        }
        Ok(Self {
            this_context,
            send_commit_bundle,
            send_message,
        })
    }
}

#[cfg(target_family = "wasm")]
#[async_trait::async_trait(?Send)]
impl core_crypto::MlsTransport for MlsTransport {
    /// Send a commit bundle to the corresponding endpoint.
    async fn send_commit_bundle(
        &self,
        commit_bundle: MlsCommitBundle,
    ) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        let commit_bundle = JsValue::from(CommitBundle::try_from(commit_bundle).map_err(|err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!("converting commit bundle to wasm-compatible: {err}"))
        })?);

        let promise = self
            .send_commit_bundle
            .call1(&self.this_context, &commit_bundle)
            .map_err(|js_err| {
                core_crypto::Error::ErrorDuringMlsTransport(format!(
                    "send_commit_bundle received error from js when constructing promise: {js_err:?}"
                ))
            })?
            .dyn_into::<Promise>()
            .map_err(|not_promise| {
                core_crypto::Error::ErrorDuringMlsTransport(format!(
                    "send_commit_bundle received a value that was not a promise: {not_promise:?}"
                ))
            })?;

        let response = JsFuture::from(promise).await.map_err(|err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!(
                "send_commit_bundle received error from js when executing promise: {err:?}"
            ))
        })?;
        let response = serde_wasm_bindgen::from_value::<MlsTransportResponse>(response)
            .map_err(|not_transport_response| {
                core_crypto::Error::ErrorDuringMlsTransport(format!(
                    "send_commit_bundle received a value which was not an MlsTransportResponse after awaiting js promise: {not_transport_response:?}"
                ))
            })?;

        Ok(response.into())
    }

    /// Send a message to the corresponding endpoint.
    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        let mls_message = Uint8Array::from(mls_message.as_slice());

        let promise = self
            .send_message
            .call1(&self.this_context, &mls_message)
            .map_err(|err| {
                core_crypto::Error::ErrorDuringMlsTransport(format!(
                    "send_message received error from js when constructing promise: {err:?}"
                ))
            })?
            .dyn_into::<Promise>()
            .map_err(|not_promise| {
                core_crypto::Error::ErrorDuringMlsTransport(format!(
                    "send_message received a value that was not a promise: {not_promise:?}"
                ))
            })?;

        let response = JsFuture::from(promise).await.map_err(|err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!(
                "send_message received error from js when executing promise: {err:?}"
            ))
        })?;
        let response = serde_wasm_bindgen::from_value::<MlsTransportResponse>(response)
            .map_err(|not_transport_response| {
                core_crypto::Error::ErrorDuringMlsTransport(format!(
                    "send_message received a value which was not an MlsTransportResponse after awaiting js promise: {not_transport_response:?}"
                ))
            })?;

        Ok(response.into())
    }
}

/// In uniffi, `MlsTransport` is a trait which we need to wrap
#[cfg(not(target_family = "wasm"))]
type Callbacks = Arc<dyn MlsTransport>;

#[cfg(not(target_family = "wasm"))]
fn callback_shim(callbacks: Callbacks) -> Arc<dyn core_crypto::MlsTransport> {
    Arc::new(MlsTransportShim::new(callbacks))
}

/// In wasm, `MlsTransport` is an object with some callable members defined.
#[cfg(target_family = "wasm")]
type Callbacks = MlsTransport;

#[cfg(target_family = "wasm")]
fn callback_shim(callbacks: Callbacks) -> Arc<dyn core_crypto::MlsTransport> {
    Arc::new(callbacks)
}

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    /// See [core_crypto::mls::MlsCentral::provide_transport]
    pub async fn provide_transport(&self, callbacks: Callbacks) -> CoreCryptoResult<()> {
        self.inner.provide_transport(callback_shim(callbacks)).await;
        Ok(())
    }
}
