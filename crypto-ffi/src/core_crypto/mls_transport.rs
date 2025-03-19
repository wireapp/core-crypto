//! Implement the MLS Transport interface.
//!
//! Unfortunately, there is no good way to reuse code between uniffi and wasm for an interface
//! like this; the fundamental techniques in use are very different. So we just have to feature-gate
//! everything.

#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use std::{fmt, sync::Arc};

use core_crypto::prelude::MlsCommitBundle;

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

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
extern "C" {
    /// Used by core crypto to send commits or application messages to the delivery service.
    /// This trait must be implemented before calling any functions that produce commits.
    pub type MlsTransport;

    /// Send a commit bundle to the corresponding endpoint.
    #[wasm_bindgen(structural, method, catch, js_name = sendCommitBundle, unchecked_return_type = "MlsTransportResponse")]
    pub async fn send_commit_bundle(this: &MlsTransport, commit_bundle: CommitBundle) -> Result<JsValue, JsValue>;

    /// Send a message to the corresponding endpoint.
    #[wasm_bindgen(structural, method, catch, js_name = sendMessage, unchecked_return_type = "MlsTransportResponse")]
    pub async fn send_message(this: &MlsTransport, mls_message: Vec<u8>) -> Result<JsValue, JsValue>;
}

#[cfg(target_family = "wasm")]
struct MlsTransportShim(Arc<async_lock::Mutex<MlsTransport>>);

#[cfg(target_family = "wasm")]
// SAFETY: by wrapping the foreign thing in Arc<Mutex<_>>, we make this value safe to transport and view between threads
unsafe impl Send for MlsTransportShim {}

#[cfg(target_family = "wasm")]
// SAFETY: by wrapping the foreign thing in Arc<Mutex<_>>, we make this value safe to transport and view between threads
unsafe impl Sync for MlsTransportShim {}

#[cfg(target_family = "wasm")]
impl fmt::Debug for MlsTransportShim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MlsTransportShim")
            .field(&"Arc<Mutex<MlsTransport>>")
            .finish()
    }
}

#[cfg(target_family = "wasm")]
impl MlsTransportShim {
    fn new(mls_transport: MlsTransport) -> Self {
        // we implement send and sync on self because of the arc/mutex thing
        #[expect(clippy::arc_with_non_send_sync)]
        Self(Arc::new(async_lock::Mutex::new(mls_transport)))
    }
}

#[cfg(target_family = "wasm")]
#[async_trait::async_trait(?Send)]
impl core_crypto::MlsTransport for MlsTransportShim {
    /// Send a commit bundle to the corresponding endpoint.
    async fn send_commit_bundle(
        &self,
        commit_bundle: MlsCommitBundle,
    ) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        let commit_bundle = commit_bundle.try_into().map_err(|err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!("converting commit bundle to wasm-compatible: {err}"))
        })?;
        let guard = self.0.lock().await;
        let response = guard.send_commit_bundle(commit_bundle).await.map_err(|js_err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!(
                "send_commit_bundle received errror from js: {js_err:?}"
            ))
        })?;
        let response = serde_wasm_bindgen::from_value::<MlsTransportResponse>(response).map_err(|err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!(
                "send_commit_bundle erred when deserializing response: {err}"
            ))
        })?;
        Ok(response.into())
    }

    /// Send a message to the corresponding endpoint.
    async fn send_message(&self, mls_message: Vec<u8>) -> core_crypto::Result<core_crypto::MlsTransportResponse> {
        let guard = self.0.lock().await;
        let response = guard.send_message(mls_message).await.map_err(|js_err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!("send_message received errror from js: {js_err:?}"))
        })?;
        let response = serde_wasm_bindgen::from_value::<MlsTransportResponse>(response).map_err(|err| {
            core_crypto::Error::ErrorDuringMlsTransport(format!(
                "send_message erred when deserializing response: {err}"
            ))
        })?;
        Ok(response.into())
    }
}

/// In uniffi, `MlsTransport` is a trait which we need to wrap
#[cfg(not(target_family = "wasm"))]
type Callbacks = Arc<dyn MlsTransport>;

/// In wasm, `MlsTransport` is an object, a `JsValue` that someone promised duck-types to the right interface.
#[cfg(target_family = "wasm")]
type Callbacks = MlsTransport;

#[cfg_attr(target_family = "wasm", wasm_bindgen)]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl CoreCrypto {
    /// See [core_crypto::mls::MlsCentral::provide_transport]
    pub async fn provide_transport(&self, callbacks: Callbacks) -> CoreCryptoResult<()> {
        self.inner
            .provide_transport(Arc::new(MlsTransportShim::new(callbacks)))
            .await;
        Ok(())
    }
}
