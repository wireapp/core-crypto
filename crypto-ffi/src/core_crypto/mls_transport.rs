//! Implement the MLS Transport interface.
//!
//! Unfortunately, there is no good way to reuse code between uniffi and wasm for an interface
//! like this; the fundamental techniques in use are very different. So we just have to feature-gate
//! everything.
use std::{fmt, sync::Arc};

use core_crypto::{HistorySecret, MlsCommitBundle};

use crate::{ClientId, CommitBundle, CoreCryptoFfi, CoreCryptoResult, HistorySecret as HistorySecretFfi};

/// MLS transport may or may not succeeed; this response indicates to CC the outcome of the transport attempt.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum MlsTransportResponse {
    /// The message was accepted by the distribution service
    Success,
    /// A client should have consumed all incoming messages before re-trying.
    Retry,
    /// The message was rejected by the delivery service and there's no recovery.
    Abort {
        /// Why was this message rejected
        reason: String,
    },
}

/// An entity / data which has been packaged by the application to be encrypted
/// and transmitted in an application message.
//
// TODO: We derive Constructor here only because we need to construct an instance in interop.
// Remove it once we drop the FFI client from interop.
#[derive(Debug, derive_more::From, derive_more::Into, derive_more::Deref, derive_more::Constructor)]
pub struct MlsTransportData(core_crypto::MlsTransportData);

uniffi::custom_type!(MlsTransportData, Vec<u8>, {
    lower: |key| key.0.to_vec(),
    try_lift: |vec| {
        Ok(MlsTransportData(core_crypto::MlsTransportData::from(vec)))
    }
});

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
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MlsTransport: Send + Sync {
    /// Send a commit bundle to the corresponding endpoint.
    async fn send_commit_bundle(&self, commit_bundle: CommitBundle) -> MlsTransportResponse;
    /// Send a message to the corresponding endpoint.
    async fn send_message(&self, mls_message: Vec<u8>) -> MlsTransportResponse;
    /// Prepare a history secret before being sent
    async fn prepare_for_transport(&self, history_secret: HistorySecretFfi) -> MlsTransportData;
}

#[derive(derive_more::Constructor)]
struct MlsTransportShim(Arc<dyn MlsTransport>);

impl std::fmt::Debug for MlsTransportShim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MlsTransportShim")
            .field(&"Arc<dyn MlsTransport>")
            .finish()
    }
}

#[async_trait::async_trait]
impl core_crypto::MlsTransport for MlsTransportShim {
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

    async fn prepare_for_transport(
        &self,
        secret: &HistorySecret,
    ) -> core_crypto::Result<core_crypto::MlsTransportData> {
        let client_id = ClientId::from_cc(secret.client_id.clone());
        let history_secret = rmp_serde::to_vec(&secret)
            .map(|secret| HistorySecretFfi {
                client_id,
                data: secret,
            })
            .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(e.to_string()))?;
        Ok(self.0.prepare_for_transport(history_secret).await.into())
    }
}

/// In uniffi, `MlsTransport` is a trait which we need to wrap
fn callback_shim(callbacks: Arc<dyn MlsTransport>) -> Arc<dyn core_crypto::MlsTransport> {
    Arc::new(MlsTransportShim::new(callbacks))
}

#[uniffi::export]
impl CoreCryptoFfi {
    /// See [core_crypto::Session::provide_transport]
    pub async fn provide_transport(&self, callbacks: Arc<dyn MlsTransport>) -> CoreCryptoResult<()> {
        self.inner.provide_transport(callback_shim(callbacks)).await;
        Ok(())
    }
}
