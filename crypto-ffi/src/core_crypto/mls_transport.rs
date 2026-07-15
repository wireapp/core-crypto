//! Implement the MLS Transport interface.
//!
//! Unfortunately, there is no good way to reuse code between uniffi and wasm for an interface
//! like this; the fundamental techniques in use are very different. So we just have to feature-gate
//! everything.
use std::{fmt, sync::Arc};

use core_crypto::{CommitBundle as CryptoCommitBundle, HistorySecret};
use futures_util::{FutureExt as _, TryFutureExt as _};

use crate::{
    ClientId, CommitBundle, HistorySecret as HistorySecretFfi, cancellation::CancellationSlot,
    error::mls_transport::MlsTransportResult,
};

/// Application data packaged to be encrypted and transmitted in an MLS application message.
//
// TODO: We derive Constructor here only because we need to construct an instance in interop.
// Remove it once we drop the FFI client from interop.
#[derive(Debug, derive_more::From, derive_more::Into, derive_more::Deref, derive_more::Constructor)]
pub struct MlsTransportData(core_crypto::TransportData);

uniffi::custom_type!(MlsTransportData, Vec<u8>, {
    lower: |key| key.0.to_vec(),
    try_lift: |vec| {
        Ok(MlsTransportData(core_crypto::TransportData::from(vec)))
    }
});

/// Used by CoreCrypto to send commits or application messages to the delivery service.
///
/// This trait must be implemented before calling any functions that produce commits.
#[uniffi::export(with_foreign)]
#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
pub trait MlsTransport: Send + Sync {
    /// Send a commit bundle to the corresponding endpoint.
    async fn send_commit_bundle(&self, commit_bundle: CommitBundle) -> MlsTransportResult;
    /// Prepare a history secret before transmission.
    async fn prepare_for_transport(&self, history_secret: HistorySecretFfi) -> MlsTransportData;
}

#[derive(derive_more::Constructor)]
struct MlsTransportShim {
    callbacks: Arc<dyn MlsTransport>,
    cancellation_slot: Arc<CancellationSlot>,
}

impl std::fmt::Debug for MlsTransportShim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MlsTransportShim")
            .field(&fmt::from_fn(|f| write!(f, "{:p}", Arc::as_ptr(&self.callbacks))))
            .finish()
    }
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl core_crypto::MlsTransport for MlsTransportShim {
    async fn send_commit_bundle(&self, commit_bundle: CryptoCommitBundle) -> core_crypto::Result<()> {
        let commit_bundle = CommitBundle::try_from(commit_bundle)
            .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(e.to_string()))?;

        race_callback(
            &self.cancellation_slot,
            async { self.callbacks.send_commit_bundle(commit_bundle) }
                .await
                .map_err(Into::into),
        )
        .await
    }

    async fn prepare_for_transport(&self, secret: &HistorySecret) -> core_crypto::Result<core_crypto::TransportData> {
        // This callback is expected to perform only short-running local preparation,
        // so it is intentionally not raced against transaction cancellation.
        let client_id = ClientId::from(secret.client_id.clone()).into();
        let history_secret = rmp_serde::to_vec(&secret)
            .map(|secret| HistorySecretFfi {
                client_id,
                data: secret,
            })
            .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(e.to_string()))?;
        Ok(self.callbacks.prepare_for_transport(history_secret).await.into())
    }
}

/// In uniffi, `MlsTransport` is a trait which we need to wrap, and we need to provide the transport shim with the
/// cancellation slot of core crypto.
pub(crate) fn callback_shim(
    callbacks: Arc<dyn MlsTransport>,
    cancellation_slot: Arc<CancellationSlot>,
) -> Arc<dyn core_crypto::MlsTransport> {
    Arc::new(MlsTransportShim::new(callbacks, cancellation_slot))
}

async fn race_callback<T>(
    slot: &CancellationSlot,
    callback: impl Future<Output = core_crypto::Result<T>>,
) -> core_crypto::Result<T> {
    let Some(token) = slot
        .current()
        .map_err(|e| core_crypto::Error::ErrorDuringMlsTransport(e.to_string()))?
    else {
        return callback.await;
    };

    // Futures used with select_biased!{} need to be `Fuse` instances. select_biased!{} prefers the first declared
    // future in case both finish at the same time.
    let result = futures_util::select_biased! {
        result = callback.fuse() => result,
        _ = token.cancelled().fuse() => Err(core_crypto::Error::ErrorDuringMlsTransport("cancelled via cancellation token".into())),
    };

    result
}
