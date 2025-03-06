use std::sync::Arc;

use async_trait::async_trait;
use core_crypto::prelude::ConversationId;

use crate::{CoreCryptoError, generic::CoreCryptoResult};

use super::CoreCrypto;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum EpochChangedReportingError {
    #[error("panic or otherwise unexpected error from foreign code")]
    Ffi(#[from] uniffi::UnexpectedUniFFICallbackError),
}

/// An `EpochObserver` is notified whenever a conversation's epoch changes.
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait EpochObserver: Send + Sync {
    /// This function will be called every time a conversation's epoch changes.
    ///
    /// The `epoch` parameter is the new epoch.
    ///
    /// <div class="warning">
    /// This function must not block! Foreign implementors of this inteface can
    /// spawn a task indirecting the notification, or (unblocking) send the notification
    /// on some kind of channel, or anything else, as long as the operation completes
    /// quickly.
    /// </div>
    ///
    /// Though the signature includes an error type, that error is only present because
    /// it is required by `uniffi` in order to handle panics. This function should suppress
    /// and ignore internal errors instead of propagating them, to the maximum extent possible.
    async fn epoch_changed(
        &self,
        conversation_id: ConversationId,
        epoch: u64,
    ) -> Result<(), EpochChangedReportingError>;
}

/// This shim bridges the public `EpochObserver` interface with the internal one defined by `core-crypto`.
///
/// This is slightly unfortunate, as it introduces an extra layer of indirection before a change notice can
/// actually reach its foreign target. However, the orphan rule prevents us from just tying the two traits
/// together directly, so this is the straightforward way to accomplish that.
struct ObserverShim(Arc<dyn EpochObserver>);

#[async_trait]
impl core_crypto::mls::EpochObserver for ObserverShim {
    async fn epoch_changed(&self, conversation_id: ConversationId, epoch: u64) {
        // We want to ignore all errors arising from the change notice function.
        // It should be purely fire-and-forget.
        let _ = self.0.epoch_changed(conversation_id, epoch).await;
    }
}

#[uniffi::export]
impl CoreCrypto {
    /// Add an epoch observer to this client.
    ///
    /// This function should be called 0 or 1 times in a client's lifetime.
    /// If called when an epoch observer already exists, this will return an error.
    pub async fn register_epoch_observer(&self, epoch_observer: Arc<dyn EpochObserver>) -> CoreCryptoResult<()> {
        let shim = Arc::new(ObserverShim(epoch_observer));
        self.central
            .register_epoch_observer(shim)
            .await
            .map_err(CoreCryptoError::generic())
    }
}
