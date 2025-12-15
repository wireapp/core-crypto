use std::sync::Arc;

use async_trait::async_trait;

use crate::{ConversationId, CoreCryptoError, CoreCryptoFfi, CoreCryptoResult, HistorySecret};

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum NewHistoryClientReportingError {
    #[error("panic or otherwise unexpected error from foreign code")]
    Ffi(#[from] uniffi::UnexpectedUniFFICallbackError),
}

/// An `HistoryObserver` is notified whenever a new history client is created.
#[uniffi::export(with_foreign)]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait HistoryObserver: Send + Sync {
    /// This function will be called every time a new history client is created.
    ///
    /// The `secret` parameter is the secret associated with the new history client
    ///
    /// <div class="warning">
    /// This function must not block! Foreign implementors of this interface can
    /// spawn a task indirecting the notification, or (unblocking) send the notification
    /// on some kind of channel, or anything else, as long as the operation completes
    /// quickly.
    /// </div>
    ///
    /// Though the signature includes an error type, that error is only present because
    /// it is required by `uniffi` in order to handle panics. This function should suppress
    /// and ignore internal errors instead of propagating them, to the maximum extent possible.
    async fn history_client_created(
        &self,
        conversation_id: Arc<ConversationId>,
        secret: HistorySecret,
    ) -> Result<(), NewHistoryClientReportingError>;
}

/// This shim bridges the public `HistoryObserver` interface with the internal one defined by `core-crypto`.
///
/// This is slightly unfortunate, as it introduces an extra layer of indirection before a change notice can
/// actually reach its foreign target. However, the orphan rule prevents us from just tying the two traits
/// together directly, so this is the straightforward way to accomplish that.
struct ObserverShim(Arc<dyn HistoryObserver>);

#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl core_crypto::mls::HistoryObserver for ObserverShim {
    async fn history_client_created(
        &self,
        conversation_id: core_crypto::ConversationId,
        secret: &core_crypto::HistorySecret,
    ) {
        let Ok(secret) = HistorySecret::try_from(secret) else {
            // weird that we couldn't convert this but ¯\_(ツ)_/¯
            log::warn!(
                conversation_id = conversation_id;
                "failed to convert to ffi history secret during creation notification");
            return;
        };
        if let Err(err) = self
            .0
            .history_client_created(Arc::new(ConversationId(conversation_id.clone().into())), secret)
            .await
        {
            // we don't _care_ if an error is thrown by the notification function, per se,
            // but this would probably be useful information for downstream debugging efforts
            log::warn!(
                conversation_id = conversation_id,
                err = log::kv::Value::from_dyn_error(&err);
                "caught an error when attempting to notify the history observer of a new history client"
            );
        }
    }
}

#[uniffi::export]
impl CoreCryptoFfi {
    /// Add a history observer to this client.
    ///
    /// This function should be called 0 or 1 times in a session's lifetime. If called
    /// when an history observer already exists, this will return an error.
    pub async fn register_history_observer(&self, history_observer: Arc<dyn HistoryObserver>) -> CoreCryptoResult<()> {
        let shim = Arc::new(ObserverShim(history_observer));
        self.inner
            .mls_session()
            .await?
            .register_history_observer(shim)
            .await
            .map_err(CoreCryptoError::generic())
    }
}
