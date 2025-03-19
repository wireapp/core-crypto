use std::sync::Arc;

use async_trait::async_trait;
use core_crypto::prelude::{ConversationId, Obfuscated};
#[cfg(target_family = "wasm")]
use log::kv;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{CoreCrypto, CoreCryptoError, CoreCryptoResult};

#[cfg(not(target_family = "wasm"))]
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum EpochChangedReportingError {
    #[error("panic or otherwise unexpected error from foreign code")]
    Ffi(#[from] uniffi::UnexpectedUniFFICallbackError),
}

/// An `EpochObserver` is notified whenever a conversation's epoch changes.
#[cfg(not(target_family = "wasm"))]
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
#[cfg(not(target_family = "wasm"))]
struct ObserverShim(Arc<dyn EpochObserver>);

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl core_crypto::mls::EpochObserver for ObserverShim {
    async fn epoch_changed(&self, conversation_id: ConversationId, epoch: u64) {
        if let Err(err) = self.0.epoch_changed(conversation_id.clone(), epoch).await {
            // we don't _care_ if an error is thrown by the the notification function, per se,
            // but this would probably be useful information for downstream debugging efforts
            log::warn!(
                conversation_id = Obfuscated::new(&conversation_id),
                epoch,
                err = log::kv::Value::from_dyn_error(&err);
                "caught an error when attempting to notify the epoch observer of an epoch change"
            );
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
impl CoreCrypto {
    /// Add an epoch observer to this client.
    ///
    /// This function should be called 0 or 1 times in a client's lifetime.
    /// If called when an epoch observer already exists, this will return an error.
    pub async fn register_epoch_observer(&self, epoch_observer: Arc<dyn EpochObserver>) -> CoreCryptoResult<()> {
        let shim = Arc::new(ObserverShim(epoch_observer));
        self.inner
            .register_epoch_observer(shim)
            .await
            .map_err(CoreCryptoError::generic())
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
extern "C" {
    /// An `EpochObserver` is notified whenever a conversation's epoch changes.
    pub type EpochObserver;

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
    #[wasm_bindgen(structural, method, catch)]
    pub async fn epoch_changed(
        this: &EpochObserver,
        conversation_id: ConversationId,
        epoch: u64,
    ) -> Result<(), JsValue>;
}

/// This shim bridges the public `EpochObserver` interface with the internal one defined by `core-crypto`.
///
/// The shim must be `Send + Sync` in order to implement `core_crypto::mls::EpochObserver`, which means
/// that it cannot simply wrap the `EpochObserver` duck type that Js gives us; `JsValue` instances are
/// very intentionally _not_ `Sync` or `Send`.
///
/// Luckily, we have a mechanism to connect unrelated structs without wrapping: channels! So we'll give
/// this shim the sender, and then spawn a task to ensure that the messages on the channel get passed
/// back to the JS side.
#[cfg(target_family = "wasm")]
struct ObserverShim(async_channel::Sender<(ConversationId, u64)>);

#[cfg(target_family = "wasm")]
#[async_trait]
impl core_crypto::mls::EpochObserver for ObserverShim {
    async fn epoch_changed(&self, conversation_id: ConversationId, epoch: u64) {
        // if this channel is full or disconnected, drop the message
        let _ = self.0.try_send((conversation_id, epoch));
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCrypto {
    /// Add an epoch observer to this client.
    ///
    /// This function should be called 0 or 1 times in a client's lifetime.
    /// If called when an epoch observer already exists, this will return an error.
    pub async fn register_epoch_observer(&self, epoch_observer: EpochObserver) -> CoreCryptoResult<()> {
        let (tx, rx) = async_channel::bounded(1);
        let shim = Arc::new(ObserverShim(tx));
        wasm_bindgen_futures::spawn_local(async move {
            while let Ok((conversation_id, epoch)) = rx.recv().await {
                if let Err(err) = epoch_observer.epoch_changed(conversation_id.clone(), epoch).await {
                    // we don't _care_ if an error is thrown by the the notification function, per se,
                    // but this would probably be useful information for downstream debugging efforts
                    log::warn!(
                        conversation_id = Obfuscated::new(&conversation_id),
                        epoch,
                        err = LoggableJsValue(err);
                        "caught an error when attempting to notify the epoch observer of an epoch change"
                    );
                }
            }
            // if the channel ever closes or produces an error, this task will complete
        });
        self.inner
            .register_epoch_observer(shim)
            .await
            .map_err(CoreCryptoError::generic())
    }
}

#[cfg(target_family = "wasm")]
struct LoggableJsValue(JsValue);

#[cfg(target_family = "wasm")]
impl kv::ToValue for LoggableJsValue {
    fn to_value(&self) -> kv::Value<'_> {
        // can't get a borrowed str from `JsValue`, so can't directly
        // convert into a string; oh well; fallback should catch it
        if let Some(f) = self.0.as_f64() {
            return f.into();
        }
        if let Some(b) = self.0.as_bool() {
            return b.into();
        }
        if self.0.is_null() || self.0.is_undefined() {
            return kv::Value::null();
        }
        kv::Value::from_debug(&self.0)
    }
}
