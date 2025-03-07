use std::sync::Arc;

use async_trait::async_trait;
use core_crypto::prelude::ConversationId;
use wasm_bindgen::prelude::*;

use crate::{InternalError, wasm::CoreCryptoResult};

use super::CoreCryptoContext;

#[wasm_bindgen]
extern "C" {
    /// An `EpochObserver` is notified whenever a conversation's epoch changes.
    pub type EpochObserver;

    /// Receivers of this callback should return _fast_, and delegate any real work to other tasks.
    ///
    /// Buffering of epoch change notifications is very limited, and notifications will be silently
    /// dropped if the buffer is full.
    #[wasm_bindgen(structural, method)]
    pub async fn epoch_changed(this: &EpochObserver, conversation_id: ConversationId, epoch: u64);
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
struct ObserverShim(async_channel::Sender<(ConversationId, u64)>);

#[async_trait]
impl core_crypto::mls::EpochObserver for ObserverShim {
    async fn epoch_changed(&self, conversation_id: ConversationId, epoch: u64) {
        // if this channel is full or disconnected, drop the message
        let _ = self.0.try_send((conversation_id, epoch));
    }
}

#[wasm_bindgen]
impl CoreCryptoContext {
    /// Add an epoch observer to this client.
    ///
    /// This function should be called 0 or 1 times in a client's lifetime.
    /// If called when an epoch observer already exists, this will return an error.
    pub async fn register_epoch_observer(&self, epoch_observer: EpochObserver) -> CoreCryptoResult<()> {
        let (tx, rx) = async_channel::bounded(1);
        let shim = Arc::new(ObserverShim(tx));
        wasm_bindgen_futures::spawn_local(async move {
            loop {
                match rx.recv().await {
                    Ok((conversation_id, epoch)) => epoch_observer.epoch_changed(conversation_id, epoch).await,
                    Err(_) => {
                        // channel was closed
                        break;
                    }
                }
            }
        });
        self.inner
            .register_epoch_observer(shim)
            .await
            .map_err(InternalError::generic())
            .map_err(Into::into)
    }
}
