use async_trait::async_trait;
use core_crypto::prelude::Obfuscated;
#[cfg(target_family = "wasm")]
use js_sys::Promise;
#[cfg(target_family = "wasm")]
use log::kv;
use std::sync::Arc;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(target_family = "wasm")]
use wasm_bindgen_futures::JsFuture;

#[cfg(target_family = "wasm")]
use crate::ConversationId;
#[cfg(not(target_family = "wasm"))]
use crate::ConversationIdMaybeArc;
use crate::{CoreCrypto, CoreCryptoError, CoreCryptoResult, conversation_id_coerce_maybe_arc};
use ::core_crypto::prelude::ConversationId as InternalConversationId;

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
    /// This function must not block! Foreign implementors of this interface can
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
        conversation_id: ConversationIdMaybeArc,
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
    async fn epoch_changed(&self, conversation_id: InternalConversationId, epoch: u64) {
        if let Err(err) = self
            .0
            .epoch_changed(conversation_id_coerce_maybe_arc(&conversation_id), epoch)
            .await
        {
            // we don't _care_ if an error is thrown by the notification function, per se,
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
    /// This function should be called 0 or 1 times in a session's lifetime. If called
    /// when an epoch observer already exists, this will return an error.
    pub async fn register_epoch_observer(&self, epoch_observer: Arc<dyn EpochObserver>) -> CoreCryptoResult<()> {
        let shim = Arc::new(ObserverShim(epoch_observer));
        self.inner
            .register_epoch_observer(shim)
            .await
            .map_err(CoreCryptoError::generic())
    }
}

/// An `EpochObserver` is notified whenever a conversation's epoch changes.
#[cfg(target_family = "wasm")]
#[wasm_bindgen]
#[derive(derive_more::Debug)]
#[debug("EpochObserver")]
pub struct EpochObserver {
    this_context: JsValue,
    epoch_changed: js_sys::Function,
}

#[cfg(target_family = "wasm")]
// SAFETY: we promise that we're only ever using this in a single-threaded context
unsafe impl Send for EpochObserver {}
#[cfg(target_family = "wasm")]
// SAFETY: we promise that we're only ever using this in a single-threaded context
unsafe impl Sync for EpochObserver {}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl EpochObserver {
    /// Create a new Epoch Observer.
    ///
    /// This function should be hidden on the JS side of things! The JS bindings should have an `interface EpochObserver`
    /// which has the method defined, and the bindings themselves should destructure an instance implementing that
    /// interface appropriately to construct this.
    ///
    /// - `this_context` is the instance itself, which will be bound to `this` within the function bodies
    /// - `epoch_changed`: A function of the form `(conversation_id: Uint8Array, epoch: bigint) -> Promise<void>`.
    ///   Called every time a conversation's epoch changes.
    #[wasm_bindgen(constructor)]
    pub fn new(this_context: JsValue, epoch_changed: js_sys::Function) -> CoreCryptoResult<Self> {
        // we can't do much type-checking here unfortunately, but we can at least validate that the incoming functions have the right length
        if epoch_changed.length() != 2 {
            return Err(CoreCryptoError::ad_hoc(format!(
                "`epoch_changed` must accept 2 arguments but accepts {}",
                epoch_changed.length()
            )));
        }
        Ok(Self {
            this_context,
            epoch_changed,
        })
    }
}

#[cfg(target_family = "wasm")]
impl EpochObserver {
    /// Call the JS `epoch_observed` function
    ///
    /// This blocks if the JS side of things blocks.
    ///
    /// This is extracted as its own function instead of being implemented inline within the
    /// `impl EpochObserver for EpochObserver` block mostly to consolidate error-handling.
    async fn epoch_changed(&self, conversation_id: ConversationId, epoch: u64) -> Result<(), JsValue> {
        let promise = self
            .epoch_changed
            .call2(&self.this_context, &conversation_id.into(), &epoch.into())?
            .dyn_into::<Promise>()?;
        // we don't actually care what the result of executing the notification promise is; we'll ignore it if it exists
        JsFuture::from(promise).await?;
        Ok(())
    }
}

#[cfg(target_family = "wasm")]
#[async_trait(?Send)]
impl core_crypto::mls::EpochObserver for EpochObserver {
    async fn epoch_changed(&self, conversation_id: InternalConversationId, epoch: u64) {
        if let Err(err) = self
            .epoch_changed(conversation_id_coerce_maybe_arc(&conversation_id), epoch)
            .await
        {
            // we don't _care_ if an error is thrown by the notification function, per se,
            // but this would probably be useful information for downstream debugging efforts
            log::warn!(
                conversation_id = Obfuscated::new(&conversation_id),
                epoch,
                err = LoggableJsValue(err);
                "caught an error when attempting to notify the epoch observer of an epoch change"
            );
        }
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
        self.inner
            .register_epoch_observer(Arc::new(epoch_observer))
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
