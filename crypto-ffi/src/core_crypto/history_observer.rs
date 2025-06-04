use std::sync::Arc;

use async_trait::async_trait;
#[cfg(target_family = "wasm")]
use js_sys::{Promise, Uint8Array};
#[cfg(target_family = "wasm")]
use log::kv;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(target_family = "wasm")]
use wasm_bindgen_futures::JsFuture;

use crate::{CoreCrypto, CoreCryptoError, CoreCryptoResult, HistorySecret};
use core_crypto::prelude::{ConversationId, Obfuscated};

#[cfg(not(target_family = "wasm"))]
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum NewHistoryClientReportingError {
    #[error("panic or otherwise unexpected error from foreign code")]
    Ffi(#[from] uniffi::UnexpectedUniFFICallbackError),
}

/// An `HistoryObserver` is notified whenever a new history client is created.
#[cfg(not(target_family = "wasm"))]
#[uniffi::export(with_foreign)]
#[async_trait]
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
        conversation_id: ConversationId,
        secret: HistorySecret,
    ) -> Result<(), NewHistoryClientReportingError>;
}

/// This shim bridges the public `HistoryObserver` interface with the internal one defined by `core-crypto`.
///
/// This is slightly unfortunate, as it introduces an extra layer of indirection before a change notice can
/// actually reach its foreign target. However, the orphan rule prevents us from just tying the two traits
/// together directly, so this is the straightforward way to accomplish that.
#[cfg(not(target_family = "wasm"))]
struct ObserverShim(Arc<dyn HistoryObserver>);

#[cfg(not(target_family = "wasm"))]
#[async_trait]
impl core_crypto::mls::HistoryObserver for ObserverShim {
    async fn history_client_created(
        &self,
        conversation_id: ConversationId,
        secret: &core_crypto::prelude::HistorySecret,
    ) {
        if let Err(err) = HistorySecret::try_from(secret)
            .map(async |secret| self.0.history_client_created(conversation_id.clone(), secret).await)
        {
            // we don't _care_ if an error is thrown by the notification function, per se,
            // but this would probably be useful information for downstream debugging efforts
            log::warn!(
                conversation_id = Obfuscated::new(&conversation_id),
                err = log::kv::Value::from_dyn_error(&err);
                "caught an error when attempting to notify the history observer of a new history client"
            );
        }
    }
}

#[cfg(not(target_family = "wasm"))]
#[uniffi::export]
impl CoreCrypto {
    /// Add a history observer to this client.
    ///
    /// This function should be called 0 or 1 times in a session's lifetime. If called
    /// when an history observer already exists, this will return an error.
    pub async fn register_history_observer(&self, history_observer: Arc<dyn HistoryObserver>) -> CoreCryptoResult<()> {
        let shim = Arc::new(ObserverShim(history_observer));
        self.inner
            .register_history_observer(shim)
            .await
            .map_err(CoreCryptoError::generic())
    }
}

/// An `HistoryObserver` is notified whenever a new history client is created.
#[cfg(target_family = "wasm")]
#[wasm_bindgen]
#[derive(derive_more::Debug)]
#[debug("HistoryObserver")]
pub struct HistoryObserver {
    this_context: JsValue,
    history_client_created: js_sys::Function,
}

#[cfg(target_family = "wasm")]
// SAFETY: we promise that we're only ever using this in a single-threaded context
unsafe impl Send for HistoryObserver {}
#[cfg(target_family = "wasm")]
// SAFETY: we promise that we're only ever using this in a single-threaded context
unsafe impl Sync for HistoryObserver {}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl HistoryObserver {
    /// Create a new history observer.
    ///
    /// This function should be hidden on the JS side of things! The JS bindings should have an `interface HistoryObserver`
    /// which has the method defined, and the bindings themselves should destructure an instance implementing that
    /// interface appropriately to construct this.
    ///
    /// - `this_context` is the instance itself, which will be bound to `this` within the function bodies
    /// - `history_client_created`: A function of the form `(conversation_id: Uint8Array, secret: HistorySecret) -> Promise<void>`.
    ///
    ///   Called every time a history client is created.
    #[wasm_bindgen(constructor)]
    pub fn new(this_context: JsValue, history_client_created: js_sys::Function) -> CoreCryptoResult<Self> {
        // we can't do much type-checking here unfortunately, but we can at least validate that the incoming functions have the right length
        if history_client_created.length() != 2 {
            return Err(CoreCryptoError::ad_hoc(format!(
                "`history_client_created` must accept 2 arguments but accepts {}",
                history_client_created.length()
            )));
        }
        Ok(Self {
            this_context,
            history_client_created,
        })
    }
}

#[cfg(target_family = "wasm")]
impl HistoryObserver {
    /// Call the JS `history_client_created` function
    ///
    /// This blocks if the JS side of things blocks.
    ///
    /// This is extracted as its own function instead of being implemented inline within the
    /// `impl HistoryObserver for HistoryObserver` block mostly to consolidate error-handling.
    async fn history_client_created(&self, conversation_id: ConversationId, secret: JsValue) -> Result<(), JsValue> {
        let conversation_id = Uint8Array::from(conversation_id.as_slice());

        let promise = self
            .history_client_created
            .call2(&self.this_context, &conversation_id.into(), &secret)?
            .dyn_into::<Promise>()?;
        // we don't actually care what the result of executing the notification promise is; we'll ignore it if it exists
        JsFuture::from(promise).await?;
        Ok(())
    }
}

#[cfg(target_family = "wasm")]
#[async_trait(?Send)]
impl core_crypto::mls::HistoryObserver for HistoryObserver {
    async fn history_client_created(
        &self,
        conversation_id: ConversationId,
        secret: &core_crypto::prelude::HistorySecret,
    ) {
        if let Err(err) = HistorySecret::try_from(secret).map(async |secret| {
            self.history_client_created(conversation_id.clone(), secret.into())
                .await
        }) {
            // we don't _care_ if an error is thrown by the notification function, per se,
            // but this would probably be useful information for downstream debugging efforts
            log::warn!(
                conversation_id = Obfuscated::new(&conversation_id),
                err = LoggableJsValue(err.into());
                "caught an error when attempting to notify the history observer of a new history client"
            );
        }
        todo!()
    }
}

#[cfg(target_family = "wasm")]
#[wasm_bindgen]
impl CoreCrypto {
    /// Add a history observer to this client.
    ///
    /// This function should be called 0 or 1 times in a client's lifetime.
    /// If called when an history observer already exists, this will return an error.
    pub async fn register_history_observer(&self, history_observer: HistoryObserver) -> CoreCryptoResult<()> {
        self.inner
            .register_history_observer(Arc::new(history_observer))
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
