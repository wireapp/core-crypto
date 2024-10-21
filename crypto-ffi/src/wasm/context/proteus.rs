use futures_util::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use wasm_bindgen::JsValue;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen_futures::future_to_promise;
use crate::wasm::context::CoreCryptoContext;
use crate::{ProteusAutoPrekeyBundle, WasmCryptoResult};
use crate::WasmError;
use crate::proteus_impl;
use crate::wasm::CoreCryptoError;

#[wasm_bindgen]
impl CoreCryptoContext {
    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_session_from_prekey]
    pub fn proteus_session_from_prekey(&self, session_id: String, prekey: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    context.proteus_session_from_prekey(&session_id, &prekey).await?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }
    
    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_session_from_message]
    pub fn proteus_session_from_message(&self, session_id: String, envelope: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let (_, payload) = context.proteus_session_from_message(&session_id, &envelope).await?;
                    WasmCryptoResult::Ok(Uint8Array::from(payload.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }
    
    /// Returns: [`WasmCryptoResult<()>`]
    /// 
    /// /// **Note**: This isn't usually needed as persisting sessions happens automatically when decrypting/encrypting messages and initializing Sessions
    /// 
    /// See [core_crypto::context::CentralContext::proteus_session_save]
    pub fn proteus_session_save(&self, session_id: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    context.proteus_session_save(&session_id).await?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }
    
    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_session_delete]
    pub fn proteus_session_delete(&self, session_id: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    context.proteus_session_delete(&session_id).await?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }
    
    /// Returns: [`WasmCryptoResult<bool>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_session_exists]
    pub fn proteus_session_exists(&self, session_id: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let exists = context.proteus_session_exists(&session_id).await?;
                    WasmCryptoResult::Ok(JsValue::from_bool(exists))
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    /// 
    /// See [core_crypto::context::CentralContext::proteus_decrypt]
    pub fn proteus_decrypt(&self, session_id: String, ciphertext: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let cleartext = context.proteus_decrypt(&session_id, &ciphertext).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(cleartext.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Uint8Array>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_encrypt]
    pub fn proteus_encrypt(&self, session_id: String, plaintext: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let encrypted = context.proteus_encrypt(&session_id, &plaintext).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(encrypted.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }.err_into()
        )
    }

    /// Returns: [`WasmCryptoResult<js_sys::Map<string, Uint8Array>>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_encrypt_batched]
    pub fn proteus_encrypt_batched(&self, sessions: Box<[js_sys::JsString]>, plaintext: Box<[u8]>) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let session_ids: Vec<String> = sessions.iter().map(String::from).collect();
                    let batch = context.proteus_encrypt_batched(session_ids.as_slice(), &plaintext).await.map_err(CoreCryptoError::from)?;
                    let js_obj = js_sys::Map::new();
                    for (key, payload) in batch.into_iter() {
                        js_obj.set(&js_sys::JsString::from(key).into(), &Uint8Array::from(payload.as_slice()));
                    }
                    WasmCryptoResult::Ok(js_obj.into())
                } or throw WasmCryptoResult<_> }
            }.err_into()
        )
    }

    /// Returns: [`WasmCryptoResult<Uint8Array>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_new_prekey]
    pub fn proteus_new_prekey(&self, prekey_id: u16) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();
        
        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let prekey_raw = context.proteus_new_prekey(prekey_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(Uint8Array::from(prekey_raw.as_slice()).into())
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<ProteusAutoPrekeyBundle>`]
    /// 
    /// See [core_crypto::context::CentralContext::proteus_new_prekey_auto]
    pub fn proteus_new_prekey_auto(&self) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    let (id, pkb) = context.proteus_new_prekey_auto().await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(ProteusAutoPrekeyBundle { id, pkb }.into())
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Uint8Array>`]
    /// 
    /// See [core_crypto::context::CentralContext::proteus_last_resort_prekey]
    pub fn proteus_last_resort_prekey(&self) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        future_to_promise(async move {
            proteus_impl! { errcode_dest => {
                let last_resort_pkbundle = context.proteus_last_resort_prekey().await.map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(last_resort_pkbundle.as_slice()).into())
            } or throw WasmCryptoResult<_> }
        }.err_into())
    }

    /// Returns: [`WasmCryptoResult<u16>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_last_resort_prekey_id]
    pub fn proteus_last_resort_prekey_id() -> WasmCryptoResult<u16> {
        proteus_impl! {{
            Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id())
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_fingerprint]
    pub async fn proteus_fingerprint(&self) -> WasmCryptoResult<String> {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        proteus_impl! { errcode_dest => {
            context.proteus_fingerprint().await.map_err(CoreCryptoError::from).map(Into::into)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_local]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> WasmCryptoResult<String> {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        proteus_impl! { errcode_dest => {
            context
                .proteus_fingerprint_local(&session_id)
                .await
                .map_err(CoreCryptoError::from)
                .map(Into::into)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_fingerprint_remote]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> WasmCryptoResult<String> {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();

        proteus_impl! { errcode_dest => {
            context.proteus_fingerprint_remote(&session_id).await
                .map_err(CoreCryptoError::from).map(Into::into)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// See [core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle]
    pub fn proteus_fingerprint_prekeybundle(prekey: Box<[u8]>) -> WasmCryptoResult<String> {
        proteus_impl!({
            core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)
                .map_err(Into::into).map(Into::into)
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// See [core_crypto::context::CentralContext::proteus_cryptobox_migrate]
    pub fn proteus_cryptobox_migrate(&self, path: String) -> Promise {
        let errcode_dest = self.proteus_last_error_code.clone();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                proteus_impl! { errcode_dest => {
                    context.proteus_cryptobox_migrate(&path).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::UNDEFINED)
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<u32>`]
    /// 
    /// NOTE: This will clear the last error code.
    pub fn proteus_last_error_code(&self) -> Promise {
        let errcode = self.proteus_last_error_code.clone();
        future_to_promise(
            async move {
                proteus_impl! {{
                    let prev_value: u32 = *(errcode.read().await);
                    let mut errcode_val = errcode.write().await;
                    *errcode_val = 0;

                    WasmCryptoResult::Ok(prev_value.into())
                } or throw WasmCryptoResult<_> }
            }
                .err_into(),
        )
    }
}