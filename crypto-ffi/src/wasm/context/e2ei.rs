use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};

use crate::{
    Ciphersuite, CoreCryptoError, CredentialType, CrlRegistration, E2eiDumpedPkiEnv, E2eiEnrollment, InternalError,
    WasmCryptoResult, WireIdentity,
    wasm::{E2eiConversationState, context::CoreCryptoContext},
};
use core_crypto::mls::conversation::Conversation as _;
use core_crypto::{
    RecursiveError,
    prelude::{CiphersuiteName, ClientId, ConversationId, MlsCiphersuite, VerifiableGroupInfo},
};
use futures_util::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use tls_codec::Deserialize;
use wasm_bindgen::{JsValue, prelude::wasm_bindgen};
use wasm_bindgen_futures::future_to_promise;

#[wasm_bindgen]
impl CoreCryptoContext {
    /// Returns: [`WasmCryptoResult<E2eiEnrollment>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::e2ei_new_enrollment]
    pub fn e2ei_new_enrollment(
        &self,
        client_id: String,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let enrollment = context
                    .e2ei_new_enrollment(
                        client_id.into_bytes().into(),
                        display_name,
                        handle,
                        team,
                        expiry_sec,
                        ciphersuite.into(),
                    )
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<E2eiEnrollment>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::e2ei_new_activation_enrollment]
    pub fn e2ei_new_activation_enrollment(
        &self,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let enrollment = context
                    .e2ei_new_activation_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<E2eiEnrollment>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::e2ei_new_rotate_enrollment]
    pub fn e2ei_new_rotate_enrollment(
        &self,
        display_name: Option<String>,
        handle: Option<String>,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: Ciphersuite,
    ) -> Promise {
        let ciphersuite: CiphersuiteName = ciphersuite.into();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let enrollment = context
                    .e2ei_new_rotate_enrollment(display_name, handle, team, expiry_sec, ciphersuite.into())
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::context::CentralContext::e2ei_dump_pki_env]
    pub async fn e2ei_dump_pki_env(&self) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let dump: Option<E2eiDumpedPkiEnv> = context.e2ei_dump_pki_env().await?.map(Into::into);
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&dump)?)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::context::CentralContext::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> Promise {
        let context = self.inner.clone();
        future_to_promise(async move { WasmCryptoResult::Ok(context.e2ei_is_pki_env_setup().await?.into()) }.err_into())
    }

    /// See [core_crypto::mls::context::CentralContext::e2ei_register_acme_ca]
    pub async fn e2ei_register_acme_ca(&self, trust_anchor_pem: String) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context.e2ei_register_acme_ca(trust_anchor_pem).await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::context::CentralContext::e2ei_register_intermediate_ca]
    pub async fn e2ei_register_intermediate_ca(&self, cert_pem: String) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let crls = context.e2ei_register_intermediate_ca_pem(cert_pem).await?;

                let crls = if let Some(crls) = &*crls {
                    js_sys::Array::from_iter(crls.iter().map(JsValue::from))
                } else {
                    js_sys::Array::new()
                };
                WasmCryptoResult::Ok(crls.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::context::CentralContext::e2ei_register_crl]
    pub async fn e2ei_register_crl(&self, crl_dp: String, crl_der: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let cc_registration = context.e2ei_register_crl(crl_dp, crl_der.to_vec()).await?;
                let registration: CrlRegistration = cc_registration.into();
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&registration)?)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::context::CentralContext::e2ei_mls_init_only]
    pub fn e2ei_mls_init_only(
        &self,
        enrollment: E2eiEnrollment,
        certificate_chain: String,
        nb_key_package: Option<u32>,
    ) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let nb_key_package = nb_key_package
                    .map(usize::try_from)
                    .transpose()
                    .expect("we never run corecrypto on systems with architectures narrower than 32 bits");

                let crls = context
                    .e2ei_mls_init_only(
                        enrollment.0.write().await.deref_mut(),
                        certificate_chain,
                        nb_key_package,
                    )
                    .await?;

                let crls = if let Some(crls) = &*crls {
                    js_sys::Array::from_iter(crls.iter().map(JsValue::from))
                } else {
                    js_sys::Array::new()
                };
                WasmCryptoResult::Ok(crls.into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// See [core_crypto::mls::conversation::ConversationGuard::e2ei_rotate]
    pub fn e2ei_rotate(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context
                    .conversation_guard(&conversation_id)
                    .await?
                    .e2ei_rotate(None)
                    .await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Option<Vec<String>>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::save_x509_credential]
    pub fn save_x509_credential(&self, enrollment: E2eiEnrollment, certificate_chain: String) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let new_crl_distribution_point: Option<Vec<String>> = context
                    .save_x509_credential(enrollment.0.write().await.deref_mut(), certificate_chain)
                    .await?
                    .into();
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&new_crl_distribution_point)?)
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<()>`]
    ///
    /// see [core_crypto::context::CentralContext::delete_stale_key_packages]
    pub fn delete_stale_key_packages(&self, cipher_suite: Ciphersuite) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                context.delete_stale_key_packages(cipher_suite.into()).await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::context::CentralContext::e2ei_enrollment_stash]
    pub fn e2ei_enrollment_stash(&self, enrollment: E2eiEnrollment) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let enrollment = std::sync::Arc::try_unwrap(enrollment.0)
                    .map_err(|_| {
                        InternalError::Other("enrollment had multiple strong refs and could not be unwrapped".into())
                    })?
                    .into_inner();
                let handle = context.e2ei_enrollment_stash(enrollment).await?;
                WasmCryptoResult::Ok(Uint8Array::from(handle.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// see [core_crypto::mls::context::CentralContext::e2ei_enrollment_stash_pop]
    pub fn e2ei_enrollment_stash_pop(&self, handle: Box<[u8]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let enrollment = context
                    .e2ei_enrollment_stash_pop(handle.to_vec())
                    .await
                    .map(async_lock::RwLock::new)
                    .map(std::sync::Arc::new)
                    .map(E2eiEnrollment)
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(enrollment.into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<u8>`]
    ///
    /// see [core_crypto::mls::conversation::ImmutableConversation::e2ei_conversation_state]
    pub fn e2ei_conversation_state(&self, conversation_id: ConversationId) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let state: E2eiConversationState = context
                    .conversation_guard(&conversation_id)
                    .await?
                    .e2ei_conversation_state()
                    .await?
                    .into();
                WasmCryptoResult::Ok((state as u8).into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::e2ei_is_enabled]
    pub fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> Promise {
        let sc = MlsCiphersuite::from(ciphersuite).signature_algorithm();
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let is_enabled = context.e2ei_is_enabled(sc).await.map_err(CoreCryptoError::from)?.into();
                WasmCryptoResult::Ok(is_enabled)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Vec<WireIdentity>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::get_device_identities]
    pub fn get_device_identities(&self, conversation_id: ConversationId, device_ids: Box<[Uint8Array]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let device_ids = device_ids.iter().map(|c| c.to_vec().into()).collect::<Vec<ClientId>>();
                let identities = context
                    .conversation_guard(&conversation_id)
                    .await?
                    .get_device_identities(&device_ids[..])
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<WireIdentity>>();
                WasmCryptoResult::Ok(identities.into())
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<HashMap<String, Vec<WireIdentity>>>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::get_user_identities]
    pub fn get_user_identities(&self, conversation_id: ConversationId, user_ids: Box<[String]>) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let identities = context
                    .conversation_guard(&conversation_id)
                    .await?
                    .get_user_identities(user_ids.deref())
                    .await
                    .map_err(CoreCryptoError::from)?
                    .into_iter()
                    .map(|(k, v)| (k, v.into_iter().map(Into::into).collect()))
                    .collect::<HashMap<String, Vec<WireIdentity>>>();
                let js_obj = js_sys::Map::new();
                for (uid, identities) in identities.into_iter() {
                    let uid = js_sys::JsString::from(uid).into();
                    let identities = JsValue::from(identities);
                    js_obj.set(&uid, &identities);
                }
                WasmCryptoResult::Ok(js_obj.into())
            }
            .err_into(),
        )
    }

    #[allow(clippy::boxed_local)]
    /// Returns: [`WasmCryptoResult<u8>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::get_credential_in_use]
    pub fn get_credential_in_use(&self, group_info: Box<[u8]>, credential_type: CredentialType) -> Promise {
        let context = self.inner.clone();
        future_to_promise(
            async move {
                let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_ref())
                    .map_err(core_crypto::mls::conversation::Error::tls_deserialize(
                        "verifiable group info",
                    ))
                    .map_err(RecursiveError::mls_conversation("getting credential in use"))?;

                let state: E2eiConversationState = context
                    .get_credential_in_use(group_info, credential_type.into())
                    .await
                    .map(Into::into)
                    .map_err(CoreCryptoError::from)?;

                WasmCryptoResult::Ok((state as u8).into())
            }
            .err_into(),
        )
    }
}
