#![allow(unused_variables)]
pub mod context;
mod epoch_observer;
mod utils;

use std::{collections::HashMap, ops::Deref, sync::Arc};

use crate::proteus_impl;
use core_crypto::mls::conversation::Conversation as _;
use core_crypto::prelude::*;
use futures_util::future::TryFutureExt;
use js_sys::{Promise, Uint8Array};
use tls_codec::Deserialize;
use utils::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;

use crate::{
    Ciphersuite, CoreCrypto, CoreCryptoError, CredentialType, InternalError, MlsError, WasmCryptoResult, WireIdentity,
    lower_ciphersuites,
};

#[wasm_bindgen(getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Dump of the PKI environemnt as PEM
pub struct E2eiDumpedPkiEnv {
    #[wasm_bindgen(readonly)]
    /// Root CA in use (i.e. Trust Anchor)
    pub root_ca: String,
    #[wasm_bindgen(readonly)]
    /// Intermediate CAs that are loaded
    pub intermediates: Vec<String>,
    #[wasm_bindgen(readonly)]
    /// CRLs registered in the PKI env
    pub crls: Vec<String>,
}

impl From<core_crypto::e2e_identity::E2eiDumpedPkiEnv> for E2eiDumpedPkiEnv {
    fn from(value: core_crypto::e2e_identity::E2eiDumpedPkiEnv) -> Self {
        Self {
            root_ca: value.root_ca,
            intermediates: value.intermediates,
            crls: value.crls,
        }
    }
}

#[wasm_bindgen]
impl CoreCrypto {
    /// Returns: [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::session_exists]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_session_exists(&self, session_id: String) -> Promise {
        let central = self.inner.clone();

        future_to_promise(
            async move {
                proteus_impl! {{
                    let exists = central.proteus_session_exists(&session_id).await.map_err(CoreCryptoError::from)?;
                    WasmCryptoResult::Ok(JsValue::from_bool(exists))
                } or throw WasmCryptoResult<_> }
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<u16>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::last_resort_prekey_id]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_last_resort_prekey_id() -> WasmCryptoResult<u16> {
        proteus_impl! {{
            Ok(core_crypto::CoreCrypto::proteus_last_resort_prekey_id())
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint(&self) -> WasmCryptoResult<String> {
        let central = self.inner.clone();

        proteus_impl! {{
            central.proteus_fingerprint().await.map_err(CoreCryptoError::from)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_local]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_local(&self, session_id: String) -> WasmCryptoResult<String> {
        let central = self.inner.clone();

        proteus_impl! {{
            central
                .proteus_fingerprint_local(&session_id)
                .await
                .map_err(CoreCryptoError::from)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCentral::fingerprint_remote]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub async fn proteus_fingerprint_remote(&self, session_id: String) -> WasmCryptoResult<String> {
        let central = self.inner.clone();

        proteus_impl! {{
            central.proteus_fingerprint_remote(&session_id).await
                .map_err(CoreCryptoError::from)
        } or throw WasmCryptoResult<_> }
    }

    /// Returns: [`WasmCryptoResult<String>`]
    ///
    /// see [core_crypto::proteus::ProteusCproteus_fingerprint_prekeybundle]
    #[cfg_attr(not(feature = "proteus"), allow(unused_variables))]
    pub fn proteus_fingerprint_prekeybundle(prekey: Box<[u8]>) -> WasmCryptoResult<String> {
        proteus_impl!({
            core_crypto::proteus::ProteusCentral::fingerprint_prekeybundle(&prekey)
                .map_err(Into::into)
        } or throw WasmCryptoResult<_>)
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// See [crate::mls::conversation::ImmutableConversation::export_secret_key]
    pub fn export_secret_key(&self, conversation_id: ConversationId, key_length: usize) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let key = central
                    .get_raw_conversation(&conversation_id.to_vec())
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .export_secret_key(key_length)
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(key.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Vec<u8>>`]
    ///
    /// See [crate::mls::conversation::ImmutableConversation::get_external_sender]
    pub fn get_external_sender(&self, id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let ext_sender = central
                    .get_raw_conversation(&id.to_vec())
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .get_external_sender()
                    .await
                    .map_err(CoreCryptoError::from)?;
                WasmCryptoResult::Ok(Uint8Array::from(ext_sender.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// Returns: [`WasmCryptoResult<Box<[js_sys::Uint8Array]>`]
    ///
    /// See [core_crypto::mls::conversation::ImmutableConversation::get_client_ids]
    pub fn get_client_ids(&self, conversation_id: ConversationId) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let clients = central
                    .get_raw_conversation(&conversation_id.to_vec())
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
                    .get_client_ids()
                    .await;
                let clients = js_sys::Array::from_iter(
                    clients
                        .into_iter()
                        .map(|client| Uint8Array::from(client.as_slice()))
                        .map(JsValue::from),
                );
                WasmCryptoResult::Ok(clients.into())
            }
            .err_into(),
        )
    }
}

// End-to-end identity methods
#[wasm_bindgen]
impl CoreCrypto {
    /// See [core_crypto::mls::context::CentralContext::e2ei_dump_pki_env]
    pub async fn e2ei_dump_pki_env(&self) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let dump: Option<E2eiDumpedPkiEnv> = central
                    .e2ei_dump_pki_env()
                    .await
                    .map_err(RecursiveError::mls_client("dumping pki env"))?
                    .map(Into::into);
                WasmCryptoResult::Ok(serde_wasm_bindgen::to_value(&dump)?)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::mls::context::CentralContext::e2ei_is_pki_env_setup]
    pub async fn e2ei_is_pki_env_setup(&self) -> Promise {
        let central = self.inner.clone();
        future_to_promise(async move { WasmCryptoResult::Ok(central.e2ei_is_pki_env_setup().await.into()) }.err_into())
    }

    /// Returns [`WasmCryptoResult<bool>`]
    ///
    /// see [core_crypto::mls::context::CentralContext::e2ei_is_enabled]
    pub fn e2ei_is_enabled(&self, ciphersuite: Ciphersuite) -> Promise {
        let sc = MlsCiphersuite::from(ciphersuite).signature_algorithm();
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let is_enabled = central
                    .e2ei_is_enabled(sc)
                    .await
                    .map_err(RecursiveError::mls_client("is e2ei enabled for client"))?
                    .into();
                WasmCryptoResult::Ok(is_enabled)
            }
            .err_into(),
        )
    }

    /// Returns [`WasmCryptoResult<Vec<WireIdentity>>`]
    ///
    /// see [core_crypto::mls::conversation::ConversationGuard::get_device_identities]
    pub fn get_device_identities(&self, conversation_id: ConversationId, device_ids: Box<[Uint8Array]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let device_ids = device_ids.iter().map(|c| c.to_vec().into()).collect::<Vec<ClientId>>();
                let identities = central
                    .get_raw_conversation(&conversation_id)
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
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
    /// see [core_crypto::mls::conversation::ConversationGuard::get_user_identities]
    pub fn get_user_identities(&self, conversation_id: ConversationId, user_ids: Box<[String]>) -> Promise {
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let identities = central
                    .get_raw_conversation(&conversation_id)
                    .await
                    .map_err(RecursiveError::mls_client("getting conversation by id"))?
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
        let central = self.inner.clone();
        future_to_promise(
            async move {
                let group_info = VerifiableGroupInfo::tls_deserialize(&mut group_info.as_ref())
                    .map_err(|e| MlsError::Other(e.to_string()))
                    .map_err(CoreCryptoError::from)?;

                let state: E2eiConversationState = central
                    .get_credential_in_use(group_info, credential_type.into())
                    .await
                    .map(Into::into)
                    .map_err(RecursiveError::mls_client("getting credential in use"))?;

                WasmCryptoResult::Ok((state as u8).into())
            }
            .err_into(),
        )
    }
}

#[derive(Debug)]
#[wasm_bindgen(js_name = FfiWireE2EIdentity)]
#[repr(transparent)]
pub struct E2eiEnrollment(pub(super) Arc<async_lock::RwLock<core_crypto::prelude::E2eiEnrollment>>);

#[wasm_bindgen(js_class = FfiWireE2EIdentity)]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::WireE2eIdentity::directory_response]
    pub fn directory_response(&mut self, directory: Vec<u8>) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let directory: AcmeDirectory = this.directory_response(directory)?.into();
                WasmCryptoResult::Ok(directory.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_request]
    pub fn new_account_request(&self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_account: Vec<u8> = this.new_account_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_account.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_account_response]
    pub fn new_account_response(&mut self, account: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                this.new_account_response(account.to_vec())?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_request]
    pub fn new_order_request(&self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_order = this.new_order_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_order.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_order_response]
    pub fn new_order_response(&self, order: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let order: NewAcmeOrder = this.new_order_response(order.to_vec())?.into();
                WasmCryptoResult::Ok(order.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_request]
    pub fn new_authz_request(&self, url: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_authz = this.new_authz_request(url, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_authz.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_authz_response]
    pub fn new_authz_response(&mut self, authz: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let authz: NewAcmeAuthz = this.new_authz_response(authz.to_vec())?.into();
                WasmCryptoResult::Ok(authz.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::create_dpop_token]
    pub fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let dpop_token = this.create_dpop_token(expiry_secs, backend_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(dpop_token.as_bytes()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_dpop_challenge_request]
    pub fn new_dpop_challenge_request(&self, access_token: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let chall = this.new_dpop_challenge_request(access_token, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(chall.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_dpop_challenge_response]
    pub fn new_dpop_challenge_response(&self, challenge: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                this.new_dpop_challenge_response(challenge.to_vec())?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_oidc_challenge_request]
    pub fn new_oidc_challenge_request(&mut self, id_token: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let chall = this.new_oidc_challenge_request(id_token, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(chall.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::new_oidc_challenge_response]
    pub fn new_oidc_challenge_response(&mut self, challenge: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                this.new_oidc_challenge_response(challenge.to_vec()).await?;
                WasmCryptoResult::Ok(JsValue::UNDEFINED)
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_request]
    pub fn check_order_request(&self, order_url: String, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let this = this.read().await;
                let new_order = this.check_order_request(order_url, previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(new_order.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::check_order_response]
    pub fn check_order_response(&mut self, order: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                WasmCryptoResult::Ok(this.check_order_response(order.to_vec())?.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_request]
    pub fn finalize_request(&mut self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let finalize = this.finalize_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(finalize.as_slice()).into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::finalize_response]
    pub fn finalize_response(&mut self, finalize: Uint8Array) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                WasmCryptoResult::Ok(this.finalize_response(finalize.to_vec())?.into())
            }
            .err_into(),
        )
    }

    /// See [core_crypto::e2e_identity::WireE2eIdentity::certificate_request]
    pub fn certificate_request(&mut self, previous_nonce: String) -> Promise {
        let this = self.0.clone();
        future_to_promise(
            async move {
                let mut this = this.write().await;
                let certificate_req = this.certificate_request(previous_nonce)?;
                WasmCryptoResult::Ok(Uint8Array::from(certificate_req.as_slice()).into())
            }
            .err_into(),
        )
    }
}

/// Holds URLs of all the standard ACME endpoint supported on an ACME server.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
#[wasm_bindgen(skip_jsdoc, getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcmeDirectory {
    /// URL for fetching a new nonce. Use this only for creating a new account.
    #[wasm_bindgen(readonly)]
    pub new_nonce: String,
    /// URL for creating a new account.
    #[wasm_bindgen(readonly)]
    pub new_account: String,
    /// URL for creating a new order.
    #[wasm_bindgen(readonly)]
    pub new_order: String,
    /// Revocation URL
    #[wasm_bindgen(readonly)]
    pub revoke_cert: String,
}

impl From<core_crypto::prelude::E2eiAcmeDirectory> for AcmeDirectory {
    fn from(directory: core_crypto::prelude::E2eiAcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

impl From<AcmeDirectory> for core_crypto::prelude::E2eiAcmeDirectory {
    fn from(directory: AcmeDirectory) -> Self {
        Self {
            new_nonce: directory.new_nonce,
            new_account: directory.new_account,
            new_order: directory.new_order,
            revoke_cert: directory.revoke_cert,
        }
    }
}

/// Result of an order creation.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
#[wasm_bindgen(skip_jsdoc)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewAcmeOrder {
    /// Contains raw JSON data of this order. This is parsed by the underlying Rust library hence should not be accessed
    #[wasm_bindgen(readonly, getter_with_clone)]
    pub delegate: Vec<u8>,
    authorizations: ArrayOfByteArray,
}

#[wasm_bindgen]
impl NewAcmeOrder {
    #[wasm_bindgen(getter)]
    pub fn authorizations(&self) -> Vec<Uint8Array> {
        self.authorizations.clone().into()
    }
}

impl From<core_crypto::prelude::E2eiNewAcmeOrder> for NewAcmeOrder {
    fn from(new_order: core_crypto::prelude::E2eiNewAcmeOrder) -> Self {
        Self {
            delegate: new_order.delegate,
            authorizations: new_order
                .authorizations
                .into_iter()
                .map(String::into_bytes)
                .collect::<Vec<_>>()
                .into(),
        }
    }
}

impl TryFrom<NewAcmeOrder> for core_crypto::prelude::E2eiNewAcmeOrder {
    type Error = CoreCryptoError;

    fn try_from(new_order: NewAcmeOrder) -> WasmCryptoResult<Self> {
        let authorizations = new_order
            .authorizations
            .0
            .into_iter()
            .map(String::from_utf8)
            .collect::<Result<Vec<String>, _>>()
            .map_err(|_| InternalError::Other("invalid authorization string: not utf8".into()))?;
        Ok(Self {
            delegate: new_order.delegate,
            authorizations,
        })
    }
}

/// Result of an authorization creation.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
#[wasm_bindgen(skip_jsdoc, getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewAcmeAuthz {
    /// DNS entry associated with those challenge
    #[wasm_bindgen(readonly)]
    pub identifier: String,
    /// ACME challenge + ACME key thumbprint
    #[wasm_bindgen(readonly)]
    pub keyauth: Option<String>,
    /// Associated ACME Challenge
    #[wasm_bindgen(readonly)]
    pub challenge: AcmeChallenge,
}

impl From<core_crypto::prelude::E2eiNewAcmeAuthz> for NewAcmeAuthz {
    fn from(authz: core_crypto::prelude::E2eiNewAcmeAuthz) -> Self {
        Self {
            identifier: authz.identifier,
            keyauth: authz.keyauth,
            challenge: authz.challenge.into(),
        }
    }
}

impl From<NewAcmeAuthz> for core_crypto::prelude::E2eiNewAcmeAuthz {
    fn from(authz: NewAcmeAuthz) -> Self {
        Self {
            identifier: authz.identifier,
            keyauth: authz.keyauth,
            challenge: authz.challenge.into(),
        }
    }
}

/// For creating a challenge.
/// @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
#[wasm_bindgen(skip_jsdoc, getter_with_clone)]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AcmeChallenge {
    /// Contains raw JSON data of this challenge. This is parsed by the underlying Rust library hence should not be accessed
    #[wasm_bindgen(readonly)]
    pub delegate: Vec<u8>,
    /// URL of this challenge
    #[wasm_bindgen(readonly)]
    pub url: String,
    /// Non-standard, Wire specific claim. Indicates the consumer from where it should get the challenge proof.
    /// Either from wire-server "/access-token" endpoint in case of a DPoP challenge, or from an OAuth token endpoint for an OIDC challenge
    #[wasm_bindgen(readonly)]
    pub target: String,
}

impl From<core_crypto::prelude::E2eiAcmeChallenge> for AcmeChallenge {
    fn from(chall: core_crypto::prelude::E2eiAcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

impl From<AcmeChallenge> for core_crypto::prelude::E2eiAcmeChallenge {
    fn from(chall: AcmeChallenge) -> Self {
        Self {
            delegate: chall.delegate,
            url: chall.url,
            target: chall.target,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
/// see [core_crypto::prelude::E2eiConversationState]
enum E2eiConversationState {
    Verified = 1,
    /// Some clients are either still Basic or their certificate is expired
    NotVerified = 2,
    /// All clients are still Basic. If all client have expired certificates, [E2eiConversationState::NotVerified] is returned.
    NotEnabled = 3,
}

impl From<core_crypto::prelude::E2eiConversationState> for E2eiConversationState {
    fn from(state: core_crypto::prelude::E2eiConversationState) -> Self {
        match state {
            core_crypto::prelude::E2eiConversationState::Verified => Self::Verified,
            core_crypto::prelude::E2eiConversationState::NotVerified => Self::NotVerified,
            core_crypto::prelude::E2eiConversationState::NotEnabled => Self::NotEnabled,
        }
    }
}
