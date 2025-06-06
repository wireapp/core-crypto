use std::{ops::Deref, sync::Arc};

use async_lock::RwLock;
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{AcmeDirectory, CoreCryptoContext, CoreCryptoResult, NewAcmeAuthz, NewAcmeOrder};

/// See [core_crypto::e2e_identity::E2eiEnrollment]
#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = FfiWireE2EIdentity))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct E2eiEnrollment(Arc<RwLock<core_crypto::prelude::E2eiEnrollment>>);

impl E2eiEnrollment {
    pub fn new(inner: core_crypto::prelude::E2eiEnrollment) -> Self {
        Self(Arc::new(RwLock::new(inner)))
    }

    pub fn into_inner(self) -> Option<core_crypto::prelude::E2eiEnrollment> {
        Arc::into_inner(self.0).map(|rwlock| rwlock.into_inner())
    }
}

impl Deref for E2eiEnrollment {
    type Target = RwLock<core_crypto::prelude::E2eiEnrollment>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_class = FfiWireE2EIdentity))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::directory_response]
    pub async fn directory_response(&self, directory: Vec<u8>) -> CoreCryptoResult<AcmeDirectory> {
        self.write()
            .await
            .directory_response(directory)
            .map(AcmeDirectory::from)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_request]
    pub async fn new_account_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read()
            .await
            .new_account_request(previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_response]
    pub async fn new_account_response(&self, account: Vec<u8>) -> CoreCryptoResult<()> {
        self.write().await.new_account_response(account).map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_request]
    pub async fn new_order_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read().await.new_order_request(previous_nonce).map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_response]
    pub async fn new_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<NewAcmeOrder> {
        self.read()
            .await
            .new_order_response(order)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_request]
    pub async fn new_authz_request(&self, url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read()
            .await
            .new_authz_request(url, previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_response]
    pub async fn new_authz_response(&self, authz: Vec<u8>) -> CoreCryptoResult<NewAcmeAuthz> {
        self.write()
            .await
            .new_authz_response(authz)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::create_dpop_token]
    pub async fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> CoreCryptoResult<String> {
        self.read()
            .await
            .create_dpop_token(expiry_secs, backend_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_request]
    pub async fn new_dpop_challenge_request(
        &self,
        access_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.read()
            .await
            .new_dpop_challenge_request(access_token, previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_response]
    pub async fn new_dpop_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        self.read()
            .await
            .new_dpop_challenge_response(challenge)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_request]
    pub async fn check_order_request(&self, order_url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read()
            .await
            .check_order_request(order_url, previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_response]
    pub async fn check_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<String> {
        self.write().await.check_order_response(order).map_err(Into::into)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_request]
    pub async fn finalize_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.write().await.finalize_request(previous_nonce).map_err(Into::into)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::finalize_response]
    pub async fn finalize_response(&self, finalize: Vec<u8>) -> CoreCryptoResult<String> {
        self.write().await.finalize_response(finalize).map_err(Into::into)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::certificate_request]
    pub async fn certificate_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.write()
            .await
            .certificate_request(previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_request]
    pub async fn new_oidc_challenge_request(
        &self,
        id_token: String,
        refresh_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.write()
            .await
            .new_oidc_challenge_request(id_token, refresh_token, previous_nonce)
            .map_err(Into::into)
    }
}

#[cfg(not(target_family = "wasm"))]
type CoreCryptoContextObject = Arc<CoreCryptoContext>;

#[cfg(target_family = "wasm")]
type CoreCryptoContextObject = CoreCryptoContext;

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_class = FfiWireE2EIdentity))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_response]
    pub async fn new_oidc_challenge_response(
        &self,
        cc: CoreCryptoContextObject,
        challenge: Vec<u8>,
    ) -> CoreCryptoResult<()> {
        let provider = cc.inner.mls_provider().await?;
        self.write()
            .await
            .new_oidc_challenge_response(&provider, challenge)
            .await
            .map_err(Into::into)
    }

    /// See [core_crypto::prelude::E2eiEnrollment::get_refresh_token]
    pub async fn get_refresh_token(&self) -> CoreCryptoResult<String> {
        self.read()
            .await
            .get_refresh_token()
            .map(Into::into)
            .map_err(Into::into)
    }
}
