use std::ops::{Deref, DerefMut};

use async_lock::{RwLock, RwLockReadGuard, RwLockWriteGuard};
#[cfg(target_family = "wasm")]
use wasm_bindgen::prelude::*;

use crate::{AcmeDirectory, CoreCryptoError, CoreCryptoResult, NewAcmeAuthz, NewAcmeOrder};

pub(crate) struct ReadGuard<'a>(RwLockReadGuard<'a, Option<core_crypto::E2eiEnrollment>>);

impl<'a> TryFrom<RwLockReadGuard<'a, Option<core_crypto::E2eiEnrollment>>> for ReadGuard<'a> {
    type Error = CoreCryptoError;

    fn try_from(value: RwLockReadGuard<'a, Option<core_crypto::E2eiEnrollment>>) -> Result<Self, Self::Error> {
        value
            .is_some()
            .then_some(Self(value))
            .ok_or_else(|| CoreCryptoError::ad_hoc("E2eiEnrollment: attempt to read from taken value"))
    }
}

impl Deref for ReadGuard<'_> {
    type Target = core_crypto::E2eiEnrollment;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("we have read access that we already checked; nobody can mutate this out from under us")
    }
}

pub(crate) struct WriteGuard<'a>(RwLockWriteGuard<'a, Option<core_crypto::E2eiEnrollment>>);

impl<'a> TryFrom<RwLockWriteGuard<'a, Option<core_crypto::E2eiEnrollment>>> for WriteGuard<'a> {
    type Error = CoreCryptoError;

    fn try_from(value: RwLockWriteGuard<'a, Option<core_crypto::E2eiEnrollment>>) -> Result<Self, Self::Error> {
        value
            .is_some()
            .then_some(Self(value))
            .ok_or_else(|| CoreCryptoError::ad_hoc("E2eiEnrollment: attempt to write to taken value"))
    }
}

impl Deref for WriteGuard<'_> {
    type Target = core_crypto::E2eiEnrollment;

    fn deref(&self) -> &Self::Target {
        self.0
            .as_ref()
            .expect("we have exclusive access that we already checked")
    }
}

impl DerefMut for WriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
            .as_mut()
            .expect("we have exclusive access that we already checked")
    }
}

/// Wire end to end identity solution for fetching a x509 certificate which identifies a client.
///
/// See [core_crypto::e2e_identity::E2eiEnrollment]
#[derive(Debug)]
#[cfg_attr(target_family = "wasm", wasm_bindgen(js_name = FfiWireE2EIdentity))]
#[cfg_attr(not(target_family = "wasm"), derive(uniffi::Object))]
pub struct E2eiEnrollment(RwLock<Option<core_crypto::E2eiEnrollment>>);

// only these functions ever touch the contained lock directly
impl E2eiEnrollment {
    pub(crate) fn new(inner: core_crypto::E2eiEnrollment) -> Self {
        Self(RwLock::new(Some(inner)))
    }

    /// Extract the inner enrollment, leaving `None` internally.
    pub(crate) async fn take(&self) -> Option<core_crypto::E2eiEnrollment> {
        let mut guard = self.0.write().await;
        guard.take()
    }

    /// Get access to a readable view of the contained enrollment
    pub(crate) async fn read(&self) -> CoreCryptoResult<ReadGuard<'_>> {
        self.0.read().await.try_into()
    }

    /// Get access to a writeable view of the contained enrollment
    pub(crate) async fn write(&self) -> CoreCryptoResult<WriteGuard<'_>> {
        self.0.write().await.try_into()
    }
}

#[cfg_attr(target_family = "wasm", wasm_bindgen(js_class = FfiWireE2EIdentity))]
#[cfg_attr(not(target_family = "wasm"), uniffi::export)]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::directory_response]
    pub async fn directory_response(&self, directory: Vec<u8>) -> CoreCryptoResult<AcmeDirectory> {
        self.write()
            .await?
            .directory_response(directory)
            .map(AcmeDirectory::from)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_request]
    pub async fn new_account_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read()
            .await?
            .new_account_request(previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_response]
    pub async fn new_account_response(&self, account: Vec<u8>) -> CoreCryptoResult<()> {
        self.write().await?.new_account_response(account).map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_request]
    pub async fn new_order_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read().await?.new_order_request(previous_nonce).map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_response]
    pub async fn new_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<NewAcmeOrder> {
        self.read()
            .await?
            .new_order_response(order)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_request]
    pub async fn new_authz_request(&self, url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read()
            .await?
            .new_authz_request(url, previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_response]
    pub async fn new_authz_response(&self, authz: Vec<u8>) -> CoreCryptoResult<NewAcmeAuthz> {
        self.write()
            .await?
            .new_authz_response(authz)
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::create_dpop_token]
    pub async fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> CoreCryptoResult<String> {
        self.read()
            .await?
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
            .await?
            .new_dpop_challenge_request(access_token, previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_response]
    pub async fn new_dpop_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        self.read()
            .await?
            .new_dpop_challenge_response(challenge)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_request]
    pub async fn check_order_request(&self, order_url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read()
            .await?
            .check_order_request(order_url, previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_response]
    pub async fn check_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<String> {
        self.write().await?.check_order_response(order).map_err(Into::into)
    }

    /// See [core_crypto::E2eiEnrollment::finalize_request]
    pub async fn finalize_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.write().await?.finalize_request(previous_nonce).map_err(Into::into)
    }

    /// See [core_crypto::E2eiEnrollment::finalize_response]
    pub async fn finalize_response(&self, finalize: Vec<u8>) -> CoreCryptoResult<String> {
        self.write().await?.finalize_response(finalize).map_err(Into::into)
    }

    /// See [core_crypto::E2eiEnrollment::certificate_request]
    pub async fn certificate_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.write()
            .await?
            .certificate_request(previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_request]
    pub async fn new_oidc_challenge_request(
        &self,
        id_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.write()
            .await?
            .new_oidc_challenge_request(id_token, previous_nonce)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_response]
    pub async fn new_oidc_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        self.write()
            .await?
            .new_oidc_challenge_response(challenge)
            .map_err(Into::into)
    }
}
