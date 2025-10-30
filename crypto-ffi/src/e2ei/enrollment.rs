use async_lock::RwLock;

use crate::{AcmeDirectory, CoreCryptoError, CoreCryptoResult, NewAcmeAuthz, NewAcmeOrder};

/// Wire end to end identity solution for fetching a x509 certificate which identifies a client.
///
/// See [core_crypto::e2e_identity::E2eiEnrollment]
#[derive(Debug, uniffi::Object)]
pub struct E2eiEnrollment(pub(crate) RwLock<Option<core_crypto::E2eiEnrollment>>);

impl E2eiEnrollment {
    pub(crate) fn new(inner: core_crypto::E2eiEnrollment) -> Self {
        Self(RwLock::new(Some(inner)))
    }

    /// Extract the inner enrollment, leaving `None` internally.
    pub(crate) async fn take(&self) -> Option<core_crypto::E2eiEnrollment> {
        let mut guard = self.0.write().await;
        guard.take()
    }

    pub(crate) fn read_err() -> CoreCryptoError {
        CoreCryptoError::ad_hoc("E2eiEnrollment: attemped to read from taken value")
    }

    pub(crate) fn write_err() -> CoreCryptoError {
        CoreCryptoError::ad_hoc("E2eiEnrollment: attemped to write to taken value")
    }

    /// Perform a synchronous read operation on the internal value.
    ///
    /// Unfortunately you need to implement this pattern manually for async operations.
    pub(crate) async fn read<Operation, Output>(&self, operation: Operation) -> CoreCryptoResult<Output>
    where
        Operation: FnOnce(&core_crypto::E2eiEnrollment) -> Output,
    {
        let guard = self.0.read().await;
        let enrollment = guard.as_ref().ok_or_else(Self::read_err)?;
        Ok(operation(enrollment))
    }

    /// Perform a synchronous write operation on the internal value.
    ///
    /// Unfortunately you need to implement this pattern manually for async operations.
    pub(crate) async fn write<Operation, Output>(&self, operation: Operation) -> CoreCryptoResult<Output>
    where
        Operation: FnOnce(&mut core_crypto::E2eiEnrollment) -> Output,
    {
        let mut guard = self.0.write().await;
        let enrollment = guard.as_mut().ok_or_else(Self::write_err)?;
        Ok(operation(enrollment))
    }
}

#[uniffi::export]
impl E2eiEnrollment {
    /// See [core_crypto::e2e_identity::E2eiEnrollment::directory_response]
    pub async fn directory_response(&self, directory: Vec<u8>) -> CoreCryptoResult<AcmeDirectory> {
        self.write(move |inner| inner.directory_response(directory))
            .await?
            .map(AcmeDirectory::from)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_request]
    pub async fn new_account_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read(move |inner| inner.new_account_request(previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_account_response]
    pub async fn new_account_response(&self, account: Vec<u8>) -> CoreCryptoResult<()> {
        self.write(move |inner| inner.new_account_response(account))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_request]
    pub async fn new_order_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read(move |inner| inner.new_order_request(previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_order_response]
    pub async fn new_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<NewAcmeOrder> {
        self.read(move |inner| inner.new_order_response(order))
            .await?
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_request]
    pub async fn new_authz_request(&self, url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read(move |inner| inner.new_authz_request(url, previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_authz_response]
    pub async fn new_authz_response(&self, authz: Vec<u8>) -> CoreCryptoResult<NewAcmeAuthz> {
        self.write(move |inner| inner.new_authz_response(authz))
            .await?
            .map(Into::into)
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::create_dpop_token]
    pub async fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> CoreCryptoResult<String> {
        self.read(move |inner| inner.create_dpop_token(expiry_secs, backend_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_request]
    pub async fn new_dpop_challenge_request(
        &self,
        access_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.read(move |inner| inner.new_dpop_challenge_request(access_token, previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_dpop_challenge_response]
    pub async fn new_dpop_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        self.read(move |inner| inner.new_dpop_challenge_response(challenge))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_request]
    pub async fn check_order_request(&self, order_url: String, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.read(move |inner| inner.check_order_request(order_url, previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::check_order_response]
    pub async fn check_order_response(&self, order: Vec<u8>) -> CoreCryptoResult<String> {
        self.write(move |inner| inner.check_order_response(order))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::E2eiEnrollment::finalize_request]
    pub async fn finalize_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.write(move |inner| inner.finalize_request(previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::E2eiEnrollment::finalize_response]
    pub async fn finalize_response(&self, finalize: Vec<u8>) -> CoreCryptoResult<String> {
        self.write(move |inner| inner.finalize_response(finalize))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::E2eiEnrollment::certificate_request]
    pub async fn certificate_request(&self, previous_nonce: String) -> CoreCryptoResult<Vec<u8>> {
        self.write(move |inner| inner.certificate_request(previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_request]
    pub async fn new_oidc_challenge_request(
        &self,
        id_token: String,
        previous_nonce: String,
    ) -> CoreCryptoResult<Vec<u8>> {
        self.write(move |inner| inner.new_oidc_challenge_request(id_token, previous_nonce))
            .await?
            .map_err(Into::into)
    }

    /// See [core_crypto::e2e_identity::E2eiEnrollment::new_oidc_challenge_response]
    pub async fn new_oidc_challenge_response(&self, challenge: Vec<u8>) -> CoreCryptoResult<()> {
        self.write(move |inner| inner.new_oidc_challenge_response(challenge))
            .await?
            .map_err(Into::into)
    }
}
