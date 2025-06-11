mod crypto;
#[cfg(test)]
pub mod test_utils;

use core_crypto_keystore::CryptoKeystoreMls as _;
use mls_crypto_provider::MlsCryptoProvider;
use openmls_traits::{OpenMlsCryptoProvider as _, random::OpenMlsRand as _};
use wire_e2e_identity::{RustyE2eIdentity, prelude::E2eiAcmeAuthorization};
use zeroize::Zeroize as _;

use crate::{
    KeystoreError, MlsError,
    prelude::{ClientId, MlsCiphersuite},
};

use super::{EnrollmentHandle, Error, Json, Result, crypto::E2eiSignatureKeypair, id::QualifiedE2eiClientId, types};

/// Wire end to end identity solution for fetching a x509 certificate which identifies a client.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct E2eiEnrollment {
    delegate: RustyE2eIdentity,
    pub(crate) sign_sk: E2eiSignatureKeypair,
    pub(super) client_id: String,
    pub(super) display_name: String,
    pub(super) handle: String,
    pub(super) team: Option<String>,
    expiry: core::time::Duration,
    directory: Option<types::E2eiAcmeDirectory>,
    account: Option<wire_e2e_identity::prelude::E2eiAcmeAccount>,
    user_authz: Option<E2eiAcmeAuthorization>,
    device_authz: Option<E2eiAcmeAuthorization>,
    valid_order: Option<wire_e2e_identity::prelude::E2eiAcmeOrder>,
    finalize: Option<wire_e2e_identity::prelude::E2eiAcmeFinalize>,
    pub(super) ciphersuite: MlsCiphersuite,
    has_called_new_oidc_challenge_request: bool,
}

impl std::ops::Deref for E2eiEnrollment {
    type Target = RustyE2eIdentity;

    fn deref(&self) -> &Self::Target {
        &self.delegate
    }
}

impl E2eiEnrollment {
    /// Builds an instance holding private key material. This instance has to be used in the whole
    /// enrollment process then dropped to clear secret key material.
    ///
    /// # Parameters
    /// * `client_id` - client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_sec` - generated x509 certificate expiry in seconds
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        client_id: ClientId,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        backend: &MlsCryptoProvider,
        ciphersuite: MlsCiphersuite,
        sign_keypair: Option<E2eiSignatureKeypair>,
        has_called_new_oidc_challenge_request: bool,
    ) -> Result<Self> {
        let alg = ciphersuite.try_into()?;
        let sign_sk = sign_keypair
            .map(Ok)
            .unwrap_or_else(|| Self::new_sign_key(ciphersuite, backend))?;

        let client_id = QualifiedE2eiClientId::try_from(client_id.as_slice())?;
        let client_id = String::try_from(client_id)?;
        let expiry = core::time::Duration::from_secs(u64::from(expiry_sec));
        let delegate = RustyE2eIdentity::try_new(alg, sign_sk.clone()).map_err(Error::from)?;
        Ok(Self {
            delegate,
            sign_sk,
            client_id,
            display_name,
            handle,
            team,
            expiry,
            directory: None,
            account: None,
            user_authz: None,
            device_authz: None,
            valid_order: None,
            finalize: None,
            ciphersuite,
            has_called_new_oidc_challenge_request,
        })
    }

    pub(crate) fn ciphersuite(&self) -> &MlsCiphersuite {
        &self.ciphersuite
    }

    /// Parses the response from `GET /acme/{provisioner-name}/directory`.
    /// Use this [types::E2eiAcmeDirectory] in the next step to fetch the first nonce from the acme server. Use
    /// [types::E2eiAcmeDirectory.new_nonce].
    ///
    /// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
    ///
    /// # Parameters
    /// * `directory` - http response body
    pub fn directory_response(&mut self, directory: Json) -> Result<types::E2eiAcmeDirectory> {
        let directory = serde_json::from_slice(&directory[..])?;
        let directory: types::E2eiAcmeDirectory = self.acme_directory_response(directory)?.into();
        self.directory = Some(directory.clone());
        Ok(directory)
    }

    /// For creating a new acme account. This returns a signed JWS-alike request body to send to
    /// `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `directory` - you got from [Self::directory_response]
    /// * `previous_nonce` - you got from calling `HEAD {directory.new_nonce}`
    pub fn new_account_request(&self, previous_nonce: String) -> Result<Json> {
        let directory = self
            .directory
            .as_ref()
            .ok_or(Error::OutOfOrderEnrollment("You must first call 'directoryResponse()'"))?;
        let account = self.acme_new_account_request(&directory.try_into()?, previous_nonce)?;
        let account = serde_json::to_vec(&account)?;
        Ok(account)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `account` - http response body
    pub fn new_account_response(&mut self, account: Json) -> Result<()> {
        let account = serde_json::from_slice(&account[..])?;
        let account = self.acme_new_account_response(account)?;
        self.account = Some(account);
        Ok(())
    }

    /// Creates a new acme order for the handle (userId + display name) and the clientId.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/new-account`
    pub fn new_order_request(&self, previous_nonce: String) -> Result<Json> {
        let directory = self
            .directory
            .as_ref()
            .ok_or(Error::OutOfOrderEnrollment("You must first call 'directoryResponse()'"))?;
        let account = self.account.as_ref().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'newAccountResponse()'",
        ))?;
        let order = self.acme_new_order_request(
            &self.display_name,
            &self.client_id,
            &self.handle,
            self.expiry,
            &directory.try_into()?,
            account,
            previous_nonce,
        )?;
        let order = serde_json::to_vec(&order)?;
        Ok(order)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-order`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `new_order` - http response body
    pub fn new_order_response(&self, order: Json) -> Result<types::E2eiNewAcmeOrder> {
        let order = serde_json::from_slice(&order[..])?;
        self.acme_new_order_response(order)?.try_into()
    }

    /// Creates a new authorization request.
    ///
    /// See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
    ///
    /// # Parameters
    /// * `url` - one of the URL in new order's authorizations (from [Self::new_order_response])
    /// * `account` - you got from [Self::new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/new-order`
    ///   (or from the previous to this method if you are creating the second authorization)
    pub fn new_authz_request(&self, url: String, previous_nonce: String) -> Result<Json> {
        let account = self.account.as_ref().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'newAccountResponse()'",
        ))?;
        let authz = self.acme_new_authz_request(&url.parse()?, account, previous_nonce)?;
        let authz = serde_json::to_vec(&authz)?;
        Ok(authz)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
    ///
    /// See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
    ///
    /// # Parameters
    /// * `new_authz` - http response body
    pub fn new_authz_response(&mut self, authz: Json) -> Result<types::E2eiNewAcmeAuthz> {
        let authz = serde_json::from_slice(&authz[..])?;
        let authz = self.acme_new_authz_response(authz)?;
        match &authz {
            E2eiAcmeAuthorization::User { .. } => self.user_authz = Some(authz.clone()),
            E2eiAcmeAuthorization::Device { .. } => self.device_authz = Some(authz.clone()),
        };
        authz.try_into()
    }

    /// Generates a new client Dpop JWT token. It demonstrates proof of possession of the nonces
    /// (from wire-server & acme server) and will be verified by the acme server when verifying the
    /// challenge (in order to deliver a certificate).
    ///
    /// Then send it to
    /// [`POST /clients/{id}/access-token`](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// on wire-server.
    ///
    /// # Parameters
    /// * `expiry_secs` - of the client Dpop JWT. This should be equal to the grace period set in Team Management
    /// * `backend_nonce` - you get by calling `GET /clients/token/nonce` on wire-server.
    ///   See endpoint [definition](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce)
    /// * `expiry` - token expiry
    #[allow(clippy::too_many_arguments)]
    pub fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> Result<String> {
        let expiry = core::time::Duration::from_secs(expiry_secs as u64);
        let authz = self
            .device_authz
            .as_ref()
            .ok_or(Error::OutOfOrderEnrollment("You must first call 'newAuthzResponse()'"))?;
        let challenge = match authz {
            E2eiAcmeAuthorization::Device { challenge, .. } => challenge,
            E2eiAcmeAuthorization::User { .. } => return Err(Error::ImplementationError),
        };
        Ok(self.new_dpop_token(
            &self.client_id,
            self.display_name.as_str(),
            challenge,
            backend_nonce,
            self.handle.as_str(),
            self.team.clone(),
            expiry,
        )?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `access_token` - returned by wire-server from [this endpoint](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// * `dpop_challenge` - you found after [Self::new_authz_response]
    /// * `account` - you got from [Self::new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn new_dpop_challenge_request(&self, access_token: String, previous_nonce: String) -> Result<Json> {
        let authz = self
            .device_authz
            .as_ref()
            .ok_or(Error::OutOfOrderEnrollment("You must first call 'newAuthzResponse()'"))?;
        let challenge = match authz {
            E2eiAcmeAuthorization::Device { challenge, .. } => challenge,
            E2eiAcmeAuthorization::User { .. } => return Err(Error::ImplementationError),
        };
        let account = self.account.as_ref().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'newAccountResponse()'",
        ))?;
        let challenge = self.acme_dpop_challenge_request(access_token, challenge, account, previous_nonce)?;
        let challenge = serde_json::to_vec(&challenge)?;
        Ok(challenge)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for the DPoP challenge
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `challenge` - http response body
    pub fn new_dpop_challenge_response(&self, challenge: Json) -> Result<()> {
        let challenge = serde_json::from_slice(&challenge[..])?;
        Ok(self.acme_new_challenge_response(challenge)?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `id_token` - you get back from Identity Provider
    /// * `oidc_challenge` - you found after [Self::new_authz_response]
    /// * `account` - you got from [Self::new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn new_oidc_challenge_request(&mut self, id_token: String, previous_nonce: String) -> Result<Json> {
        let authz = self
            .user_authz
            .as_ref()
            .ok_or(Error::OutOfOrderEnrollment("You must first call 'newAuthzResponse()'"))?;
        let challenge = match authz {
            E2eiAcmeAuthorization::User { challenge, .. } => challenge,
            E2eiAcmeAuthorization::Device { .. } => return Err(Error::ImplementationError),
        };
        let account = self.account.as_ref().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'newAccountResponse()'",
        ))?;
        let challenge = self.acme_oidc_challenge_request(id_token, challenge, account, previous_nonce)?;
        let challenge = serde_json::to_vec(&challenge)?;

        self.has_called_new_oidc_challenge_request = true;

        Ok(challenge)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for the OIDC challenge
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `challenge` - http response body
    pub async fn new_oidc_challenge_response(&mut self, challenge: Json) -> Result<()> {
        let challenge = serde_json::from_slice(&challenge[..])?;
        self.acme_new_challenge_response(challenge)?;

        if !self.has_called_new_oidc_challenge_request {
            return Err(Error::OutOfOrderEnrollment(
                "You must first call 'new_oidc_challenge_request()'",
            ));
        }

        Ok(())
    }

    /// Verifies that the previous challenge has been completed.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order_url` - `location` header from http response you got from [Self::new_order_response]
    /// * `account` - you got from [Self::new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
    pub fn check_order_request(&self, order_url: String, previous_nonce: String) -> Result<Json> {
        let account = self.account.as_ref().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'newAccountResponse()'",
        ))?;
        let order = self.acme_check_order_request(order_url.parse()?, account, previous_nonce)?;
        let order = serde_json::to_vec(&order)?;
        Ok(order)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order` - http response body
    ///
    /// # Returns
    /// The finalize url to use with [Self::finalize_request]
    pub fn check_order_response(&mut self, order: Json) -> Result<String> {
        let order = serde_json::from_slice(&order[..])?;
        let valid_order = self.acme_check_order_response(order)?;
        let finalize_url = valid_order.finalize_url.to_string();
        self.valid_order = Some(valid_order);
        Ok(finalize_url)
    }

    /// Final step before fetching the certificate.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `domains` - you want to generate a certificate for e.g. `["wire.com"]`
    /// * `order` - you got from [Self::check_order_response]
    /// * `account` - you got from [Self::new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}`
    pub fn finalize_request(&mut self, previous_nonce: String) -> Result<Json> {
        let account = self.account.as_ref().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'newAccountResponse()'",
        ))?;
        let order = self.valid_order.as_ref().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'checkOrderResponse()'",
        ))?;
        let finalize = self.acme_finalize_request(order, account, previous_nonce)?;
        let finalize = serde_json::to_vec(&finalize)?;
        Ok(finalize)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `finalize` - http response body
    ///
    /// # Returns
    /// The certificate url to use with [Self::certificate_request]
    pub fn finalize_response(&mut self, finalize: Json) -> Result<String> {
        let finalize = serde_json::from_slice(&finalize[..])?;
        let finalize = self.acme_finalize_response(finalize)?;
        let certificate_url = finalize.certificate_url.to_string();
        self.finalize = Some(finalize);
        Ok(certificate_url)
    }

    /// Creates a request for finally fetching the x509 certificate.
    ///
    /// See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2).
    ///
    /// # Parameters
    /// * `finalize` - you got from [Self::finalize_response]
    /// * `account` - you got from [Self::new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}/finalize`
    pub fn certificate_request(&mut self, previous_nonce: String) -> Result<Json> {
        let account = self.account.take().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'newAccountResponse()'",
        ))?;
        let finalize = self
            .finalize
            .take()
            .ok_or(Error::OutOfOrderEnrollment("You must first call 'finalizeResponse()'"))?;
        let certificate = self.acme_x509_certificate_request(finalize, account, previous_nonce)?;
        let certificate = serde_json::to_vec(&certificate)?;
        Ok(certificate)
    }

    pub(crate) async fn certificate_response(
        &mut self,
        certificate_chain: String,
        env: &wire_e2e_identity::prelude::x509::revocation::PkiEnvironment,
    ) -> Result<Vec<Vec<u8>>> {
        let order = self.valid_order.take().ok_or(Error::OutOfOrderEnrollment(
            "You must first call 'checkOrderResponse()'",
        ))?;
        let certificates = self.acme_x509_certificate_response(certificate_chain, order, Some(env))?;

        // zeroize the private material
        self.sign_sk.zeroize();
        self.delegate.sign_kp.zeroize();
        self.delegate.acme_kp.zeroize();

        Ok(certificates)
    }

    pub(crate) async fn stash(self, backend: &MlsCryptoProvider) -> Result<EnrollmentHandle> {
        // should be enough to prevent collisions
        const HANDLE_SIZE: usize = 32;

        let content = serde_json::to_vec(&self)?;
        let handle = backend
            .crypto()
            .random_vec(HANDLE_SIZE)
            .map_err(MlsError::wrap("generating random vector of bytes"))?;
        backend
            .key_store()
            .save_e2ei_enrollment(&handle, &content)
            .await
            .map_err(KeystoreError::wrap("saving e2ei enrollment"))?;
        Ok(handle)
    }

    pub(crate) async fn stash_pop(backend: &MlsCryptoProvider, handle: EnrollmentHandle) -> Result<Self> {
        let content = backend
            .key_store()
            .pop_e2ei_enrollment(&handle)
            .await
            .map_err(KeystoreError::wrap("popping e2ei enrollment"))?;
        Ok(serde_json::from_slice(&content)?)
    }
}
