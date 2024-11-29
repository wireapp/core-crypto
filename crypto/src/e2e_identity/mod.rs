use openmls_traits::OpenMlsCryptoProvider;
use std::collections::HashMap;

use wire_e2e_identity::prelude::{E2eiAcmeAuthorization, RustyE2eIdentity};
use zeroize::Zeroize;

use error::{Error, Result};
use mls_crypto_provider::MlsCryptoProvider;

use crate::e2e_identity::init_certificates::NewCrlDistributionPoint;
use crate::{
    e2e_identity::{crypto::E2eiSignatureKeypair, id::QualifiedE2eiClientId},
    mls::credential::x509::CertificatePrivateKey,
    prelude::{id::ClientId, identifier::ClientIdentifier, CertificateBundle, MlsCiphersuite},
    CryptoError,
};

pub(crate) mod conversation_state;
mod crypto;
pub(crate) mod device_status;
pub mod enabled;
pub mod error;
pub(crate) mod id;
pub(crate) mod identity;
pub(crate) mod init_certificates;
#[cfg(not(target_family = "wasm"))]
pub(crate) mod refresh_token;
pub(crate) mod rotate;
pub(crate) mod stash;
pub mod types;

use crate::context::CentralContext;
pub use init_certificates::E2eiDumpedPkiEnv;

type Json = Vec<u8>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Supporting struct for CRL registration result
pub struct CrlRegistration {
    /// Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
    pub dirty: bool,
    /// Optional expiration timestamp
    pub expiration: Option<u64>,
}

impl CentralContext {
    /// Creates an enrollment instance with private key material you can use in order to fetch
    /// a new x509 certificate from the acme server.
    ///
    /// # Parameters
    /// * `client_id` - client identifier e.g. `b7ac11a4-8f01-4527-af88-1c30885a7931:6add501bacd1d90e@example.com`
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_sec` - generated x509 certificate expiry in seconds
    pub async fn e2ei_new_enrollment(
        &self,
        client_id: ClientId,
        display_name: String,
        handle: String,
        team: Option<String>,
        expiry_sec: u32,
        ciphersuite: MlsCiphersuite,
    ) -> Result<E2eiEnrollment> {
        let signature_keypair = None; // fresh install without a Basic client. Supplying None will generate a new keypair
        E2eiEnrollment::try_new(
            client_id,
            display_name,
            handle,
            team,
            expiry_sec,
            &self.mls_provider().await?,
            ciphersuite,
            signature_keypair,
            #[cfg(not(target_family = "wasm"))]
            None, // fresh install so no refresh token registered yet
        )
    }

    /// Parses the ACME server response from the endpoint fetching x509 certificates and uses it
    /// to initialize the MLS client with a certificate
    pub async fn e2ei_mls_init_only(
        &self,
        enrollment: &mut E2eiEnrollment,
        certificate_chain: String,
        nb_init_key_packages: Option<usize>,
    ) -> Result<NewCrlDistributionPoint> {
        let sk = enrollment.get_sign_key_for_mls()?;
        let cs = enrollment.ciphersuite;
        let certificate_chain = enrollment
            .certificate_response(
                certificate_chain,
                self.mls_provider()
                    .await?
                    .authentication_service()
                    .borrow()
                    .await
                    .as_ref()
                    .ok_or(CryptoError::ConsumerError)?,
            )
            .await?;

        let crl_new_distribution_points = self
            .extract_dp_on_init(&certificate_chain[..])
            .await
            .map_err(Error::credential("extracting dp on init"))?;

        let private_key = CertificatePrivateKey {
            value: sk,
            signature_scheme: cs.signature_algorithm(),
        };

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
        };
        let identifier = ClientIdentifier::X509(HashMap::from([(cs.signature_algorithm(), cert_bundle)]));
        self.mls_init(identifier, vec![cs], nb_init_key_packages).await?;
        Ok(crl_new_distribution_points)
    }
}

/// Wire end to end identity solution for fetching a x509 certificate which identifies a client.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct E2eiEnrollment {
    delegate: RustyE2eIdentity,
    pub(crate) sign_sk: E2eiSignatureKeypair,
    client_id: String,
    display_name: String,
    handle: String,
    team: Option<String>,
    expiry: core::time::Duration,
    directory: Option<types::E2eiAcmeDirectory>,
    account: Option<wire_e2e_identity::prelude::E2eiAcmeAccount>,
    user_authz: Option<E2eiAcmeAuthorization>,
    device_authz: Option<E2eiAcmeAuthorization>,
    valid_order: Option<wire_e2e_identity::prelude::E2eiAcmeOrder>,
    finalize: Option<wire_e2e_identity::prelude::E2eiAcmeFinalize>,
    ciphersuite: MlsCiphersuite,
    #[cfg(not(target_family = "wasm"))]
    refresh_token: Option<refresh_token::RefreshToken>,
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
        #[cfg(not(target_family = "wasm"))] refresh_token: Option<refresh_token::RefreshToken>,
    ) -> Result<Self> {
        let alg = ciphersuite.try_into()?;
        let sign_sk = match sign_keypair {
            Some(kp) => kp,
            None => Self::new_sign_key(ciphersuite, backend)?,
        };

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
            #[cfg(not(target_family = "wasm"))]
            refresh_token,
        })
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
    /// * `refresh_token` - you get back from Identity Provider to renew the access token
    /// * `oidc_challenge` - you found after [Self::new_authz_response]
    /// * `account` - you got from [Self::new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn new_oidc_challenge_request(
        &mut self,
        id_token: String,
        #[cfg(not(target_family = "wasm"))] refresh_token: String,
        previous_nonce: String,
    ) -> Result<Json> {
        #[cfg(not(target_family = "wasm"))]
        {
            if refresh_token.is_empty() {
                return Err(Error::InvalidRefreshToken);
            }
        }
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
        #[cfg(not(target_family = "wasm"))]
        {
            self.refresh_token.replace(refresh_token.into());
        }
        Ok(challenge)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for the OIDC challenge
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `challenge` - http response body
    pub async fn new_oidc_challenge_response(
        &mut self,
        #[cfg(not(target_family = "wasm"))] backend: &MlsCryptoProvider,
        challenge: Json,
    ) -> Result<()> {
        let challenge = serde_json::from_slice(&challenge[..])?;
        self.acme_new_challenge_response(challenge)?;

        #[cfg(not(target_family = "wasm"))]
        {
            // Now that the OIDC challenge is valid, we can store the refresh token for future uses. Note
            // that we could have persisted it at the end of the enrollment but what if the next enrollment
            // steps fail ? Is it a reason good enough not to persist the token and ask the user to
            // authenticate again: probably not.
            let refresh_token = self.refresh_token.take().ok_or(Error::OutOfOrderEnrollment(
                "You must first call 'new_oidc_challenge_request()'",
            ))?;
            refresh_token.replace(backend).await?;
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

    async fn certificate_response(
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

        #[cfg(not(target_family = "wasm"))]
        self.refresh_token.zeroize();

        Ok(certificates)
    }
}

#[cfg(test)]
// This is pub(crate), to make constants below usable
pub(crate) mod tests {
    use itertools::Itertools;
    use mls_crypto_provider::PkiKeypair;

    #[cfg(not(target_family = "wasm"))]
    use openmls_traits::OpenMlsCryptoProvider;
    use serde_json::json;
    use wasm_bindgen_test::*;

    use crate::context::CentralContext;
    #[cfg(not(target_family = "wasm"))]
    use crate::e2e_identity::refresh_token::RefreshToken;
    use crate::{
        e2e_identity::{
            error::{Error, Result},
            id::QualifiedE2eiClientId,
            tests::x509::X509TestChain,
        },
        prelude::*,
        test_utils::{context::TEAM, *},
    };

    wasm_bindgen_test_configure!(run_in_browser);

    pub(crate) const E2EI_DISPLAY_NAME: &str = "Alice Smith";
    pub(crate) const E2EI_HANDLE: &str = "alice_wire";
    pub(crate) const E2EI_CLIENT_ID: &str = "bd4c7053-1c5a-4020-9559-cd7bf7961954:4959bc6ab12f2846@world.com";
    pub(crate) const E2EI_CLIENT_ID_URI: &str = "vUxwUxxaQCCVWc1795YZVA!4959bc6ab12f2846@world.com";
    pub(crate) const E2EI_EXPIRY: u32 = 90 * 24 * 3600;

    pub(crate) fn init_enrollment(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
        Box::pin(async move {
            let E2eiInitWrapper { context: cc, case } = wrapper;
            let cs = case.ciphersuite();
            cc.e2ei_new_enrollment(
                E2EI_CLIENT_ID.into(),
                E2EI_DISPLAY_NAME.to_string(),
                E2EI_HANDLE.to_string(),
                Some(TEAM.to_string()),
                E2EI_EXPIRY,
                cs,
            )
            .await
        })
    }

    pub(crate) const NEW_HANDLE: &str = "new_alice_wire";
    pub(crate) const NEW_DISPLAY_NAME: &str = "New Alice Smith";
    pub(crate) fn init_activation_or_rotation(wrapper: E2eiInitWrapper) -> InitFnReturn<'_> {
        Box::pin(async move {
            let E2eiInitWrapper { context: cc, case } = wrapper;
            let cs = case.ciphersuite();
            match case.credential_type {
                MlsCredentialType::Basic => {
                    cc.e2ei_new_activation_enrollment(
                        NEW_DISPLAY_NAME.to_string(),
                        NEW_HANDLE.to_string(),
                        Some(TEAM.to_string()),
                        E2EI_EXPIRY,
                        cs,
                    )
                    .await
                }
                MlsCredentialType::X509 => {
                    cc.e2ei_new_rotate_enrollment(
                        Some(NEW_DISPLAY_NAME.to_string()),
                        Some(NEW_HANDLE.to_string()),
                        Some(TEAM.to_string()),
                        E2EI_EXPIRY,
                        cs,
                    )
                    .await
                }
            }
        })
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    async fn e2e_identity_should_work(case: TestCase) {
        run_test_wo_clients(case.clone(), move |mut cc| {
            Box::pin(async move {
                let x509_test_chain = X509TestChain::init_empty(case.signature_scheme());

                let is_renewal = false;

                let (mut enrollment, cert) = e2ei_enrollment(
                    &mut cc,
                    &case,
                    &x509_test_chain,
                    Some(E2EI_CLIENT_ID_URI),
                    is_renewal,
                    init_enrollment,
                    noop_restore,
                )
                .await
                .unwrap();

                cc.context
                    .e2ei_mls_init_only(&mut enrollment, cert, Some(INITIAL_KEYING_MATERIAL_COUNT))
                    .await
                    .unwrap();

                // verify the created client can create a conversation
                let id = conversation_id();
                cc.context
                    .new_conversation(&id, MlsCredentialType::X509, case.cfg.clone())
                    .await
                    .unwrap();
                cc.context.encrypt_message(&id, "Hello e2e identity !").await.unwrap();
                assert_eq!(
                    cc.context.e2ei_conversation_state(&id).await.unwrap(),
                    E2eiConversationState::Verified
                );
                assert!(cc.context.e2ei_is_enabled(case.signature_scheme()).await.unwrap());
            })
        })
        .await
    }

    pub(crate) type RestoreFnReturn<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = E2eiEnrollment> + 'a>>;

    pub(crate) fn noop_restore(e: E2eiEnrollment, _cc: &CentralContext) -> RestoreFnReturn<'_> {
        Box::pin(async move { e })
    }

    pub(crate) type InitFnReturn<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<E2eiEnrollment>> + 'a>>;

    /// Helps the compiler with its lifetime inference rules while passing async closures
    pub(crate) struct E2eiInitWrapper<'a> {
        pub(crate) context: &'a CentralContext,
        pub(crate) case: &'a TestCase,
    }

    pub(crate) async fn e2ei_enrollment<'a>(
        ctx: &'a mut ClientContext,
        case: &TestCase,
        x509_test_chain: &X509TestChain,
        client_id: Option<&str>,
        #[cfg(not(target_family = "wasm"))] is_renewal: bool,
        #[cfg(target_family = "wasm")] _is_renewal: bool,
        init: impl Fn(E2eiInitWrapper) -> InitFnReturn<'_>,
        // used to verify persisting the instance actually does restore it entirely
        restore: impl Fn(E2eiEnrollment, &'a CentralContext) -> RestoreFnReturn<'a>,
    ) -> Result<(E2eiEnrollment, String)> {
        x509_test_chain.register_with_central(&ctx.context).await;
        #[cfg(not(target_family = "wasm"))]
        {
            let backend = ctx.context.mls_provider().await?;
            let keystore = backend.key_store();
            if is_renewal {
                let initial_refresh_token =
                    crate::e2e_identity::refresh_token::RefreshToken::from("initial-refresh-token".to_string());
                let initial_refresh_token =
                    core_crypto_keystore::entities::E2eiRefreshToken::from(initial_refresh_token);
                keystore.save(initial_refresh_token).await?;
            }
        }

        let wrapper = E2eiInitWrapper {
            context: &ctx.context,
            case,
        };
        let mut enrollment = init(wrapper).await?;

        #[cfg(not(target_family = "wasm"))]
        {
            let backend = ctx.context.mls_provider().await?;
            let keystore = backend.key_store();
            if is_renewal {
                assert!(enrollment.refresh_token.is_some());
                assert!(RefreshToken::find(keystore).await.is_ok());
            } else {
                assert!(matches!(
                    enrollment.get_refresh_token().unwrap_err(),
                    Error::OutOfOrderEnrollment(_)
                ));
                assert!(RefreshToken::find(keystore).await.is_err());
            }
        }

        let (display_name, handle) = (enrollment.display_name.clone(), &enrollment.handle.clone());

        let directory = json!({
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order",
            "revokeCert": "https://example.com/acme/revoke-cert"
        });
        let directory = serde_json::to_vec(&directory)?;
        enrollment.directory_response(directory)?;

        let mut enrollment = restore(enrollment, &ctx.context).await;

        let previous_nonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
        let _account_req = enrollment.new_account_request(previous_nonce.to_string())?;

        let account_resp = json!({
            "status": "valid",
            "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
        });
        let account_resp = serde_json::to_vec(&account_resp)?;
        enrollment.new_account_response(account_resp)?;

        let enrollment = restore(enrollment, &ctx.context).await;

        let _order_req = enrollment.new_order_request(previous_nonce.to_string()).unwrap();
        let client_id = match client_id {
            None => ctx.get_e2ei_client_id().await.to_uri(),
            Some(client_id) => format!("{}{client_id}", wire_e2e_identity::prelude::E2eiClientId::URI_SCHEME),
        };
        let device_identifier = format!("{{\"name\":\"{display_name}\",\"domain\":\"world.com\",\"client-id\":\"{client_id}\",\"handle\":\"wireapp://%40{handle}@world.com\"}}");
        let user_identifier = format!(
            "{{\"name\":\"{display_name}\",\"domain\":\"world.com\",\"handle\":\"wireapp://%40{handle}@world.com\"}}"
        );
        let order_resp = json!({
            "status": "pending",
            "expires": "2037-01-05T14:09:07.99Z",
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2037-01-08T00:00:00Z",
            "identifiers": [
                {
                  "type": "wireapp-user",
                  "value": user_identifier
                },
                {
                  "type": "wireapp-device",
                  "value": device_identifier
                }
            ],
            "authorizations": [
                "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
                "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        });
        let order_resp = serde_json::to_vec(&order_resp)?;
        let new_order = enrollment.new_order_response(order_resp)?;

        let mut enrollment = restore(enrollment, &ctx.context).await;

        let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";

        let [user_authz_url, device_authz_url] = new_order.authorizations.as_slice() else {
            unreachable!()
        };

        let _user_authz_req = enrollment.new_authz_request(user_authz_url.to_string(), previous_nonce.to_string())?;

        let user_authz_resp = json!({
            "status": "pending",
            "expires": "2037-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-user",
              "value": user_identifier
            },
            "challenges": [
              {
                "type": "wire-oidc-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "http://example.com/target"
              }
            ]
        });
        let user_authz_resp = serde_json::to_vec(&user_authz_resp)?;
        enrollment.new_authz_response(user_authz_resp)?;

        let _device_authz_req =
            enrollment.new_authz_request(device_authz_url.to_string(), previous_nonce.to_string())?;

        let device_authz_resp = json!({
            "status": "pending",
            "expires": "2037-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-device",
              "value": device_identifier
            },
            "challenges": [
              {
                "type": "wire-dpop-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://wire.com/clients/4959bc6ab12f2846/access-token"
              }
            ]
        });
        let device_authz_resp = serde_json::to_vec(&device_authz_resp)?;
        enrollment.new_authz_response(device_authz_resp)?;

        let enrollment = restore(enrollment, &ctx.context).await;

        let backend_nonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
        let _dpop_token = enrollment.create_dpop_token(3600, backend_nonce.to_string())?;

        let access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA".to_string();
        let _dpop_chall_req = enrollment.new_dpop_challenge_request(access_token, previous_nonce.to_string())?;
        let dpop_chall_resp = json!({
            "type": "wire-dpop-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "valid",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0",
            "target": "http://example.com/target"
        });
        let dpop_chall_resp = serde_json::to_vec(&dpop_chall_resp)?;
        enrollment.new_dpop_challenge_response(dpop_chall_resp)?;

        let mut enrollment = restore(enrollment, &ctx.context).await;

        let id_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ".to_string();
        #[cfg(not(target_family = "wasm"))]
        let new_refresh_token = "new-refresh-token";
        let _oidc_chall_req = enrollment.new_oidc_challenge_request(
            id_token,
            #[cfg(not(target_family = "wasm"))]
            new_refresh_token.to_string(),
            previous_nonce.to_string(),
        )?;

        #[cfg(not(target_family = "wasm"))]
        assert!(enrollment.get_refresh_token().is_ok());

        let oidc_chall_resp = json!({
            "type": "wire-oidc-01",
            "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
            "status": "valid",
            "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb",
            "target": "http://example.com/target"
        });
        let oidc_chall_resp = serde_json::to_vec(&oidc_chall_resp)?;

        #[cfg(not(target_family = "wasm"))]
        {
            let backend = ctx.context.mls_provider().await?;
            let keystore = backend.key_store();
            enrollment
                .new_oidc_challenge_response(&ctx.context.mls_provider().await.unwrap(), oidc_chall_resp)
                .await?;
            // Now Refresh token is persisted in the keystore
            assert_eq!(RefreshToken::find(keystore).await?.as_str(), new_refresh_token);
            // No reason at this point to have the refresh token in memory
            assert!(enrollment.get_refresh_token().is_err());
        }

        #[cfg(target_family = "wasm")]
        enrollment.new_oidc_challenge_response(oidc_chall_resp).await?;

        let mut enrollment = restore(enrollment, &ctx.context).await;

        let _get_order_req = enrollment.check_order_request(order_url.to_string(), previous_nonce.to_string())?;

        let order_resp = json!({
          "status": "ready",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-user",
              "value": user_identifier
            },
            {
              "type": "wireapp-device",
              "value": device_identifier
            }
          ],
          "authorizations": [
            "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
            "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
          ],
          "expires": "2037-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2037-02-09T15:59:20.442908Z"
        });
        let order_resp = serde_json::to_vec(&order_resp)?;
        enrollment.check_order_response(order_resp)?;

        let mut enrollment = restore(enrollment, &ctx.context).await;

        let _finalize_req = enrollment.finalize_request(previous_nonce.to_string())?;
        let finalize_resp = json!({
          "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
          "status": "valid",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-user",
              "value": user_identifier
            },
            {
              "type": "wireapp-device",
              "value": device_identifier
            }
          ],
          "authorizations": [
            "https://example.com/acme/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
            "https://example.com/acme/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
          ],
          "expires": "2037-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2037-02-09T15:59:20.442908Z"
        });
        let finalize_resp = serde_json::to_vec(&finalize_resp)?;
        enrollment.finalize_response(finalize_resp)?;

        let mut enrollment = restore(enrollment, &ctx.context).await;

        let _certificate_req = enrollment.certificate_request(previous_nonce.to_string())?;

        let existing_keypair = PkiKeypair::new(case.signature_scheme(), enrollment.sign_sk.to_vec()).unwrap();

        let client_id = QualifiedE2eiClientId::from_str_unchecked(enrollment.client_id.as_str());
        let cert = CertificateBundle::new(
            handle,
            &display_name,
            Some(&client_id),
            Some(existing_keypair),
            x509_test_chain.find_local_intermediate_ca(),
        );

        let cert_chain = cert
            .certificate_chain
            .into_iter()
            .map(|c| pem::Pem::new("CERTIFICATE", c).to_string())
            .join("");

        Ok((enrollment, cert_chain))
    }
}
