use error::*;
use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, Ed25519KeyPair, Jwk};
use prelude::*;
use rusty_acme::prelude::AcmeChallenge;
use rusty_jwt_tools::jwk::TryIntoJwk;
use rusty_jwt_tools::prelude::{ClientId, Dpop, Htm, Pem, RustyJwtTools};

mod error;
mod types;

pub mod prelude {
    pub use super::error::{E2eIdentityError, E2eIdentityResult};
    pub use super::types::{
        E2eiAcmeAccount, E2eiAcmeChall, E2eiAcmeFinalize, E2eiAcmeOrder, E2eiNewAcmeAuthz, E2eiNewAcmeOrder,
    };
    pub use super::RustyE2eIdentity;
    pub use rusty_acme::prelude::{AcmeDirectory, RustyAcme, RustyAcmeError};
    pub use rusty_jwt_tools::prelude::{HashAlgorithm, JwsAlgorithm, RustyJwtError};
}

pub type Json = serde_json::Value;

#[derive(Debug)]
pub struct RustyE2eIdentity {
    sign_alg: JwsAlgorithm,
    sign_kp: Pem,
    pub hash_alg: HashAlgorithm,
    jwk: Jwk,
}

impl RustyE2eIdentity {
    /// Builds an instance holding private key material. This instance has to be used in the whole
    /// enrollment process then dropped to clear secret key material.
    ///
    /// # Parameters
    /// * `sign_alg` - Signature algorithm (only Ed25519 for now)
    /// * `raw_sign_kp` - Signature keypair in PEM format
    pub fn try_new(sign_alg: JwsAlgorithm, raw_sign_kp: Vec<u8>) -> E2eIdentityResult<Self> {
        let (sign_kp, jwk) = match sign_alg {
            JwsAlgorithm::Ed25519 => {
                let kp = Ed25519KeyPair::from_bytes(raw_sign_kp.as_slice())?;
                (kp.to_pem(), kp.public_key().try_into_jwk()?)
            }
            JwsAlgorithm::P256 => {
                let kp = ES256KeyPair::from_bytes(raw_sign_kp.as_slice())?;
                (kp.to_pem()?, kp.public_key().try_into_jwk()?)
            }
            JwsAlgorithm::P384 => {
                let kp = ES384KeyPair::from_bytes(raw_sign_kp.as_slice())?;
                (kp.to_pem()?, kp.public_key().try_into_jwk()?)
            }
        };
        Ok(Self {
            sign_alg,
            sign_kp: sign_kp.into(),
            hash_alg: HashAlgorithm::from(sign_alg),
            jwk,
        })
    }

    /// Parses the response from `GET /acme/{provisioner-name}/directory`.
    /// Use this [AcmeDirectory] in the next step to fetch the first nonce from the acme server. Use
    /// [AcmeDirectory::new_nonce].
    ///
    /// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
    ///
    /// # Parameters
    /// * `directory` - http response body
    pub fn acme_directory_response(&self, directory: Json) -> E2eIdentityResult<AcmeDirectory> {
        let directory = RustyAcme::acme_directory_response(directory)?;
        Ok(directory)
    }

    /// For creating a new acme account. This returns a signed JWS-alike request body to send to
    /// `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `directory` - you got from [Self::acme_directory_response]
    /// * `previous_nonce` - you got from calling `HEAD {directory.new_nonce}`
    pub fn acme_new_account_request(
        &self,
        directory: &AcmeDirectory,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let acct_req = RustyAcme::new_account_request(directory, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(acct_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `account` - http response body
    pub fn acme_new_account_response(&self, account: Json) -> E2eIdentityResult<E2eiAcmeAccount> {
        let account = RustyAcme::new_account_response(account)?;
        Ok(serde_json::to_value(account)?.into())
    }

    /// Creates a new acme order for the handle (userId + display name) and the clientId.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `domain` - DNS name of owning backend e.g. `example.com`
    /// * `client_id` - client identifier with user b64Url encoded & clientId hex encoded e.g. `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ/6add501bacd1d90e@example.com`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry` - x509 generated certificate expiry
    /// * `directory` - you got from [Self::acme_directory_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/new-account`
    #[allow(clippy::too_many_arguments)]
    pub fn acme_new_order_request(
        &self,
        display_name: &str,
        client_id: &str,
        handle: &str,
        expiry: core::time::Duration,
        directory: &AcmeDirectory,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = serde_json::from_value(account.clone().into())?;
        let client_id = ClientId::try_from_qualified(client_id)?;
        let order_req = RustyAcme::new_order_request(
            display_name,
            client_id,
            handle,
            expiry,
            directory,
            &account,
            self.sign_alg,
            &self.sign_kp,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(order_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-order`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `new_order` - http response body
    pub fn acme_new_order_response(&self, new_order: Json) -> E2eIdentityResult<E2eiNewAcmeOrder> {
        let new_order = RustyAcme::new_order_response(new_order)?;
        let authorizations = new_order.authorizations.clone();
        let new_order = serde_json::to_vec(&new_order)?.into();
        Ok(E2eiNewAcmeOrder {
            new_order,
            authorizations,
        })
    }

    /// Creates a new authorization request.
    ///
    /// See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
    ///
    /// # Parameters
    /// * `url` - one of the URL in new order's authorizations (from [Self::acme_new_order_response])
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/new-order`
    /// (or from the previous to this method if you are creating the second authorization)
    pub fn acme_new_authz_request(
        &self,
        url: &url::Url,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = serde_json::from_value(account.clone().into())?;
        let authz_req = RustyAcme::new_authz_request(url, &account, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(authz_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
    ///
    /// You then have to map the challenge from this authorization object. The `client_id_challenge`
    /// will be the one with the `client_id_host` (you supplied to [Self::acme_new_order_request]) identifier,
    /// the other will be your `handle_challenge`.
    ///
    /// See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
    ///
    /// # Parameters
    /// * `new_authz` - http response body
    pub fn acme_new_authz_response(&self, new_authz: Json) -> E2eIdentityResult<E2eiNewAcmeAuthz> {
        let new_authz = serde_json::from_value(new_authz)?;
        let new_authz = RustyAcme::new_authz_response(new_authz)?;
        let identifier = new_authz.identifier.to_json()?;

        let wire_dpop_challenge = new_authz
            .wire_dpop_challenge()
            .map(|c| serde_json::to_value(c).map(|chall| (chall, c.url.clone())))
            .transpose()?
            .map(|(chall, url)| E2eiAcmeChall { url, chall });
        let wire_oidc_challenge = new_authz
            .wire_oidc_challenge()
            .map(|c| serde_json::to_value(c).map(|chall| (chall, c.url.clone())))
            .transpose()?
            .map(|(chall, url)| E2eiAcmeChall { url, chall });

        Ok(E2eiNewAcmeAuthz {
            identifier,
            wire_dpop_challenge,
            wire_oidc_challenge,
        })
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
    /// * `access_token_url` - backend endpoint where this token will be sent. Should be [this one](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// * `user_id` - an UUIDv4 uniquely identifying the user
    /// * `client` - client identifier
    /// * `domain` - owning backend domain e.g. `wire.com`
    /// * `client_id_challenge` - you found after [Self::acme_new_authz_response]
    /// * `backend_nonce` - you get by calling `GET /clients/token/nonce` on wire-server.
    /// See endpoint [definition](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce)
    /// * `backend_nonce` - you get by calling `GET /clients/token/nonce` on wire-server.
    /// * `expiry` - token expiry
    #[allow(clippy::too_many_arguments)]
    pub fn new_dpop_token(
        &self,
        access_token_url: &url::Url,
        client_id: &str,
        dpop_challenge: &E2eiAcmeChall,
        backend_nonce: String,
        expiry: core::time::Duration,
    ) -> E2eIdentityResult<String> {
        let client_id_challenge = serde_json::from_value::<AcmeChallenge>(dpop_challenge.chall.clone())?;
        let dpop = Dpop {
            htu: access_token_url.as_str().try_into()?,
            htm: Htm::Post,
            challenge: client_id_challenge.token.into(),
            extra_claims: None,
        };
        let client_id = ClientId::try_from_qualified(client_id)?;
        Ok(RustyJwtTools::generate_dpop_token(
            dpop,
            &client_id,
            backend_nonce.into(),
            expiry,
            self.sign_alg,
            &self.sign_kp,
        )?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `access_token` - returned by wire-server from [this endpoint](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// * `dpop_challenge` - you found after [Self::acme_new_authz_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn acme_dpop_challenge_request(
        &self,
        access_token: String,
        dpop_challenge: &E2eiAcmeChall,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = serde_json::from_value(account.clone().into())?;
        let handle_chall = serde_json::from_value(dpop_challenge.chall.clone())?;
        let new_challenge_req = RustyAcme::dpop_chall_request(
            access_token,
            handle_chall,
            &account,
            self.sign_alg,
            &self.sign_kp,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(new_challenge_req)?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `id_token` - returned by Identity Provider
    /// * `oidc_challenge` - you found after [Self::acme_new_authz_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn acme_oidc_challenge_request(
        &self,
        id_token: String,
        oidc_challenge: &E2eiAcmeChall,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = serde_json::from_value(account.clone().into())?;
        let oidc_chall = serde_json::from_value(oidc_challenge.chall.clone())?;
        let new_challenge_req = RustyAcme::oidc_chall_request(
            id_token,
            oidc_chall,
            &account,
            self.sign_alg,
            self.hash_alg,
            &self.sign_kp,
            &self.jwk,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(new_challenge_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}`.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `challenge` - http response body
    pub fn acme_new_challenge_response(&self, challenge: Json) -> E2eIdentityResult<()> {
        let challenge = serde_json::from_value(challenge)?;
        RustyAcme::new_chall_response(challenge)?;
        Ok(())
    }

    /// Verifies that the previous challenge has been completed.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order_url` - "location" header from http response you got from [Self::acme_new_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
    pub fn acme_check_order_request(
        &self,
        order_url: url::Url,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = serde_json::from_value(account.clone().into())?;
        let check_order_req =
            RustyAcme::check_order_request(order_url, &account, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(check_order_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order` - http response body
    pub fn acme_check_order_response(&self, order: Json) -> E2eIdentityResult<E2eiAcmeOrder> {
        let order = RustyAcme::check_order_response(order)?;
        Ok(serde_json::to_value(order)?.into())
    }

    /// Final step before fetching the certificate.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `domains` - domains you want to generate a certificate for e.g. `["wire.com"]`
    /// * `order` - you got from [Self::acme_check_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/order/{order-id}`
    pub fn acme_finalize_request(
        &self,
        order: E2eiAcmeOrder,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let order = serde_json::from_value(order.into())?;
        let account = serde_json::from_value(account.clone().into())?;
        let finalize_req = RustyAcme::finalize_req(order, &account, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(finalize_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `finalize` - http response body
    pub fn acme_finalize_response(&self, finalize: Json) -> E2eIdentityResult<E2eiAcmeFinalize> {
        let finalize = RustyAcme::finalize_response(finalize)?;
        let certificate_url = finalize.certificate.clone();
        let finalize = serde_json::to_value(&finalize)?;
        Ok(E2eiAcmeFinalize {
            certificate_url,
            finalize,
        })
    }

    /// Creates a request for finally fetching the x509 certificate.
    ///
    /// See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2).
    ///
    /// # Parameters
    /// * `domains` - domains you want to generate a certificate for e.g. `["wire.com"]`
    /// * `order` - you got from [Self::acme_check_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - "replay-nonce" response header from `POST /acme/{provisioner-name}/order/{order-id}`
    pub fn acme_x509_certificate_request(
        &self,
        finalize: E2eiAcmeFinalize,
        account: E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let finalize = serde_json::from_value(finalize.finalize)?;
        let account = serde_json::from_value(account.into())?;
        let certificate_req =
            RustyAcme::certificate_req(finalize, account, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(certificate_req)?)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/certificate/{certificate-id}`.
    ///
    /// See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
    ///
    /// # Parameters
    /// * `response` - http string response body
    pub fn acme_x509_certificate_response(&self, response: String) -> E2eIdentityResult<Vec<String>> {
        Ok(RustyAcme::certificate_response(response)?)
    }
}
