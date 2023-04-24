use std::collections::HashMap;
use wire_e2e_identity::prelude::RustyE2eIdentity;

use error::*;
use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::{id::ClientId, CertificateBundle, MlsCentral, MlsCiphersuite};
use crate::{mls::credential::x509::CertificatePrivateKey, prelude::identifier::ClientIdentifier};

mod crypto;
pub(crate) mod degraded;
pub mod error;
pub(crate) mod identity;
pub(crate) mod stash;
pub mod types;

type Json = Vec<u8>;

impl MlsCentral {
    /// Creates an enrollment instance with private key material you can use in order to fetch
    /// a new x509 certificate from the acme server.
    /// Make sure to call [WireE2eIdentity::free] (not yet available) to dispose this instance and its associated
    /// keying material.
    ///
    /// # Parameters
    /// * `client_id` - client identifier with user b64Url encoded & clientId hex encoded e.g. `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ:6add501bacd1d90e@example.com`
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_days` - generated x509 certificate expiry in days
    pub fn e2ei_new_enrollment(
        &self,
        client_id: ClientId,
        display_name: String,
        handle: String,
        expiry_days: u32,
        ciphersuite: MlsCiphersuite,
    ) -> E2eIdentityResult<WireE2eIdentity> {
        WireE2eIdentity::try_new(
            client_id,
            display_name,
            handle,
            expiry_days,
            &self.mls_backend,
            ciphersuite,
        )
    }

    /// Parses the ACME server response from the endpoint fetching x509 certificates and uses it
    /// to initialize the MLS client with a certificate
    pub async fn e2ei_mls_init(&mut self, e2ei: WireE2eIdentity, certificate_chain: String) -> E2eIdentityResult<()> {
        e2ei.certificate_response(self, certificate_chain).await
    }
}

/// Wire end to end identity solution for fetching a x509 certificate which identifies a client.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WireE2eIdentity {
    delegate: RustyE2eIdentity,
    sign_sk: Vec<u8>,
    client_id: String,
    display_name: String,
    handle: String,
    expiry: core::time::Duration,
    directory: Option<types::E2eiAcmeDirectory>,
    account: Option<wire_e2e_identity::prelude::E2eiAcmeAccount>,
    authz: Option<wire_e2e_identity::prelude::E2eiNewAcmeAuthz>,
    valid_order: Option<wire_e2e_identity::prelude::E2eiAcmeOrder>,
    finalize: Option<wire_e2e_identity::prelude::E2eiAcmeFinalize>,
    ciphersuite: MlsCiphersuite,
}

impl std::ops::Deref for WireE2eIdentity {
    type Target = RustyE2eIdentity;

    fn deref(&self) -> &Self::Target {
        &self.delegate
    }
}

impl WireE2eIdentity {
    /// Builds an instance holding private key material. This instance has to be used in the whole
    /// enrollment process then dropped to clear secret key material.
    ///
    /// # Parameters
    /// * `client_id` - client identifier with user b64Url encoded & clientId hex encoded e.g. `NDUyMGUyMmY2YjA3NGU3NjkyZjE1NjJjZTAwMmQ2NTQ:6add501bacd1d90e@example.com`
    /// * `display_name` - human readable name displayed in the application e.g. `Smith, Alice M (QA)`
    /// * `handle` - user handle e.g. `alice.smith.qa@example.com`
    /// * `expiry_days` - generated x509 certificate expiry in days
    pub fn try_new(
        client_id: ClientId,
        display_name: String,
        handle: String,
        expiry_days: u32,
        backend: &MlsCryptoProvider,
        ciphersuite: MlsCiphersuite,
    ) -> E2eIdentityResult<Self> {
        let alg = ciphersuite.try_into()?;
        let sign_sk = Self::new_sign_key(ciphersuite, backend)?;
        let client_id = std::str::from_utf8(&client_id[..])?.to_string();
        let expiry = core::time::Duration::from_secs(u64::from(expiry_days) * 24 * 3600);
        Ok(Self {
            delegate: RustyE2eIdentity::try_new(alg, sign_sk.clone())?,
            sign_sk,
            client_id,
            display_name,
            handle,
            expiry,
            directory: None,
            account: None,
            authz: None,
            valid_order: None,
            finalize: None,
            ciphersuite,
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
    pub fn directory_response(&mut self, directory: Json) -> E2eIdentityResult<types::E2eiAcmeDirectory> {
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
    /// * `directory` - you got from [Self::acme_directory_response]
    /// * `previous_nonce` - you got from calling `HEAD {directory.new_nonce}`
    pub fn new_account_request(&self, previous_nonce: String) -> E2eIdentityResult<Json> {
        let directory = self.directory.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
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
    pub fn new_account_response(&mut self, account: Json) -> E2eIdentityResult<()> {
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
    pub fn new_order_request(&self, previous_nonce: String) -> E2eIdentityResult<Json> {
        let directory = self.directory.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let account = self.account.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
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
    pub fn new_order_response(&self, order: Json) -> E2eIdentityResult<types::E2eiNewAcmeOrder> {
        let order = serde_json::from_slice(&order[..])?;
        self.acme_new_order_response(order)?.try_into()
    }

    /// Creates a new authorization request.
    ///
    /// See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
    ///
    /// # Parameters
    /// * `url` - one of the URL in new order's authorizations (from [Self::acme_new_order_response])
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/new-order`
    /// (or from the previous to this method if you are creating the second authorization)
    pub fn new_authz_request(&self, url: String, previous_nonce: String) -> E2eIdentityResult<Json> {
        let account = self.account.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
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
    pub fn new_authz_response(&mut self, authz: Json) -> E2eIdentityResult<types::E2eiNewAcmeAuthz> {
        let authz = serde_json::from_slice(&authz[..])?;
        let authz = self.acme_new_authz_response(authz)?;
        self.authz = Some(authz.clone());
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
    /// See endpoint [definition](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce)
    /// * `expiry` - token expiry
    #[allow(clippy::too_many_arguments)]
    pub fn create_dpop_token(&self, expiry_secs: u32, backend_nonce: String) -> E2eIdentityResult<String> {
        let expiry = core::time::Duration::from_secs(expiry_secs as u64);
        let authz = self.authz.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let dpop_challenge = authz
            .wire_dpop_challenge
            .as_ref()
            .ok_or(E2eIdentityError::ImplementationError)?;
        Ok(self.new_dpop_token(&self.client_id, dpop_challenge, backend_nonce, expiry)?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `access_token` - returned by wire-server from [this endpoint](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// * `dpop_challenge` - you found after [Self::acme_new_authz_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn new_dpop_challenge_request(&self, access_token: String, previous_nonce: String) -> E2eIdentityResult<Json> {
        let authz = self.authz.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let dpop_challenge = authz
            .wire_dpop_challenge
            .as_ref()
            .ok_or(E2eIdentityError::ImplementationError)?;
        let account = self.account.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let challenge = self.acme_dpop_challenge_request(access_token, dpop_challenge, account, previous_nonce)?;
        let challenge = serde_json::to_vec(&challenge)?;
        Ok(challenge)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `id_token` - you get back from Identity Provider
    /// * `oidc_challenge` - you found after [Self::acme_new_authz_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn new_oidc_challenge_request(&self, id_token: String, previous_nonce: String) -> E2eIdentityResult<Json> {
        let authz = self.authz.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let oidc_challenge = authz
            .wire_oidc_challenge
            .as_ref()
            .ok_or(E2eIdentityError::ImplementationError)?;
        let account = self.account.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let challenge = self.acme_oidc_challenge_request(id_token, oidc_challenge, account, previous_nonce)?;
        let challenge = serde_json::to_vec(&challenge)?;
        Ok(challenge)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}`.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `challenge` - http response body
    pub fn new_challenge_response(&self, challenge: Json) -> E2eIdentityResult<()> {
        let challenge = serde_json::from_slice(&challenge[..])?;
        Ok(self.acme_new_challenge_response(challenge)?)
    }

    /// Verifies that the previous challenge has been completed.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order_url` - `location` header from http response you got from [Self::acme_new_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
    pub fn check_order_request(&self, order_url: String, previous_nonce: String) -> E2eIdentityResult<Json> {
        let account = self.account.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
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
    pub fn check_order_response(&mut self, order: Json) -> E2eIdentityResult<String> {
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
    /// * `order` - you got from [Self::acme_check_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}`
    pub fn finalize_request(&mut self, previous_nonce: String) -> E2eIdentityResult<Json> {
        let account = self.account.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let order = self.valid_order.take().ok_or(E2eIdentityError::ImplementationError)?;
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
    pub fn finalize_response(&mut self, finalize: Json) -> E2eIdentityResult<String> {
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
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}/finalize`
    pub fn certificate_request(&mut self, previous_nonce: String) -> E2eIdentityResult<Json> {
        let account = self.account.take().ok_or(E2eIdentityError::ImplementationError)?;
        let finalize = self.finalize.take().ok_or(E2eIdentityError::ImplementationError)?;
        let certificate = self.acme_x509_certificate_request(finalize, account, previous_nonce)?;
        let certificate = serde_json::to_vec(&certificate)?;
        Ok(certificate)
    }

    async fn certificate_response(
        self,
        mls_central: &mut MlsCentral,
        certificate_chain: String,
    ) -> E2eIdentityResult<()> {
        let certificate_chain = self.acme_x509_certificate_response(certificate_chain)?;
        let private_key = CertificatePrivateKey {
            value: self.sign_sk,
            signature_scheme: self.ciphersuite.signature_algorithm(),
        };

        let cert_bundle = CertificateBundle {
            certificate_chain,
            private_key,
        };
        // TODO
        let identifier = ClientIdentifier::X509(HashMap::from([(self.ciphersuite, cert_bundle)]));
        mls_central.mls_init(identifier, vec![self.ciphersuite]).await?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::prelude::E2eIdentityError;
    use crate::{
        prelude::{ClientId, E2eIdentityResult, MlsCentral, WireE2eIdentity},
        test_utils::*,
    };
    use serde_json::json;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    #[ignore]
    pub async fn e2e_identity_should_work(case: TestCase) {
        run_test_wo_clients(case.clone(), move |cc| {
            Box::pin(async move {
                let result = e2ei_enrollment(case, cc, move |e, cc| Box::pin(async move { (e, cc) })).await;
                assert!(result.is_ok());
            })
        })
        .await
    }

    pub type RestoreFnResult<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = (WireE2eIdentity, MlsCentral)> + 'a>>;

    pub async fn e2ei_enrollment<'a>(
        case: TestCase,
        cc: MlsCentral,
        // used to verify persisting the instance actually does restore it entirely
        restore: impl Fn(WireE2eIdentity, MlsCentral) -> RestoreFnResult<'a> + 'a,
    ) -> E2eIdentityResult<()> {
        let display_name = "Alice Smith".to_string();
        let domain = "wire.com";
        let client_id: ClientId = format!("NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg:6c1866f567616f31@{domain}")
            .as_str()
            .into();
        let handle = "alice_wire".to_string();
        let expiry = 90;

        let mut enrollment = cc.e2ei_new_enrollment(client_id, display_name, handle, expiry, case.ciphersuite())?;
        let directory = json!({
            "newNonce": "https://example.com/acme/new-nonce",
            "newAccount": "https://example.com/acme/new-account",
            "newOrder": "https://example.com/acme/new-order"
        });
        let directory = serde_json::to_vec(&directory)?;
        enrollment.directory_response(directory)?;

        let (mut enrollment, cc) = restore(enrollment, cc).await;

        let previous_nonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
        let _account_req = enrollment.new_account_request(previous_nonce.to_string())?;

        let account_resp = json!({
            "status": "valid",
            "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
        });
        let account_resp = serde_json::to_vec(&account_resp)?;
        enrollment.new_account_response(account_resp)?;

        let (enrollment, cc) = restore(enrollment, cc).await;

        let _order_req = enrollment.new_order_request(previous_nonce.to_string())?;

        let order_resp = json!({
            "status": "pending",
            "expires": "2037-01-05T14:09:07.99Z",
            "notBefore": "2016-01-01T00:00:00Z",
            "notAfter": "2037-01-08T00:00:00Z",
            "identifiers": [
                {
                  "type": "wireapp-id",
                  "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
                }
            ],
            "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis",
            ],
            "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
        });
        let order_resp = serde_json::to_vec(&order_resp)?;
        let new_order = enrollment.new_order_response(order_resp)?;

        let (mut enrollment, cc) = restore(enrollment, cc).await;

        let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";

        let authz_url = new_order
            .authorizations
            .get(0)
            .ok_or(E2eIdentityError::ImplementationError)?;
        let _authz_req = enrollment.new_authz_request(authz_url.to_string(), previous_nonce.to_string())?;

        let authz_resp = json!({
            "status": "pending",
            "expires": "2016-01-02T14:09:30Z",
            "identifier": {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            },
            "challenges": [
              {
                "type": "wire-oidc-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://dex/dex"
              },
              {
                "type": "wire-dpop-01",
                "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                "status": "pending",
                "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY",
                "target": "https://wire.com/clients/6c1866f567616f31/access-token"
              }
            ]
        });
        let authz_resp = serde_json::to_vec(&authz_resp)?;
        enrollment.new_authz_response(authz_resp)?;

        let (enrollment, cc) = restore(enrollment, cc).await;

        let backend_nonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
        let _dpop_token = enrollment.create_dpop_token(3600, backend_nonce.to_string())?;

        let access_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA".to_string();
        let _dpop_chall_req = enrollment.new_dpop_challenge_request(access_token, previous_nonce.to_string())?;
        let dpop_chall_resp = json!({
            "type": "wire-dpop-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "status": "valid",
            "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
        });
        let dpop_chall_resp = serde_json::to_vec(&dpop_chall_resp)?;
        enrollment.new_challenge_response(dpop_chall_resp)?;

        let (enrollment, cc) = restore(enrollment, cc).await;

        let id_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ".to_string();
        let _oidc_chall_req = enrollment.new_oidc_challenge_request(id_token, previous_nonce.to_string())?;
        let oidc_chall_resp = json!({
            "type": "wire-oidc-01",
            "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
            "status": "valid",
            "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
        });
        let oidc_chall_resp = serde_json::to_vec(&oidc_chall_resp)?;
        enrollment.new_challenge_response(oidc_chall_resp)?;

        let (mut enrollment, cc) = restore(enrollment, cc).await;

        let _get_order_req = enrollment.check_order_request(order_url.to_string(), previous_nonce.to_string())?;

        let order_resp = json!({
          "status": "ready",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        });
        let order_resp = serde_json::to_vec(&order_resp)?;
        enrollment.check_order_response(order_resp)?;

        let (mut enrollment, cc) = restore(enrollment, cc).await;

        let _finalize_req = enrollment.finalize_request(previous_nonce.to_string())?;
        let finalize_resp = json!({
          "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
          "status": "valid",
          "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
          "identifiers": [
            {
              "type": "wireapp-id",
              "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
            }
          ],
          "authorizations": [
            "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
          ],
          "expires": "2032-02-10T14:59:20Z",
          "notBefore": "2013-02-09T14:59:20.442908Z",
          "notAfter": "2032-02-09T15:59:20.442908Z"
        });
        let finalize_resp = serde_json::to_vec(&finalize_resp)?;
        enrollment.finalize_response(finalize_resp)?;

        let (mut enrollment, mut cc) = restore(enrollment, cc).await;

        let _certificate_req = enrollment.certificate_request(previous_nonce.to_string())?;

        let certificate_resp = r#"-----BEGIN CERTIFICATE-----
MIICLjCCAdSgAwIBAgIQIi6jHWSEF/LHAkiyoiSHbjAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzA0MDUwOTI2NThaFw0yMzA0MDUxMDI2NThaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGzbFXHk2ngUGpBYzabE
AtDJIefbX1/wDUSDJbEL/nJNo4IBBjCCAQIwDgYDVR0PAQH/BAQDAgeAMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUhifYTPG7M3pyQMrz
HYmakvfDG80wHwYDVR0jBBgwFoAUHPSH1n7X87LAYJnc+cFG2a3ZAQ4wcgYDVR0R
BGswaYZQaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRB
Mk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb22GFWltOndpcmVh
cHA9YWxpY2Vfd2lyZTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYI
KoZIzj0EAwIDSAAwRQIhAKY0Zs8SYwS7mFFenPDoCDHPQbCbV9VdvYpBQncOFD5K
AiAisX68Di4B0dN059YsVDXpM0drnkrVTRKHV+F+ipDjZQ==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBtzCCAV6gAwIBAgIQPbElEJQ58HlbQf7bqrJjXTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNDA1MDky
NjUzWhcNMzMwNDAyMDkyNjUzWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbM
rA1eqJE9xlGOwO+sYbexThtlU/to9jJj5SBoKPx7Q8QMBlmPTjqDVumXhUvSe+xY
JE7M+lBXfVZCywzIIPWjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQc9IfWftfzssBgmdz5wUbZrdkBDjAfBgNVHSMEGDAW
gBQY+1rDw64QLm/weFQC1mo9y29ddTAKBggqhkjOPQQDAgNHADBEAiARvd7RBuuv
OhUy7ncjd/nzoN5Qs0p6D+ujdSLDqLlNIAIgfkwAAgsQMDF3ClqVM/p9cmS95B0g
CAdIObqPoNL5MJo=
-----END CERTIFICATE-----"#;
        cc.e2ei_mls_init(enrollment, certificate_resp.to_string()).await
    }
}
