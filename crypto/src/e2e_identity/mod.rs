use openmls::prelude::SignaturePrivateKey;
use wire_e2e_identity::prelude::RustyE2eIdentity;

use error::*;
use mls_crypto_provider::MlsCryptoProvider;

use crate::prelude::{CertificateBundle, ClientId, MlsCentral, MlsCiphersuite};

mod crypto;
pub mod error;
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
    pub fn new_acme_enrollment(
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
#[derive(Debug)]
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
    #[allow(clippy::too_many_arguments)]
    pub fn new_order_request(&mut self, previous_nonce: String) -> E2eIdentityResult<Json> {
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
    /// * `access_token_url` - backend endpoint where this token will be sent. Should be [this one](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    /// * `backend_nonce` - you get by calling `GET /clients/token/nonce` on wire-server.
    /// See endpoint [definition](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce)
    /// * `expiry` - token expiry
    #[allow(clippy::too_many_arguments)]
    pub fn create_dpop_token(&self, access_token_url: String, backend_nonce: String) -> E2eIdentityResult<String> {
        let authz = self.authz.as_ref().ok_or(E2eIdentityError::ImplementationError)?;
        let dpop_challenge = authz
            .wire_dpop_challenge
            .as_ref()
            .ok_or(E2eIdentityError::ImplementationError)?;
        Ok(self.new_dpop_token(
            &access_token_url.parse()?,
            &self.client_id,
            dpop_challenge,
            backend_nonce,
            self.expiry,
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
    pub fn check_order_response(&mut self, order: Json) -> E2eIdentityResult<()> {
        let order = serde_json::from_slice(&order[..])?;
        let valid_order = self.acme_check_order_response(order)?;
        self.valid_order = Some(valid_order);
        Ok(())
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
    pub fn finalize_response(&mut self, finalize: Json) -> E2eIdentityResult<()> {
        let finalize = serde_json::from_slice(&finalize[..])?;
        let finalize = self.acme_finalize_response(finalize)?;
        self.finalize = Some(finalize);
        Ok(())
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
        let private_key = SignaturePrivateKey {
            value: self.sign_sk,
            signature_scheme: self.ciphersuite.signature_algorithm(),
        };
        let cb = CertificateBundle {
            certificate_chain,
            private_key,
        };
        let client_id = ClientId::from(self.client_id.as_bytes());
        mls_central
            .mls_init(client_id, vec![self.ciphersuite], Some(cb))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use openmls::prelude::SignatureScheme;
    use serde_json::json;
    use wasm_bindgen_test::*;

    use crate::prelude::ClientId;
    use crate::test_utils::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    // #[async_std::test]
    pub async fn e2e_identity_should_work(case: TestCase) {
        /*let case = TestCase::new(
            crate::mls::credential::CertificateBundle::rand_basic(),
            openmls::prelude::Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        );*/
        #[cfg(not(target_family = "wasm"))]
        let supported_alg = [
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_SECP256R1_SHA256,
            SignatureScheme::ECDSA_SECP384R1_SHA384,
        ];
        // EC signature are not supported because not supported by ring on WASM
        #[cfg(target_family = "wasm")]
        let supported_alg = [SignatureScheme::ED25519];

        if supported_alg.contains(&case.signature_scheme()) {
            run_test_wo_clients(case.clone(), move |mut cc| {
                Box::pin(async move {
                    let display_name = "Smith, Alice M (QA)".to_string();
                    let domain = "example.com";
                    let client_id: ClientId =
                        format!("NDEyZGYwNjc2MzFkNDBiNTllYmVmMjQyZTIzNTc4NWQ:65c3ac1a1631c136@{domain}").as_str().into();
                    let handle = format!("alice.smith.qa@{domain}");
                    let expiry = 90;

                    let mut enrollment = cc.new_acme_enrollment(client_id, display_name, handle, expiry, case.ciphersuite()).unwrap();
                    let directory = json!({
                        "newNonce": "https://example.com/acme/new-nonce",
                        "newAccount": "https://example.com/acme/new-account",
                        "newOrder": "https://example.com/acme/new-order"
                    });
                    let directory = serde_json::to_vec(&directory).unwrap();
                    enrollment.directory_response(directory).unwrap();

                    let previous_nonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
                    let _account_req = enrollment
                        .new_account_request( previous_nonce.to_string())
                        .unwrap();

                    let account_resp = json!({
                        "status": "valid",
                        "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
                    });
                    let account_resp = serde_json::to_vec(&account_resp).unwrap();
                    enrollment.new_account_response(account_resp).unwrap();

                    let _order_req = enrollment.new_order_request(previous_nonce.to_string()).unwrap();

                    let order_resp = json!({
                        "status": "pending",
                        "expires": "2037-01-05T14:09:07.99Z",
                        "notBefore": "2016-01-01T00:00:00Z",
                        "notAfter": "2037-01-08T00:00:00Z",
                        "identifiers": [
                            {
                              "type": "wireapp-id",
                              "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
                            }
                        ],
                        "authorizations": [
                            "https://example.com/acme/authz/PAniVnsZcis",
                        ],
                        "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
                    });
                    let order_resp = serde_json::to_vec(&order_resp).unwrap();
                    let new_order = enrollment.new_order_response(order_resp).unwrap();
                    let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";

                    let authz_url = new_order.authorizations.get(0).unwrap();
                    let _authz_req = enrollment
                        .new_authz_request(authz_url.to_string(), previous_nonce.to_string())
                        .unwrap();

                    let authz_resp = json!({
                        "status": "pending",
                        "expires": "2016-01-02T14:09:30Z",
                        "identifier": {
                          "type": "wireapp-id",
                          "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
                        },
                        "challenges": [
                          {
                            "type": "wire-oidc-01",
                            "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
                            "status": "pending",
                            "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY"
                          },
                          {
                            "type": "wire-dpop-01",
                            "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
                            "status": "pending",
                            "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY"
                          }
                        ]
                    });
                    let authz_resp = serde_json::to_vec(&authz_resp).unwrap();
                     enrollment.new_authz_response(authz_resp).unwrap();

                    let backend_nonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
                    let dpop_url = "https://example.org/clients/42/access-token".to_string();

                    let _dpop_token = enrollment.create_dpop_token(dpop_url, backend_nonce.to_string()).unwrap();

                    let access_token = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlldjZPWlVudWlwbmZrMHRWZFlLRnM5MWpSdjVoVmF6a2llTEhBTmN1UEUifX0.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY4MzczNzc1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsImp0aSI6Ijk4NGM1OTA0LWZhM2UtNDVhZi1iZGM1LTlhODMzNjkxOGUyYiIsIm5vbmNlIjoiYjNWSU9YTk9aVE4xVUV0b2FXSk9VM1owZFVWdWJFMDNZV1ZIUVdOb2NFMCIsImNoYWwiOiJTWTc0dEptQUlJaGR6UnRKdnB4Mzg5ZjZFS0hiWHV4USIsImNuZiI6eyJraWQiOiJocG9RV2xNUmtjUURKN2xNcDhaSHp4WVBNVDBJM0Vhc2VqUHZhWmlGUGpjIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVVGM1QxVmZTMXBpYUV0SFIxUjRaMGQ0WTJsa1VVZHFiMUpXWkdOdFlWQmpSblI0VG5Gd1gydzJTU0o5ZlEuZXlKcFlYUWlPakUyTnpVNU5qRTNOVFlzSW1WNGNDSTZNVFkzTmpBME9ERTFOaXdpYm1KbUlqb3hOamMxT1RZeE56VTJMQ0p6ZFdJaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aWFuUnBJam9pTlRBM09HWmtaVEl0TlRCaU9DMDBabVZtTFdJeE5EQXRNekJrWVRrellqQmtZems1SWl3aWJtOXVZMlVpT2lKaU0xWkpUMWhPVDFwVVRqRlZSWFJ2WVZkS1QxVXpXakJrVlZaMVlrVXdNMWxYVmtoUlYwNXZZMFV3SWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk5Ua3pNRGN2SWl3aVkyaGhiQ0k2SWxOWk56UjBTbTFCU1Vsb1pIcFNkRXAyY0hnek9EbG1Oa1ZMU0dKWWRYaFJJbjAuQk1MS1Y1OG43c1dITXkxMlUtTHlMc0ZJSkd0TVNKcXVoUkZvYnV6ZTlGNEpBN1NjdlFWSEdUTFF2ZVZfUXBfUTROZThyeU9GcEphUTc1VW5ORHR1RFEiLCJjbGllbnRfaWQiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Tf10dkKrNikGNgGhIdkrMHb0v6Jpde09MaIyBeuY6KORcxuglMGY7_V9Kd0LcVVPMDy1q4xbd39ZqosGz1NUBQ".to_string();
                    let _dpop_chall_req = enrollment
                        .new_dpop_challenge_request(access_token, previous_nonce.to_string())
                        .unwrap();
                    let dpop_chall_resp = json!({
                        "type": "wire-dpop-01",
                        "url": "https://example.com/acme/chall/prV_B7yEyA4",
                        "status": "valid",
                        "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
                    });
                    let dpop_chall_resp = serde_json::to_vec(&dpop_chall_resp).unwrap();
                    enrollment.new_challenge_response(dpop_chall_resp).unwrap();

                    let id_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ".to_string();
                    let _oidc_chall_req = enrollment
                        .new_oidc_challenge_request(id_token, previous_nonce.to_string())
                        .unwrap();
                    let oidc_chall_resp = json!({
                        "type": "wire-oidc-01",
                        "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
                        "status": "valid",
                        "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
                    });
                    let oidc_chall_resp = serde_json::to_vec(&oidc_chall_resp).unwrap();
                    enrollment.new_challenge_response(oidc_chall_resp).unwrap();

                    let _get_order_req = enrollment
                        .check_order_request(order_url.to_string(), previous_nonce.to_string())
                        .unwrap();

                    let order_resp = json!({
                      "status": "ready",
                      "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
                      "identifiers": [
                        {
                          "type": "wireapp-id",
                          "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
                        }
                      ],
                      "authorizations": [
                        "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
                      ],
                      "expires": "2032-02-10T14:59:20Z",
                      "notBefore": "2013-02-09T14:59:20.442908Z",
                      "notAfter": "2032-02-09T15:59:20.442908Z"
                    });
                    let order_resp = serde_json::to_vec(&order_resp).unwrap();
                    enrollment.check_order_response(order_resp).unwrap();

                    let _finalize_req = enrollment
                        .finalize_request( previous_nonce.to_string())
                        .unwrap();
                    let finalize_resp = json!({
                      "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
                      "status": "valid",
                      "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
                      "identifiers": [
                        {
                          "type": "wireapp-id",
                          "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
                        }
                      ],
                      "authorizations": [
                        "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
                      ],
                      "expires": "2032-02-10T14:59:20Z",
                      "notBefore": "2013-02-09T14:59:20.442908Z",
                      "notAfter": "2032-02-09T15:59:20.442908Z"
                    });
                    let finalize_resp = serde_json::to_vec(&finalize_resp).unwrap();
                     enrollment.finalize_response(finalize_resp).unwrap();

                    let _certificate_req = enrollment
                        .certificate_request( previous_nonce.to_string())
                        .unwrap();

                    let certificate_resp = r#"-----BEGIN CERTIFICATE-----
MIICaDCCAg6gAwIBAgIQH3CanUzXJpP+pbXNUVpp7TAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzAyMDkxNDU5MjBaFw0yMzAyMDkxNTU5MjBaMDQxFDASBgNVBAoTC2V4YW1wbGUu
Y29tMRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAVCw/
lxGMV2Zx723yhVv94Fb+LCARV0h1F1/zmvRZGy6jggE1MIIBMTAOBgNVHQ8BAf8E
BAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSr
zp+ejXBydYcjmBr4cTp931ceUTAfBgNVHSMEGDAWgBS04sLODR52O3cPNlNdK3f6
tinkIzCBoAYDVR0RBIGYMIGVghNzbWl0aCwgYWxpY2UgbSAocWEphidpbXBwOndp
cmVhcHA9YWxpY2Uuc21pdGgucWFAZXhhbXBsZS5jb22GVWltcHA6d2lyZWFwcD1u
amppeXRyam10aXlvZGpqbmR5NXltZTVuZ3ptbWpoaG5qZmtvZGEwbmprL2QyYmEy
YzFhNTc1ODhlZTRAZXhhbXBsZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQE
YWNtZQQAMAoGCCqGSM49BAMCA0gAMEUCIG6cfFB2En9YKVPuQhEZcoELtZbkFsTJ
PeWa6zTkrI47AiEApQP8piMQWhofGLL6oTWoks3+6JfPRWZP9Z7JkhdiBmY=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQP5i/9/vpRPXels/aSa5lZTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMjA5MTQ1
OTE4WhcNMzMwMjA2MTQ1OTE4WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFNd
5wbJjtVSmXxftBSmHgTJS3F1LGMlb789KtcSTjjJVO//VNdg3XDYvhHyitHx/Bz+
5yxkrPaRzeGeJkZfkuejZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBS04sLODR52O3cPNlNdK3f6tinkIzAfBgNVHSMEGDAW
gBTqNi9/bemraZjLYA8TGat3ianEizAKBggqhkjOPQQDAgNIADBFAiEAuo8JLvys
IvUCvPUJi1++80IgPeRxxRvn5zlHDh3qKZECIHONc1xx1ixlIyp9mOtdeTvG5Dql
RheWYpDHRiLax1Id
-----END CERTIFICATE-----"#;
                    cc.e2ei_mls_init(enrollment, certificate_resp.to_string()).await.unwrap();
                })
            })
            .await
        }
    }
}
