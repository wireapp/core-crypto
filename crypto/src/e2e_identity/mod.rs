use crate::{prelude::MlsCentral, prelude::MlsCiphersuite};
use error::*;
use mls_crypto_provider::MlsCryptoProvider;
use wire_e2e_identity::prelude::RustyE2eIdentity;

mod crypto;
pub mod error;
pub mod types;

type Json = Vec<u8>;

impl MlsCentral {
    /// Creates an enrollment instance with private key material you can use in order to fetch
    /// a new x509 certificate from the acme server.
    /// Make sure to call [WireE2eIdentity::free] (not yet available) to dispose this instance and its associated
    /// keying material.
    pub fn new_acme_enrollment(&self, ciphersuite: MlsCiphersuite) -> E2eIdentityResult<WireE2eIdentity> {
        WireE2eIdentity::try_new(&self.mls_backend, ciphersuite)
    }
}

/// Wire end to end identity solution for fetching a x509 certificate which identifies a client.
///
/// Here are the steps to follow to implement it:
#[derive(Debug)]
pub struct WireE2eIdentity(RustyE2eIdentity);

impl WireE2eIdentity {
    /// Builds an instance holding private key material. This instance has to be used in the whole
    /// enrollment process then dropped to clear secret key material.
    ///
    /// # Parameters
    /// * `sign_alg` - Signature algorithm (only Ed25519 for now)
    /// * `raw_sign_kp` - Signature keypair in PEM format
    pub fn try_new(backend: &MlsCryptoProvider, ciphersuite: MlsCiphersuite) -> E2eIdentityResult<Self> {
        let alg = ciphersuite.try_into()?;
        let sign_kp = Self::new_sign_keypair(ciphersuite, backend)?;
        Ok(Self(RustyE2eIdentity::try_new(alg, sign_kp)?))
    }

    /// Parses the response from `GET /acme/{provisioner-name}/directory`.
    /// Use this [AcmeDirectory] in the next step to fetch the first nonce from the acme server. Use
    /// [AcmeDirectory::new_nonce].
    ///
    /// See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
    ///
    /// # Parameters
    /// * `directory` - http response body
    pub fn directory_response(&self, directory: Json) -> E2eIdentityResult<types::E2eiAcmeDirectory> {
        let directory = serde_json::from_slice(&directory[..])?;
        Ok(self.0.acme_directory_response(directory)?.into())
    }

    /// For creating a new acme account. This returns a signed JWS-alike request body to send to
    /// `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `directory` - you got from [Self::acme_directory_response]
    /// * `previous_nonce` - you got from calling `HEAD {directory.new_nonce}`
    pub fn new_account_request(
        &self,
        directory: types::E2eiAcmeDirectory,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = self
            .0
            .acme_new_account_request(&directory.try_into()?, previous_nonce)?;
        let account = serde_json::to_vec(&account)?;
        Ok(account)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/new-account`.
    ///
    /// See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
    ///
    /// # Parameters
    /// * `account` - http response body
    pub fn new_account_response(&self, account: Json) -> E2eIdentityResult<types::E2eiAcmeAccount> {
        let account = serde_json::from_slice(&account[..])?;
        self.0.acme_new_account_response(account)?.try_into()
    }

    /// Creates a new acme order for the handle (userId + display name) and the clientId.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `handle_host` - domain of the authorization server e.g. `idp.example.org`
    /// * `client_id_host` - domain of the wire-server e.g. `wire.example.org`
    /// * `expiry` - generated x509 certificate expiry
    /// * `directory` - you got from [Self::acme_directory_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/new-account`
    pub fn new_order_request(
        &self,
        handle: String,
        client_id: String,
        expiry_days: u32,
        directory: types::E2eiAcmeDirectory,
        account: types::E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let expiry = core::time::Duration::from_secs(u64::from(expiry_days) * 3600 * 24);
        let order = self.0.acme_new_order_request(
            handle,
            client_id,
            expiry,
            &directory.try_into()?,
            &account.try_into()?,
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
        self.0.acme_new_order_response(order)?.try_into()
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
    pub fn new_authz_request(
        &self,
        url: String,
        account: types::E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let authz = self
            .0
            .acme_new_authz_request(&url.parse()?, &account.try_into()?, previous_nonce)?;
        let authz = serde_json::to_vec(&authz)?;
        Ok(authz)
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
    pub fn new_authz_response(&self, authz: Json) -> E2eIdentityResult<types::E2eiNewAcmeAuthz> {
        let authz = serde_json::from_slice(&authz[..])?;
        self.0.acme_new_authz_response(authz)?.try_into()
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
    pub fn create_dpop_token(
        &self,
        access_token_url: String,
        user_id: String,
        client_id: u64,
        domain: String,
        client_id_challenge: types::E2eiAcmeChallenge,
        backend_nonce: String,
        expiry_days: u32,
    ) -> E2eIdentityResult<String> {
        let expiry = core::time::Duration::from_secs(u64::from(expiry_days) * 3600 * 24);
        Ok(self.0.new_dpop_token(
            &access_token_url.parse()?,
            user_id,
            client_id,
            domain,
            &client_id_challenge.try_into()?,
            backend_nonce,
            expiry,
        )?)
    }

    /// Creates a new challenge request.
    ///
    /// See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
    ///
    /// # Parameters
    /// * `handle_challenge` - you found after [Self::acme_new_authz_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
    pub fn new_challenge_request(
        &self,
        handle_chall: types::E2eiAcmeChallenge,
        account: types::E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let challenge =
            self.0
                .acme_new_challenge_request(&handle_chall.try_into()?, &account.try_into()?, previous_nonce)?;
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
        Ok(self.0.acme_new_challenge_response(challenge)?)
    }

    /// Verifies that the previous challenge has been completed.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order_url` - `location` header from http response you got from [Self::acme_new_order_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
    pub fn check_order_request(
        &self,
        order_url: String,
        account: types::E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let order = self
            .0
            .acme_check_order_request(order_url.parse()?, &account.try_into()?, previous_nonce)?;
        let order = serde_json::to_vec(&order)?;
        Ok(order)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `order` - http response body
    pub fn check_order_response(&self, order: Json) -> E2eIdentityResult<types::E2eiAcmeOrder> {
        let order = serde_json::from_slice(&order[..])?;
        self.0.acme_check_order_response(order)?.try_into()
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
    pub fn finalize_request(
        &self,
        domains: Vec<String>,
        order: types::E2eiAcmeOrder,
        account: types::E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let finalize =
            self.0
                .acme_finalize_request(domains, order.try_into()?, &account.try_into()?, previous_nonce)?;
        let finalize = serde_json::to_vec(&finalize)?;
        Ok(finalize)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
    ///
    /// See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
    ///
    /// # Parameters
    /// * `finalize` - http response body
    pub fn finalize_response(&self, finalize: Json) -> E2eIdentityResult<types::E2eiAcmeFinalize> {
        let finalize = serde_json::from_slice(&finalize[..])?;
        self.0.acme_finalize_response(finalize)?.try_into()
    }

    /// Creates a request for finally fetching the x509 certificate.
    ///
    /// See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2).
    ///
    /// # Parameters
    /// * `finalize` - you got from [Self::finalize_response]
    /// * `account` - you got from [Self::acme_new_account_response]
    /// * `previous_nonce` - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}/finalize`
    pub fn certificate_request(
        &self,
        finalize: types::E2eiAcmeFinalize,
        account: types::E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let certificate =
            self.0
                .acme_x509_certificate_request(finalize.try_into()?, account.try_into()?, previous_nonce)?;
        let certificate = serde_json::to_vec(&certificate)?;
        Ok(certificate)
    }

    /// Parses the response from `POST /acme/{provisioner-name}/certificate/{certificate-id}`.
    ///
    /// See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2)
    ///
    /// # Parameters
    /// * `response` - http string response body
    pub fn certificate_response(&self, certificate_chain: String) -> E2eIdentityResult<Vec<String>> {
        Ok(self.0.acme_x509_certificate_response(certificate_chain)?)
    }

    // TODO: expose this across the FFI
    /// Drops this instance and all its associated private key material
    pub fn free(self) {
        drop(self)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::test_utils::*;
    use openmls::prelude::SignatureScheme;
    use serde_json::json;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn e2e_identity_should_work(case: TestCase) {
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
            run_test_with_client_ids(case.clone(), ["alice"], move |[cc]| {
                Box::pin(async move {
                    let enrollment = cc.new_acme_enrollment(case.ciphersuite()).unwrap();
                    let directory = json!({
                        "newNonce": "https://example.com/acme/new-nonce",
                        "newAccount": "https://example.com/acme/new-account",
                        "newOrder": "https://example.com/acme/new-order"
                    });
                    let directory = serde_json::to_vec(&directory).unwrap();
                    let directory = enrollment.directory_response(directory).unwrap();

                    let previous_nonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
                    let _account_req = enrollment
                        .new_account_request(directory.clone(), previous_nonce.to_string())
                        .unwrap();

                    let account_resp = json!({
                        "status": "valid",
                        "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
                    });
                    let account_resp = serde_json::to_vec(&account_resp).unwrap();
                    let account = enrollment.new_account_response(account_resp).unwrap();

                    let _order_req = enrollment
                        .new_order_request(
                            "idp.example.org".to_string(),
                            "wire.example.org".to_string(),
                            90,
                            directory,
                            account.clone(),
                            previous_nonce.to_string(),
                        )
                        .unwrap();

                    let order_resp = json!({
                        "status": "pending",
                        "expires": "2037-01-05T14:09:07.99Z",
                        "notBefore": "2016-01-01T00:00:00Z",
                        "notAfter": "2037-01-08T00:00:00Z",
                        "identifiers": [
                            { "type": "dns", "value": "www.example.org" },
                            { "type": "dns", "value": "example.org" }
                        ],
                        "authorizations": [
                            "https://example.com/acme/authz/PAniVnsZcis",
                            "https://example.com/acme/authz/r4HqLzrSrpI"
                        ],
                        "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
                    });
                    let order_resp = serde_json::to_vec(&order_resp).unwrap();
                    let new_order = enrollment.new_order_response(order_resp).unwrap();
                    let order_url = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";

                    let authz1_url = new_order.authorizations.get(0).unwrap();
                    let _authz1_req = enrollment
                        .new_authz_request(authz1_url.to_string(), account.clone(), previous_nonce.to_string())
                        .unwrap();

                    let authz1_resp = json!({
                        "status": "pending",
                        "expires": "2016-01-02T14:09:30Z",
                        "identifier": {
                          "type": "dns",
                          "value": "wire.example.org"
                        },
                        "challenges": [
                          {
                            "type": "wire-http-01",
                            "url": "https://example.com/acme/chall/prV_B7yEyA4",
                            "token": "DGyRejmCefe7v4NfDGDKfA"
                          }
                        ]
                    });
                    let authz1_resp = serde_json::to_vec(&authz1_resp).unwrap();
                    let authz1 = enrollment.new_authz_response(authz1_resp).unwrap();

                    let authz2_url = new_order.authorizations.get(1).unwrap();
                    let _authz2_req = enrollment
                        .new_authz_request(authz2_url.to_string(), account.clone(), previous_nonce.to_string())
                        .unwrap();

                    let authz2_resp = json!({
                        "status": "pending",
                        "expires": "2016-01-02T14:09:30Z",
                        "identifier": {
                          "type": "dns",
                          "value": "idp.example.org"
                        },
                        "challenges": [
                          {
                            "type": "wire-oidc-01",
                            "url": "https://example.com/acme/chall/prV_B7yEyA4",
                            "token": "DGyRejmCefe7v4NfDGDKfA"
                          }
                        ]
                    });
                    let authz2_resp = serde_json::to_vec(&authz2_resp).unwrap();
                    let authz2 = enrollment.new_authz_response(authz2_resp).unwrap();

                    let (client_id_chall, handle_chall) = {
                        match (authz1.identifier.as_str(), authz2.identifier.as_str()) {
                            (client_id, handle) if (client_id, handle) == ("wire.example.org", "idp.example.org") => {
                                (authz1.wire_http_challenge.unwrap(), authz2.wire_oidc_challenge.unwrap())
                            }
                            (handle, client_id) if (client_id, handle) == ("wire.example.org", "idp.example.org") => {
                                (authz1.wire_oidc_challenge.unwrap(), authz2.wire_http_challenge.unwrap())
                            }
                            _ => panic!(""),
                        }
                    };

                    let backend_nonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";

                    let user_id = uuid::Uuid::new_v4().to_string();
                    let client_id = 42;
                    let domain = "example.org";
                    let dpop_url = format!("https://example.org/clients/{client_id}/access-token");

                    let _dpop_token = enrollment
                        .create_dpop_token(
                            dpop_url,
                            user_id,
                            client_id,
                            domain.to_string(),
                            client_id_chall,
                            backend_nonce.to_string(),
                            90,
                        )
                        .unwrap();

                    let _handle_chall_req = enrollment
                        .new_challenge_request(handle_chall, account.clone(), previous_nonce.to_string())
                        .unwrap();

                    let chall_resp = json!({
                        "type": "wire-oidc-01",
                        "url": "https://example.com/acme/chall/prV_B7yEyA4",
                        "status": "valid",
                        "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
                    });
                    let chall_resp = serde_json::to_vec(&chall_resp).unwrap();
                    enrollment.new_challenge_response(chall_resp).unwrap();

                    let _get_order_req = enrollment
                        .check_order_request(order_url.to_string(), account.clone(), previous_nonce.to_string())
                        .unwrap();

                    let order_resp = json!({
                        "status": "ready",
                        "expires": "2037-01-05T14:09:07.99Z",
                        "notBefore": "2016-01-01T00:00:00Z",
                        "notAfter": "2037-01-08T00:00:00Z",
                        "identifiers": [
                            { "type": "dns", "value": "www.example.org" },
                            { "type": "dns", "value": "example.org" }
                        ],
                        "authorizations": [
                            "https://example.com/acme/authz/PAniVnsZcis",
                            "https://example.com/acme/authz/r4HqLzrSrpI"
                        ],
                        "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
                    });
                    let order_resp = serde_json::to_vec(&order_resp).unwrap();
                    let order = enrollment.check_order_response(order_resp).unwrap();

                    let domains = vec!["idp.example.org".to_string(), "wire.example.org".to_string()];
                    let _finalize_req = enrollment
                        .finalize_request(domains, order, account.clone(), previous_nonce.to_string())
                        .unwrap();
                    let finalize_resp = json!({
                        "status": "valid",
                        "expires": "2016-01-20T14:09:07.99Z",
                        "notBefore": "2016-01-01T00:00:00Z",
                        "notAfter": "2016-01-08T00:00:00Z",
                        "identifiers": [
                            { "type": "dns", "value": "www.example.org" },
                            { "type": "dns", "value": "example.org" }
                        ],
                        "authorizations": [
                            "https://example.com/acme/authz/PAniVnsZcis",
                            "https://example.com/acme/authz/r4HqLzrSrpI"
                        ],
                        "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
                        "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
                    });
                    let finalize_resp = serde_json::to_vec(&finalize_resp).unwrap();
                    let finalize = enrollment.finalize_response(finalize_resp).unwrap();

                    let _certificate_req = enrollment
                        .certificate_request(finalize, account, previous_nonce.to_string())
                        .unwrap();

                    let certificate_resp = r#"-----BEGIN CERTIFICATE-----
MIIB7DCCAZKgAwIBAgIRAIErw6bhWUQXxeS0xsdMvyEwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwMTA1MjAwMDQxWhcNMjMwMTA2MjAwMTQxWjAAMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEq9rybsGxEBLpn6Tx5LHladF6jw3Vuc5Yr27NKRLwFWbCUXUmwApv
arn35O3u+w1CnwTyCA2tt605GhvbL039AKOBvjCBuzAOBgNVHQ8BAf8EBAMCB4Aw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBTlxc6/odBa
eTAlHYZcoCeFyn0BCjAfBgNVHSMEGDAWgBRsNCwlQHq5dXTxxfhhKHYOFQtlXzAm
BgNVHREBAf8EHDAagg5sb2dpbi53aXJlLmNvbYIId2lyZS5jb20wIgYMKwYBBAGC
pGTGKEABBBIwEAIBBgQJd2lyZS1hY21lBAAwCgYIKoZIzj0EAwIDSAAwRQIgAwhX
Jvnc7hOUOT41I35ZZi5rgJKF4FtMyImvCFY1UQ0CIQC2k+k7uqwgMRp10z3xzWHE
3sMuOBJG/UAR+VtFvCmGSA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAOzPGCzghRSFfL08VAXS/DQwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDEwNTIw
MDEzOFoXDTMzMDEwMjIwMDEzOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARc
LwmNj175LF1Wd+CC7lVGVUzr/ys+mR7XbN0csRx3okfJKZFxx0PGs6JO+pTUG0C3
27GSfNQU+2tz5fnrmahxo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUbDQsJUB6uXV08cX4YSh2DhULZV8wHwYDVR0jBBgw
FoAUuL+rLbn8HEXbB6Pw5wzGhGjlE24wCgYIKoZIzj0EAwIDSAAwRQIgEltwd9QL
LdKVfvqnrQ/H3a4uIPgJz0+YQI1Y0eYuMB4CIQCYMrIYAqC7nqjqVXrROShrISO+
S26guHAMqXDlqqueOQ==
-----END CERTIFICATE-----"#;
                    enrollment.certificate_response(certificate_resp.to_string()).unwrap();
                    enrollment.free();
                })
            })
            .await
        }
    }
}
