use crate::{prelude::MlsCentral, prelude::MlsCiphersuite};
use error::*;
use mls_crypto_provider::MlsCryptoProvider;
use wire_e2e_identity::prelude::RustyE2eIdentity;

mod crypto;
pub mod error;
pub mod types;

type Json = Vec<u8>;

impl MlsCentral {
    /// TODO
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
    /// TODO
    pub fn try_new(backend: &MlsCryptoProvider, ciphersuite: MlsCiphersuite) -> E2eIdentityResult<Self> {
        let alg = ciphersuite.try_into()?;
        let sign_kp = Self::new_sign_keypair(ciphersuite, backend)?;
        Ok(Self(RustyE2eIdentity::try_new(alg, sign_kp)?))
    }

    /// TODO
    pub fn directory_response(&self, directory: Json) -> E2eIdentityResult<types::E2eiAcmeDirectory> {
        let directory = serde_json::from_slice(&directory[..])?;
        Ok(self.0.acme_directory_response(directory)?.into())
    }

    /// TODO
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

    /// TODO
    pub fn new_account_response(&self, account: Json) -> E2eIdentityResult<types::E2eiAcmeAccount> {
        let account = serde_json::from_slice(&account[..])?;
        self.0.acme_new_account_response(account)?.try_into()
    }

    /// TODO
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

    /// TODO
    pub fn new_order_response(&self, order: Json) -> E2eIdentityResult<types::E2eiNewAcmeOrder> {
        let order = serde_json::from_slice(&order[..])?;
        self.0.acme_new_order_response(order)?.try_into()
    }

    /// TODO
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

    /// TODO
    pub fn new_authz_response(&self, authz: Json) -> E2eIdentityResult<types::E2eiNewAcmeAuthz> {
        let authz = serde_json::from_slice(&authz[..])?;
        self.0.acme_new_authz_response(authz)?.try_into()
    }

    /// TODO
    #[allow(clippy::too_many_arguments)]
    pub fn create_dpop_token(
        &self,
        access_token_url: String,
        user_id: String,
        client_id: u64,
        domain: String,
        client_id_challenge: types::E2eiAcmeChall,
        backend_nonce: String,
        expiry_seconds: u64,
    ) -> E2eIdentityResult<String> {
        let expiry = core::time::Duration::from_secs(expiry_seconds);
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

    /// TODO
    pub fn new_challenge_request(
        &self,
        handle_chall: types::E2eiAcmeChall,
        account: types::E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let challenge =
            self.0
                .acme_new_challenge_request(&handle_chall.try_into()?, &account.try_into()?, previous_nonce)?;
        let challenge = serde_json::to_vec(&challenge)?;
        Ok(challenge)
    }

    /// TODO
    pub fn new_challenge_response(&self, challenge: Json) -> E2eIdentityResult<()> {
        let challenge = serde_json::from_slice(&challenge[..])?;
        Ok(self.0.acme_new_challenge_response(challenge)?)
    }

    /// TODO
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

    /// TODO
    pub fn check_order_response(&self, order: Json) -> E2eIdentityResult<types::E2eiAcmeOrder> {
        let order = serde_json::from_slice(&order[..])?;
        self.0.acme_check_order_response(order)?.try_into()
    }

    /// TODO
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

    /// TODO
    pub fn finalize_response(&self, finalize: Json) -> E2eIdentityResult<types::E2eiAcmeFinalize> {
        let finalize = serde_json::from_slice(&finalize[..])?;
        self.0.acme_finalize_response(finalize)?.try_into()
    }

    /// TODO
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

    /// TODO
    pub fn certificate_response(&self, certificate_chain: String) -> E2eIdentityResult<Vec<String>> {
        Ok(self.0.acme_x509_certificate_response(certificate_chain)?)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::test_utils::*;
    use openmls::prelude::SignatureScheme;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn provided_sign_key_should_sign_account_request(case: TestCase) {
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
                    let directory = serde_json::json!({
                        "newNonce": "https://example.com/acme/new-nonce",
                        "newAccount": "https://example.com/acme/new-account",
                        "newOrder": "https://example.com/acme/new-order"
                    });
                    let directory = serde_json::to_vec(&directory).unwrap();
                    let directory = enrollment.directory_response(directory).unwrap();

                    let previous_nonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM".to_string();
                    let account_req = enrollment.new_account_request(directory, previous_nonce);
                    assert!(account_req.is_ok());
                })
            })
            .await
        }
    }
}
