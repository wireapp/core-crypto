use error::*;
use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, Ed25519KeyPair};
use prelude::*;
use rusty_acme::prelude::AcmeChall;
use rusty_jwt_tools::prelude::{ClientId, Dpop, Htm, Pem};
use rusty_jwt_tools::RustyJwtTools;

mod error;
mod sample;
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
}

impl RustyE2eIdentity {
    /// TODO
    pub fn try_new(sign_alg: JwsAlgorithm, raw_sign_kp: Vec<u8>) -> E2eIdentityResult<Self> {
        let sign_kp = match sign_alg {
            JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_bytes(raw_sign_kp.as_slice())?.to_pem(),
            JwsAlgorithm::P256 => ES256KeyPair::from_bytes(raw_sign_kp.as_slice())?.to_pem()?,
            JwsAlgorithm::P384 => ES384KeyPair::from_bytes(raw_sign_kp.as_slice())?.to_pem()?,
        }
        .into();
        Ok(Self { sign_alg, sign_kp })
    }

    /// TODO
    pub fn acme_directory_response(&self, directory: Json) -> E2eIdentityResult<AcmeDirectory> {
        let directory = RustyAcme::acme_directory_response(directory)?;
        Ok(directory)
    }

    /// TODO
    pub fn acme_new_account_request(
        &self,
        directory: &AcmeDirectory,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let acct_req = RustyAcme::new_account_request(directory, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(acct_req)?)
    }

    /// TODO
    pub fn acme_new_account_response(&self, account: Json) -> E2eIdentityResult<E2eiAcmeAccount> {
        let account = RustyAcme::new_account_response(account)?;
        Ok(serde_json::to_value(account)?.into())
    }

    /// TODO
    pub fn acme_new_order_request(
        &self,
        handle: String,
        client_id: String,
        expiry: core::time::Duration,
        directory: &AcmeDirectory,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = serde_json::from_value(account.clone().into())?;
        let order_req = RustyAcme::new_order_request(
            handle,
            client_id,
            expiry,
            directory,
            &account,
            self.sign_alg,
            &self.sign_kp,
            previous_nonce,
        )?;
        Ok(serde_json::to_value(order_req)?)
    }

    /// TODO
    pub fn acme_new_order_response(&self, new_order: Json) -> E2eIdentityResult<E2eiNewAcmeOrder> {
        let new_order = RustyAcme::new_order_response(new_order)?;
        let authorizations = new_order.authorizations.clone();
        let new_order = serde_json::to_vec(&new_order)?.into();
        Ok(E2eiNewAcmeOrder {
            new_order,
            authorizations,
        })
    }

    /// TODO
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

    /// TODO
    pub fn acme_new_authz_response(&self, new_authz: Json) -> E2eIdentityResult<E2eiNewAcmeAuthz> {
        let new_authz = serde_json::from_value(new_authz)?;
        let new_authz = RustyAcme::new_authz_response(new_authz)?;
        let identifier = new_authz.identifier.value().to_string();
        let wire_http_chall = new_authz
            .wire_http_challenge()
            .map(|c| serde_json::to_value(c).map(|chall| (chall, c.url.clone())))
            .transpose()?
            .map(|(chall, url)| E2eiAcmeChall { url, chall });
        let wire_oidc_chall = new_authz
            .wire_http_challenge()
            .map(|c| serde_json::to_value(c).map(|chall| (chall, c.url.clone())))
            .transpose()?
            .map(|(chall, url)| E2eiAcmeChall { url, chall });
        Ok(E2eiNewAcmeAuthz {
            identifier,
            wire_http_challenge: wire_http_chall,
            wire_oidc_challenge: wire_oidc_chall,
        })
    }

    /// Generates a new client Dpop JWT token
    ///
    /// # Parameters
    /// * `htu` - backend endpoint where this token will be sent. Should be [this one](https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token)
    #[allow(clippy::too_many_arguments)]
    pub fn new_dpop_token(
        &self,
        access_token_url: &url::Url,
        user_id: String,
        client_id: u64,
        domain: String,
        client_id_challenge: &E2eiAcmeChall,
        backend_nonce: String,
        expiry: core::time::Duration,
    ) -> E2eIdentityResult<String> {
        let client_id_challenge = serde_json::from_value::<AcmeChall>(client_id_challenge.chall.clone())?;
        let dpop = Dpop {
            htu: access_token_url.as_str().try_into()?,
            htm: Htm::Post,
            challenge: client_id_challenge.token.into(),
            extra_claims: None,
        };
        let client_id = ClientId::try_new(user_id, client_id, &domain)?;
        Ok(RustyJwtTools::generate_dpop_token(
            dpop,
            client_id,
            backend_nonce.into(),
            expiry,
            self.sign_alg,
            &self.sign_kp,
        )?)
    }

    /// TODO
    pub fn acme_new_challenge_request(
        &self,
        handle_chall: &E2eiAcmeChall,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let account = serde_json::from_value(account.clone().into())?;
        let handle_chall = serde_json::from_value(handle_chall.chall.clone())?;
        let new_challenge_req =
            RustyAcme::new_chall_request(handle_chall, &account, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(new_challenge_req)?)
    }

    /// TODO
    pub fn acme_new_challenge_response(&self, challenge: Json) -> E2eIdentityResult<()> {
        let challenge = serde_json::from_value(challenge)?;
        RustyAcme::new_chall_response(challenge)?;
        Ok(())
    }

    /// TODO
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

    /// TODO
    pub fn acme_check_order_response(&self, order: Json) -> E2eIdentityResult<E2eiAcmeOrder> {
        let order = RustyAcme::check_order_response(order)?;
        Ok(serde_json::to_value(order)?.into())
    }

    /// TODO
    pub fn acme_finalize_request(
        &self,
        domains: Vec<String>,
        order: E2eiAcmeOrder,
        account: &E2eiAcmeAccount,
        previous_nonce: String,
    ) -> E2eIdentityResult<Json> {
        let order = serde_json::from_value(order.into())?;
        let account = serde_json::from_value(account.clone().into())?;
        let finalize_req =
            RustyAcme::finalize_req(domains, order, &account, self.sign_alg, &self.sign_kp, previous_nonce)?;
        Ok(serde_json::to_value(finalize_req)?)
    }

    /// TODO
    pub fn acme_finalize_response(&self, finalize: Json) -> E2eIdentityResult<E2eiAcmeFinalize> {
        let finalize = RustyAcme::check_order_response(finalize)?;
        let certificate_url = finalize.finalize.clone();
        let finalize = serde_json::to_value(&finalize)?;
        Ok(E2eiAcmeFinalize {
            certificate_url,
            finalize,
        })
    }

    /// TODO
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

    // TODO
    pub fn acme_x509_certificate_response(&self, response: String) -> E2eIdentityResult<Vec<String>> {
        Ok(RustyAcme::certificate_response(response)?)
    }
}
