use std::sync::Arc;

use jwt_simple::prelude::Jwk;
use rusty_jwt_tools::prelude::{ClientId, HashAlgorithm, JwsAlgorithm, Pem};
use url::Url;

use crate::{
    acme::AcmeJws,
    pki_env::{
        PkiEnvironment,
        hooks::{HttpHeader, HttpMethod, HttpResponse},
    },
};

mod checks;
mod dpop_challenge;
mod error;
mod initial;
mod oidc_challenge;

mod identity;
mod thumbprint;

#[derive(Debug)]
pub struct X509CredentialConfiguration {
    pub acme_url: String,
    pub idp_url: String,
    pub sign_alg: JwsAlgorithm,
    pub hash_alg: HashAlgorithm,
    pub display_name: String,
    pub client_id: ClientId,
    pub handle: String,
    pub domain: String,
    pub team: Option<String>,
    pub validity_period: std::time::Duration,
}

pub mod states {
    use crate::acme::{AcmeAccount, AcmeChallenge, AcmeOrder};

    #[derive(Debug)]
    pub struct Initialized;

    #[derive(Debug)]
    pub struct DpopChallengeCompleted {
        pub nonce: String,
        pub acme_account: AcmeAccount,
        pub order: AcmeOrder,
        pub oidc_challenge: AcmeChallenge,
    }
}

#[derive(core_crypto_macros::Debug)]
/// The type representing the X509 acquisition process.
///
/// Performs the two ACME challenges necessary to obtain a certificate,
/// wire-dpop-01 and wire-oidc-01, in that order.
///
/// State transitions:
///      (*)
///       |
///       | ::try_new()
///       |
///       v
///  Initialized
///       |
///       | .complete_dpop_challenge()
///       |
///       v
///  DpopChallengeCompleted
///       |
///       | .complete_oidc_challenge()
///       |
///       v
///  (no final state, acquisition is consumed)
///
/// After the second (OIDC) challenge, the signing keypair and the certificate
/// chain is returned to the caller. Regardless of success, the acquisition
/// instance is consumed and cannot be used anymore.
///
/// Sample usage:
///
/// ```rust,ignore
/// let acq = X509CredentialAcquisition::try_new(pki_env, config)?;
/// let (sign_kp, certs) = acq
///     .complete_dpop_challenge().await?
///     .complete_oidc_challenge().await?;
/// ```
pub struct X509CredentialAcquisition<T: std::fmt::Debug = states::Initialized> {
    /// A reference to the PKI environment that stores trust anchors.
    pki_env: Arc<PkiEnvironment>,
    /// The configuration used for acquisition.
    config: X509CredentialConfiguration,
    /// The signing keypair, public part of which will be certified
    /// by the ACME server via inclusion in the certificate.
    /// This keypair is essentially the credential.
    #[sensitive]
    sign_kp: Pem,
    /// The keypair used to sign requests (JWS messages) sent to
    /// the ACME server. Bound to the ACME client account.
    #[sensitive]
    acme_kp: Pem,
    /// Public part of the `acme_kp` keypair, in JSON Web Key form.
    acme_jwk: Jwk,
    /// State-specific data.
    data: T,
}

pub type Result<T> = std::result::Result<T, error::Error>;

fn get_header(resp: &HttpResponse, header: &'static str) -> Result<String> {
    resp.first_header(header)
        .ok_or_else(|| error::Error::MissingHeader(header))
}

impl<T: std::fmt::Debug> X509CredentialAcquisition<T> {
    /// Send an HTTP request to the ACME server and return the result in the form of a
    /// pair (nonce, deserialized JSON response). The nonce is returned so it can be
    /// used by the caller to construct the body of the next ACME request.
    async fn acme_request(&self, url: &Url, body: &AcmeJws) -> Result<(String, serde_json::Value)> {
        let headers = vec![HttpHeader {
            name: "content-type".into(),
            value: "application/jose+json".into(),
        }];
        let body = serde_json::to_string(&body)?.into();
        let response = self
            .pki_env
            .hooks()
            .http_request(HttpMethod::Post, url.to_string(), headers, body)
            .await?;

        let nonce = get_header(&response, "replay-nonce")?;
        Ok((nonce, response.json()?))
    }

    fn acme_url(&self, path: &str) -> Url {
        format!("https://{}/acme/wire/{path}", self.config.acme_url)
            .parse()
            .expect("valid URL")
    }
}
