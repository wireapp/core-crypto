use rusty_jwt_tools::{jwk_thumbprint::JwkThumbprint, prelude::Pem};
use x509_cert::Certificate;

use super::{Result, X509CredentialAcquisition, states};
use crate::{
    acme::{RustyAcme, RustyAcmeError},
    pki_env::hooks::{HttpHeader, HttpMethod},
};

impl X509CredentialAcquisition<states::DpopChallengeCompleted> {
    /// Complete the OIDC challenge and get the certificate chain.
    ///
    /// Returns (signing keypair in PEM format, certificate chain).
    /// The first certificate in the chain is the end-entity certificate,
    /// i.e. the one certifying the public portion of the signing keypair.
    pub async fn complete_oidc_challenge(self) -> Result<(Pem, Vec<Certificate>)> {
        let hooks = self.pki_env.hooks();

        // Complete the OIDC challenge.
        let oidc_challenge_token = &self.data.oidc_challenge.token;
        let thumbprint = JwkThumbprint::generate(&self.acme_jwk, self.config.hash_alg)?.kid;
        let key_auth = format!("{oidc_challenge_token}.{thumbprint}");

        let url = &self.data.oidc_challenge.url;
        let id_token = hooks
            .authenticate(self.config.idp_url.clone(), key_auth, url.to_string())
            .await?;

        let oidc_challenge_request = RustyAcme::oidc_chall_request(
            id_token,
            &self.data.oidc_challenge,
            &self.data.acme_account,
            self.config.sign_alg,
            &self.acme_kp,
            self.data.nonce.clone(),
        )?;
        let (nonce, response) = self.acme_request(url, &oidc_challenge_request).await?;
        let _ = RustyAcme::new_chall_response(response)?;

        // Finalize the order. This generates a CSR (Certificate Signing Request) and
        // sends it to the ACME server.
        let finalize_request = RustyAcme::finalize_req(
            &self.data.order,
            &self.data.acme_account,
            self.config.sign_alg,
            &self.acme_kp,
            &self.sign_kp,
            nonce,
        )?;
        let (nonce, response) = self.acme_request(&self.data.order.finalize, &finalize_request).await?;
        let finalize = RustyAcme::finalize_response(response)?;

        // Get the certificate chain.
        //
        // See [RFC 8555 Section 7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2).
        let certificate_request = RustyAcme::certificate_req(
            &finalize,
            &self.data.acme_account,
            self.config.sign_alg,
            &self.acme_kp,
            nonce,
        )?;
        let headers = vec![HttpHeader {
            name: "content-type".into(),
            value: "application/jose+json".into(),
        }];
        let body = serde_json::to_string(&certificate_request)?.into();
        let response = hooks
            .http_request(HttpMethod::Post, finalize.certificate.to_string(), headers, body)
            .await?;
        let response = String::from_utf8(response.body).map_err(|e| RustyAcmeError::from(e.utf8_error()))?;
        let certificates = RustyAcme::certificate_response(response, self.data.order)?;

        super::checks::verify_cert_chain(&self.config, &self.pki_env, &certificates).await?;

        Ok((self.sign_kp, certificates))
    }
}
