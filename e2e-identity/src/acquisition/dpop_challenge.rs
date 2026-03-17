use rusty_jwt_tools::prelude::{Dpop, Handle, Htm, RustyJwtTools};

use super::{Result, X509CredentialAcquisition, get_header, states};
use crate::{
    acme::{AcmeAccount, AcmeChallenge, AcmeChallengeType, AcmeOrder, RustyAcme, RustyAcmeError},
    pki_env_hooks::HttpMethod,
};

impl X509CredentialAcquisition<states::Initialized> {
    async fn get_challenge(
        &self,
        url: &url::Url,
        acme_account: &AcmeAccount,
        nonce: String,
    ) -> Result<(String, AcmeChallenge)> {
        let authz_request =
            RustyAcme::new_authz_request(url, acme_account, self.config.sign_alg, &self.acme_kp, nonce.clone())?;
        let (nonce, response) = self.acme_request(url, &authz_request).await?;
        let authorization = RustyAcme::new_authz_response(response)?;
        let [challenge] = authorization.challenges;
        Ok((nonce, challenge))
    }

    async fn get_challenges(
        &self,
        acme_account: &AcmeAccount,
        order: &AcmeOrder,
        nonce: String,
    ) -> Result<(String, AcmeChallenge, AcmeChallenge)> {
        // ACME authorization objects specify challenges we must do in order to get a
        // certificate. We expect exactly two authorization objects, one for the "wireapp-user"
        // identifier and one for the "wireapp-device" identifier. Each authorization must
        // specify exactly one challenge.
        //
        // See [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5).
        let (nonce, challenge1) = self
            .get_challenge(&order.authorizations[0], acme_account, nonce)
            .await?;
        let (nonce, challenge2) = self
            .get_challenge(&order.authorizations[1], acme_account, nonce)
            .await?;

        // To make things easier for our caller, we return challenges in the fixed order
        // (wire-dpop-01, wire-oidc-01). We cannot rely on ACME giving us challenges in a specific
        // order.
        use AcmeChallengeType::*;
        match (challenge1.typ, challenge2.typ) {
            (WireDpop01, WireOidc01) => Ok((nonce, challenge1, challenge2)),
            (WireOidc01, WireDpop01) => Ok((nonce, challenge2, challenge1)),
            _ => Err(RustyAcmeError::from(crate::acme::AcmeAuthzError::InvalidChallengeType).into()),
        }
    }

    /// Complete the DPoP challenge.
    pub async fn complete_dpop_challenge(self) -> Result<X509CredentialAcquisition<states::DpopChallengeCompleted>> {
        let hooks = self.pki_env.hooks();

        // Get the ACME server directory via `GET /acme/{provisioner-name}/directory`.
        //
        // See [RFC 8555 Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1)
        let url = self.acme_url("directory");

        let resp = hooks
            .http_request(HttpMethod::Get, url.to_string(), vec![], vec![])
            .await?;
        let body = resp.json()?;
        let directory = RustyAcme::acme_directory_response(body).unwrap();

        let url = directory.new_nonce.to_string();
        let resp = hooks.http_request(HttpMethod::Get, url, vec![], vec![]).await?;
        let nonce = get_header(&resp, "replay-nonce")?;

        // Create a new ACME account.
        //
        // See [RFC 8555 Section 7.3](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3).
        let account_request = RustyAcme::new_account_request(&directory, self.config.sign_alg, &self.acme_kp, nonce)?;
        let (nonce, response) = self
            .acme_request(&self.acme_url("new-account"), &account_request)
            .await?;
        let acme_account = RustyAcme::new_account_response(response)?;

        // Create a new ACME order.
        //
        // See [RFC 8555 Section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4).
        let order_request = RustyAcme::new_order_request(
            &self.config.display_name,
            self.config.client_id.clone(),
            &self.config.handle.clone().into(),
            self.config.validity_period,
            &directory,
            &acme_account,
            self.config.sign_alg,
            &self.acme_kp,
            nonce,
        )?;
        let (nonce, response) = self.acme_request(&self.acme_url("new-order"), &order_request).await?;
        let order = RustyAcme::new_order_response(response)?;

        let (nonce, dpop_challenge, oidc_challenge) = self.get_challenges(&acme_account, &order, nonce).await?;

        // Generate a new client DPoP JWT token. It demonstrates proof of possession of nonces from
        // the Wire server and the ACME server), and will be verified by the ACME server when
        // verifying the challenge.
        let backend_nonce = hooks.get_backend_nonce().await?;

        let audience = dpop_challenge.url.clone();
        let client_id = &self.config.client_id;
        let handle = Handle::from(self.config.handle.clone()).try_to_qualified(&client_id.domain)?;
        let dpop = Dpop {
            htm: Htm::Post,
            htu: dpop_challenge.target.clone().into(),
            challenge: dpop_challenge.token.clone().into(),
            handle,
            team: self.config.team.clone().into(),
            display_name: self.config.display_name.clone(),
            extra_claims: None,
        };
        let token = RustyJwtTools::generate_dpop_token(
            dpop,
            client_id,
            backend_nonce.into(),
            audience,
            std::time::Duration::from_mins(5),
            self.config.sign_alg,
            &self.acme_kp,
        )?;

        // Send the DPoP token to Wire server and get back an access token.
        let access_token = hooks.fetch_backend_access_token(token).await?;

        // Complete the DPoP challenge.
        //
        // See [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1).
        let dpop_challenge_request = RustyAcme::dpop_chall_request(
            access_token,
            dpop_challenge.clone(),
            &acme_account,
            self.config.sign_alg,
            &self.acme_kp,
            nonce,
        )?;
        let (nonce, response) = self.acme_request(&dpop_challenge.url, &dpop_challenge_request).await?;
        let _ = RustyAcme::new_chall_response(response)?;

        Ok(X509CredentialAcquisition::<states::DpopChallengeCompleted> {
            pki_env: self.pki_env,
            config: self.config,
            sign_kp: self.sign_kp,
            acme_kp: self.acme_kp,
            acme_jwk: self.acme_jwk,
            data: states::DpopChallengeCompleted {
                nonce,
                acme_account,
                order,
                oidc_challenge,
            },
        })
    }
}
