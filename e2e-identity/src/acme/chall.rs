use rusty_jwt_tools::prelude::{JwsAlgorithm, Pem};

use crate::acme::{AcmeAccount, AcmeJws, RustyAcmeError, RustyAcmeResult};

/// client id challenge request to `POST /acme/challenge/{token}`
/// see [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
pub(crate) fn dpop_chall_request(
    access_token: String,
    dpop_chall: AcmeChallenge,
    account: &AcmeAccount,
    alg: JwsAlgorithm,
    kp: &Pem,
    previous_nonce: String,
) -> RustyAcmeResult<AcmeJws> {
    // Extract the account URL from previous response which created a new account
    let acct_url = account.acct_url()?;

    let payload = Some(serde_json::json!({
        "access_token": access_token,
    }));

    let req = AcmeJws::new(alg, previous_nonce, &dpop_chall.url, Some(&acct_url), payload, kp)?;
    Ok(req)
}

/// oidc challenge request to `POST /acme/challenge/{token}`
/// see [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
#[allow(clippy::too_many_arguments)]
pub(crate) fn oidc_chall_request(
    id_token: String,
    oidc_chall: &AcmeChallenge,
    account: &AcmeAccount,
    alg: JwsAlgorithm,
    kp: &Pem,
    previous_nonce: String,
) -> RustyAcmeResult<AcmeJws> {
    // Extract the account URL from previous response which created a new account
    let acct_url = account.acct_url()?;
    let payload = Some(serde_json::json!({
        "id_token": id_token,
    }));
    let req = AcmeJws::new(alg, previous_nonce, &oidc_chall.url, Some(&acct_url), payload, kp)?;
    Ok(req)
}

/// 18. parse the response from `POST /acme/challenge/{token}` [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
pub(crate) fn new_chall_response(response: serde_json::Value) -> RustyAcmeResult<AcmeChallenge> {
    let chall = serde_json::from_value::<AcmeChallenge>(response)?;
    match chall.status {
        Some(AcmeChallengeStatus::Valid) => {}
        Some(AcmeChallengeStatus::Processing) => return Err(AcmeChallError::Processing)?,
        Some(AcmeChallengeStatus::Invalid) => return Err(AcmeChallError::Invalid)?,
        Some(AcmeChallengeStatus::Pending) => {
            return Err(RustyAcmeError::ClientImplementationError(
                "a challenge is not supposed to be pending at this point. \
                    It must either be 'valid' or 'processing'.",
            ));
        }
        None => {
            return Err(RustyAcmeError::ClientImplementationError(
                "at this point a challenge is supposed to have a status",
            ));
        }
    }
    Ok(chall)
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeChallError {
    /// This challenge is invalid
    #[error("This challenge is invalid")]
    Invalid,
    /// This challenge is being processed, retry later
    #[error("This challenge is being processed, retry later")]
    Processing,
}

/// For creating a challenge
/// see [RFC 8555 Section 7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    /// Should be `wire-http-01` or `wire-oidc-01`
    pub typ: AcmeChallengeType,
    /// URL to call for the acme server to complete the challenge
    pub url: url::Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Should be `valid`
    pub status: Option<AcmeChallengeStatus>,
    /// The acme challenge value to store in the Dpop token
    pub token: String,
    /// Non-standard, Wire specific claim. Indicates the consumer from where it should get the challenge
    /// proof. Either from wire-server "/access-token" endpoint in case of a DPoP challenge, or from
    /// an OAuth token endpoint for an OIDC challenge
    pub target: url::Url,
}

#[cfg(test)]
impl AcmeChallenge {
    pub fn new_device() -> Self {
        Self {
            status: None,
            typ: AcmeChallengeType::WireDpop01,
            url: "ttps://stepca/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ"
                .parse()
                .unwrap(),
            token: "DGyRejmCefe7v4NfDGDKfA".to_string(),
            target: "http://wire.com:21893/clients/aeddd6d37af25726/access-token"
                .parse()
                .unwrap(),
        }
    }

    pub fn new_user() -> Self {
        Self {
            status: None,
            typ: AcmeChallengeType::WireOidc01,
            url: "https://stepca/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2"
                .parse()
                .unwrap(),
            token: "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ".to_string(),
            target: "http://keycloak:15170/realms/master".parse().unwrap(),
        }
    }
}

/// see [RFC 8555 Section 7.1.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.6)
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AcmeChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

/// See [RFC 8555, section 9.7.8](https://www.rfc-editor.org/info/rfc8555/#section-9.7.8) and
/// [RFC 8737](https://www.rfc-editor.org/info/rfc8737).
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AcmeChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// DPoP challenge, specific to Wire (validates client ID)
    #[serde(rename = "wire-dpop-01")]
    WireDpop01,
    /// OIDC challenge, specific to Wire (validates handle and display name)
    #[serde(rename = "wire-oidc-01")]
    WireOidc01,
}
