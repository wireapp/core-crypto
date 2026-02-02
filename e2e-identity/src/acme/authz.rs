use base64::Engine;
use rusty_jwt_tools::prelude::{JwsAlgorithm, Pem};

use crate::acme::{
    AcmeAccount, AcmeChallenge, AcmeChallengeType, AcmeIdentifier, AcmeJws, RustyAcme, RustyAcmeError, RustyAcmeResult,
};

impl RustyAcme {
    /// create authorizations
    /// see [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5)
    pub fn new_authz_request(
        url: &url::Url,
        account: &AcmeAccount,
        alg: JwsAlgorithm,
        kp: &Pem,
        previous_nonce: String,
    ) -> RustyAcmeResult<AcmeJws> {
        // Extract the account URL from previous response which created a new account
        let acct_url = account.acct_url()?;

        // No payload required for authz
        let payload = None::<serde_json::Value>;
        let req = AcmeJws::new(alg, previous_nonce, url, Some(&acct_url), payload, kp)?;
        Ok(req)
    }

    /// parse the response from `POST /acme/authz/{authz_id}`
    /// [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5)
    pub fn new_authz_response(response: serde_json::Value) -> RustyAcmeResult<AcmeAuthz> {
        let authz = serde_json::from_value::<AcmeAuthz>(response)?;

        authz.verify()?;

        match authz.status {
            AuthzStatus::Pending => {}
            AuthzStatus::Invalid => return Err(AcmeAuthzError::Invalid)?,
            AuthzStatus::Revoked => return Err(AcmeAuthzError::Revoked)?,
            AuthzStatus::Deactivated => return Err(AcmeAuthzError::Deactivated)?,
            AuthzStatus::Expired => return Err(AcmeAuthzError::Expired)?,
            AuthzStatus::Valid => {
                return Err(RustyAcmeError::ClientImplementationError(
                    "an authorization is not supposed to be valid at this point. \
                    You should only use this method to parse the response of an authorization creation.",
                ));
            }
        }
        Ok(authz)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeAuthzError {
    /// This authorization is expired
    #[error("This authorization is expired")]
    Expired,
    /// This authorization is invalid
    #[error("This authorization is invalid")]
    Invalid,
    /// The server revoked this authorization
    #[error("The server revoked this authorization")]
    Revoked,
    /// The client deactivated this authorization
    #[error("The client deactivated this authorization")]
    Deactivated,
    /// The Challenge tokens must be base64 URL strings
    #[error("The Challenge tokens must be base64 URL strings")]
    InvalidBase64Token,
    /// The Challenge token must have at least 128 bits of entropy
    #[error("The Challenge token must have at least 128 bits of entropy")]
    InvalidTokenEntropy,
    /// The Challenge type must match the identifier type
    #[error("The Challenge type must match the identifier type")]
    InvalidChallengeType,
}

/// Result of an authorization creation
/// see [RFC 8555 Section 7.5](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeAuthz {
    /// Should be pending for a newly created authorization
    pub status: AuthzStatus,
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    /// Expiration time as [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339)
    pub expires: Option<time::OffsetDateTime>,
    /// Challenges to complete later
    pub challenges: [AcmeChallenge; 1],
    /// DNS entry associated with those challenge
    pub identifier: AcmeIdentifier,
}

impl AcmeAuthz {
    pub fn verify(&self) -> RustyAcmeResult<()> {
        let [challenge] = &self.challenges;

        if matches!(
            (&self.identifier, challenge.typ),
            (AcmeIdentifier::WireappDevice(_), AcmeChallengeType::WireDpop01)
                | (AcmeIdentifier::WireappUser(_), AcmeChallengeType::WireOidc01)
        ) {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();

            let is_expired = self
                .expires
                .map(time::OffsetDateTime::unix_timestamp)
                .is_some_and(|expires| expires < now);
            if is_expired {
                return Err(AcmeAuthzError::Expired)?;
            }

            // RFC 8555 security considerations
            // see https://datatracker.ietf.org/doc/html/rfc8555#section-8.1
            let token = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(&challenge.token)
                .map_err(|_| AcmeAuthzError::InvalidBase64Token)?;

            // token have enough entropy (at least 16 bytes)
            // see https://datatracker.ietf.org/doc/html/rfc8555#section-11.3
            const RECOMMENDED_TOKEN_ENTROPY: usize = 128 / 8;
            if token.len() < RECOMMENDED_TOKEN_ENTROPY {
                return Err(AcmeAuthzError::InvalidTokenEntropy.into());
            }

            return Ok(());
        }
        Err(AcmeAuthzError::InvalidChallengeType)?
    }
}

#[cfg(test)]
impl Default for AcmeAuthz {
    fn default() -> Self {
        Self {
            status: AuthzStatus::Pending,
            expires: Some(time::OffsetDateTime::now_utc()),
            identifier: AcmeIdentifier::new_device(),
            challenges: [AcmeChallenge::new_device()],
        }
    }
}

/// see [RFC 8555 Section 7.1.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.6)
#[derive(Debug, Copy, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthzStatus {
    Pending,
    Invalid,
    Valid,
    Revoked,
    Deactivated,
    Expired,
}

#[cfg(test)]
pub mod tests {
    use serde_json::json;
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    mod json {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn can_deserialize_sample_response() {
            let rfc_sample = json!({
                "status": "pending",
                "expires": "2016-01-02T14:09:30Z",
                "identifier": {
                    "type": "wireapp-user",
                    "value": "www.example.org"
                },
                "challenges": [
                    {
                        "type": "http-01",
                        "url": "https://example.com/acme/chall/prV_B7yEyA4",
                        "token": "DGyRejmCefe7v4NfDGDKfA",
                        "target": "https://example.com/target"
                    }
                ]
            });
            assert!(serde_json::from_value::<AcmeAuthz>(rfc_sample).is_ok());
        }
    }

    mod verify {
        use super::*;

        #[test]
        #[wasm_bindgen_test]
        fn should_succeed_when_valid() {
            let tomorrow = time::OffsetDateTime::now_utc() + time::Duration::days(1);
            let order = AcmeAuthz {
                expires: Some(tomorrow),
                ..Default::default()
            };
            assert!(order.verify().is_ok());
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_expires_in_past() {
            let yesterday = time::OffsetDateTime::now_utc() - time::Duration::days(1);
            let order = AcmeAuthz {
                expires: Some(yesterday),
                ..Default::default()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::AuthzError(AcmeAuthzError::Expired)
            ));
        }

        #[test]
        #[wasm_bindgen_test]
        fn should_fail_when_challenge_type_mismatches_identifier_type() {
            let tomorrow = time::OffsetDateTime::now_utc() + time::Duration::days(1);
            let order = AcmeAuthz {
                expires: Some(tomorrow),
                identifier: AcmeIdentifier::new_user(),
                challenges: [AcmeChallenge::new_device()],
                ..Default::default()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::AuthzError(AcmeAuthzError::InvalidChallengeType)
            ));
            let order = AcmeAuthz {
                expires: Some(tomorrow),
                identifier: AcmeIdentifier::new_device(),
                challenges: [AcmeChallenge::new_user()],
                ..Default::default()
            };
            assert!(matches!(
                order.verify().unwrap_err(),
                RustyAcmeError::AuthzError(AcmeAuthzError::InvalidChallengeType)
            ));
        }
    }
}
