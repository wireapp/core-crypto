use jwt_simple::prelude::{JWTClaims, JWTHeader};
use rusty_jwt_tools::prelude::{JwsAlgorithm, Pem, RustyJwtTools};

use crate::acme::{RustyAcmeError, RustyAcmeResult};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Clone))]
#[serde(rename_all = "camelCase")]
pub struct AcmeJws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

impl AcmeJws {
    pub fn new<T>(
        alg: JwsAlgorithm,
        nonce: String,
        url: &url::Url,
        kid: Option<&url::Url>,
        payload: Option<T>,
        kp: &Pem,
    ) -> RustyAcmeResult<Self>
    where
        T: serde::Serialize,
        for<'de> T: serde::Deserialize<'de>,
    {
        let with_jwk = kid.is_none();
        let header = Self::header(alg, nonce, url, kid);

        let is_empty_payload = payload.is_none();
        let claims = payload.map(Self::claims);
        let jwt = RustyJwtTools::generate_jwt(alg, header, claims, kp, with_jwk)?;
        let (protected, jwt) = jwt.split_once('.').ok_or(RustyAcmeError::ImplementationError)?;
        let (payload, signature) = jwt.split_once('.').ok_or(RustyAcmeError::ImplementationError)?;
        if signature.contains('.') {
            // we would have a malformed jwt
            return Err(RustyAcmeError::ImplementationError);
        }

        let payload = if is_empty_payload { "" } else { payload };

        Ok(Self {
            protected: protected.to_string(),
            payload: payload.to_string(),
            signature: signature.to_string(),
        })
    }

    fn claims<T>(custom: T) -> JWTClaims<T> {
        JWTClaims {
            custom,
            nonce: None,
            issuer: None,
            subject: None,
            jwt_id: None,
            audiences: None,
            expires_at: None,
            invalid_before: None,
            issued_at: None,
        }
    }

    fn header(alg: JwsAlgorithm, nonce: String, url: &url::Url, kid: Option<&url::Url>) -> JWTHeader {
        JWTHeader {
            algorithm: alg.to_string(),
            custom: Some(serde_json::json!({
                "nonce": nonce,
                "url": url,
            })),
            key_id: kid.map(url::Url::to_string),
            ..Default::default()
        }
    }
}
