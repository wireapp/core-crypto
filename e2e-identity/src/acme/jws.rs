use rusty_jwt_tools::{
    jsonwebtoken::{Header, jwk::Jwk, jws},
    prelude::{JwsAlgorithm, Pem},
};

use crate::acme::Result;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AcmeJws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

impl AcmeJws {
    /// Signs an ACME request
    ///
    /// Without `payload`, the payload is empty, as required for POST-as-GET requests. Without `kid`, the public key
    /// is embedded as 'jwk', as required before the account exists.
    /// See [RFC 8555 Section 6.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-6.2).
    pub(crate) fn new<T>(
        alg: JwsAlgorithm,
        nonce: String,
        url: &url::Url,
        kid: Option<&url::Url>,
        payload: Option<T>,
        kp: &Pem,
    ) -> Result<Self>
    where
        T: serde::Serialize,
    {
        let key = alg.encoding_key(kp)?;
        let jwk = match kid {
            Some(_) => None,
            None => Some(Jwk::from_encoding_key(&key, alg.into())?),
        };
        let header = Header {
            alg: alg.into(),
            jwk,
            kid: kid.map(url::Url::to_string),
            nonce: Some(nonce),
            url: Some(url.to_string()),
            ..Default::default()
        };

        let jws = jws::encode(&header, payload.as_ref(), &key)?;
        Ok(Self {
            protected: jws.protected,
            payload: jws.payload,
            signature: jws.signature,
        })
    }
}
