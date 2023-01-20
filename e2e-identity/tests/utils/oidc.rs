use jwt_simple::prelude::*;
use rusty_jwt_tools::{jwk_thumbprint::JwkThumbprint, prelude::*};

#[allow(clippy::too_many_arguments)]
pub fn id_token(
    alg: JwsAlgorithm,
    kp: Pem,
    iss: String,
    sub: String,
    aud: String,
    jwk: Jwk,
    chall_token: String,
    display_name: String,
    handle: String,
) -> String {
    let headers = JWTHeader {
        algorithm: alg.to_string(),
        ..Default::default()
    };

    let thumbprint = JwkThumbprint::generate(&jwk, HashAlgorithm::SHA256).unwrap().kid;
    let keyauth = format!("{chall_token}.{thumbprint}");

    let oidc = Oidc {
        name: display_name,
        handle,
        keyauth,
    };
    let claims = Claims::with_custom_claims(oidc, Duration::from_days(1))
        .with_subject(sub)
        .with_issuer(iss)
        .with_audience(aud);
    RustyJwtTools::generate_jwt::<Oidc>(alg, headers, Some(claims), &kp, false).unwrap()
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub struct Oidc {
    name: String,
    handle: String,
    keyauth: String,
}
