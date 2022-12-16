use jwt_simple::prelude::*;
use rusty_jwt_tools::prelude::*;

pub fn keys() -> Vec<(JwsAlgorithm, Pem, Jwk, Pem, HashAlgorithm)> {
    use rusty_jwt_tools::jwk::TryIntoJwk as _;

    let ed25519_key = {
        let ed25519_client_kp = Ed25519KeyPair::generate();
        (
            JwsAlgorithm::Ed25519,
            ed25519_client_kp.to_pem().into(),
            ed25519_client_kp.public_key().try_into_jwk().unwrap(),
            Ed25519KeyPair::generate().to_pem().into(),
            HashAlgorithm::SHA256,
        )
    };
    #[cfg(not(target_family = "wasm"))]
    let p256_key = {
        let p256_client_kp = ES256KeyPair::generate();
        (
            JwsAlgorithm::P256,
            p256_client_kp.to_pem().unwrap().into(),
            p256_client_kp.public_key().try_into_jwk().unwrap(),
            ES256KeyPair::generate().to_pem().unwrap().into(),
            HashAlgorithm::SHA256,
        )
    };
    #[cfg(not(target_family = "wasm"))]
    let p384_key = {
        let p384_client_kp = ES384KeyPair::generate();
        (
            JwsAlgorithm::P384,
            p384_client_kp.to_pem().unwrap().into(),
            p384_client_kp.public_key().try_into_jwk().unwrap(),
            ES384KeyPair::generate().to_pem().unwrap().into(),
            HashAlgorithm::SHA384,
        )
    };

    #[cfg(not(target_family = "wasm"))]
    let keys = vec![ed25519_key, p256_key, p384_key];

    #[cfg(target_family = "wasm")]
    let keys = vec![ed25519_key];

    keys
}
