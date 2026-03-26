use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair};
use rusty_jwt_tools::prelude::{JwsAlgorithm, Pem};

use crate::error::E2eIdentityResult;

pub fn generate_key(sign_alg: JwsAlgorithm) -> E2eIdentityResult<Pem> {
    let pem = match sign_alg {
        JwsAlgorithm::P256 => ES256KeyPair::generate().to_pem()?,
        JwsAlgorithm::P384 => ES384KeyPair::generate().to_pem()?,
        JwsAlgorithm::P521 => ES512KeyPair::generate().to_pem()?,
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().to_pem(),
    };
    Ok(pem.into())
}
