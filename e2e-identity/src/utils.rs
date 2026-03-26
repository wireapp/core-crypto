use jwt_simple::prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair, Jwk};
use rusty_jwt_tools::{
    jwk::TryIntoJwk as _,
    prelude::{JwsAlgorithm, Pem},
};

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

pub fn public_jwk_from_pem_keypair(alg: JwsAlgorithm, keypair: &Pem) -> E2eIdentityResult<Jwk> {
    let jwk = match alg {
        JwsAlgorithm::P256 => ES256KeyPair::from_pem(keypair)?.public_key().try_into_jwk()?,
        JwsAlgorithm::P384 => ES384KeyPair::from_pem(keypair)?.public_key().try_into_jwk()?,
        JwsAlgorithm::P521 => ES512KeyPair::from_pem(keypair)?.public_key().try_into_jwk()?,
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(keypair)?.public_key().try_into_jwk()?,
    };
    Ok(jwk)
}
