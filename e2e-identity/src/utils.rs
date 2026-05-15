use jwt_simple::{
    algorithms::{ECDSAP256PublicKeyLike as _, ECDSAP384PublicKeyLike as _, ECDSAP521PublicKeyLike as _},
    prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair, Jwk},
};
use rusty_jwt_tools::{
    jwk::TryIntoJwk as _,
    prelude::{JwsAlgorithm, Pem},
};
use spki::AlgorithmIdentifierOwned;

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

pub(crate) fn public_key_bytes(alg: JwsAlgorithm, keypair: &Pem) -> E2eIdentityResult<Vec<u8>> {
    let bytes = match alg {
        JwsAlgorithm::P256 => ES256KeyPair::from_pem(keypair)?
            .public_key()
            .public_key()
            .to_bytes_uncompressed(),
        JwsAlgorithm::P384 => ES384KeyPair::from_pem(keypair)?
            .public_key()
            .public_key()
            .to_bytes_uncompressed(),
        JwsAlgorithm::P521 => ES512KeyPair::from_pem(keypair)?
            .public_key()
            .public_key()
            .to_bytes_uncompressed(),
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_pem(keypair)?.public_key().to_bytes(),
    };
    Ok(bytes)
}

pub(crate) fn jws_alg_to_x509_identifier(alg: JwsAlgorithm) -> AlgorithmIdentifierOwned {
    match alg {
        JwsAlgorithm::Ed25519 => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None,
        },
        JwsAlgorithm::P256 => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(const_oid::db::rfc5912::SECP_256_R_1.into()),
        },
        JwsAlgorithm::P384 => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(const_oid::db::rfc5912::SECP_384_R_1.into()),
        },
        JwsAlgorithm::P521 => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(const_oid::db::rfc5912::SECP_521_R_1.into()),
        },
    }
}
