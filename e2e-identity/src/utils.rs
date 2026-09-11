use certval::ExtensionProcessing as _;
use jwt_simple::{
    algorithms::{ECDSAP256PublicKeyLike as _, ECDSAP384PublicKeyLike as _, ECDSAP521PublicKeyLike as _},
    prelude::{ES256KeyPair, ES384KeyPair, ES512KeyPair, Ed25519KeyPair, Jwk},
};
use rusty_jwt_tools::{
    jwk::TryIntoJwk as _,
    prelude::{JwsAlgorithm, Pem},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::AuthorityKeyIdentifier;

use crate::{
    error::E2eIdentityResult,
    x509_check::{RustyX509CheckError, RustyX509CheckResult},
};

pub fn generate_key(sign_alg: JwsAlgorithm) -> E2eIdentityResult<Pem> {
    let pem = match sign_alg {
        JwsAlgorithm::P256 => ES256KeyPair::generate().to_pem()?,
        JwsAlgorithm::P384 => ES384KeyPair::generate().to_pem()?,
        JwsAlgorithm::P521 => ES512KeyPair::generate().to_pem()?,
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::generate().to_pem(),
    };
    Ok(pem.into())
}

pub fn pem_from_bytes(bytes: &[u8], sign_alg: JwsAlgorithm) -> E2eIdentityResult<Pem> {
    let pem = match sign_alg {
        JwsAlgorithm::P256 => ES256KeyPair::from_bytes(bytes)?.to_pem()?,
        JwsAlgorithm::P384 => ES384KeyPair::from_bytes(bytes)?.to_pem()?,
        JwsAlgorithm::P521 => ES512KeyPair::from_bytes(bytes)?.to_pem()?,
        JwsAlgorithm::Ed25519 => Ed25519KeyPair::from_bytes(bytes)?.to_pem(),
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

pub(crate) fn extract_ski_aki_from_cert(
    cert: &x509_cert::Certificate,
) -> RustyX509CheckResult<(String, Option<String>)> {
    let cert = certval::PDVCertificate::try_from(cert.clone())?;

    let ski = cert
        .get_extension(&const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER)?
        .ok_or(RustyX509CheckError::MissingSki)?;
    let ski = match ski {
        certval::PDVExtension::SubjectKeyIdentifier(ski) => hex::encode(ski.0.as_bytes()),
        _ => return Err(RustyX509CheckError::ImplementationError),
    };

    let aki = cert
        .get_extension(&const_oid::db::rfc5912::ID_CE_AUTHORITY_KEY_IDENTIFIER)?
        .and_then(|ext| match ext {
            certval::PDVExtension::AuthorityKeyIdentifier(AuthorityKeyIdentifier { key_identifier, .. }) => {
                key_identifier.as_ref()
            }
            _ => None,
        })
        .map(|ki| hex::encode(ki.as_bytes()));

    Ok((ski, aki))
}
