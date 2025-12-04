use jwt_simple::prelude::*;
use rusty_jwt_tools::{
    jwk::TryIntoJwk,
    prelude::{HashAlgorithm, JwkThumbprint, JwsAlgorithm},
};
use x509_cert::spki::SubjectPublicKeyInfoOwned;

use crate::acme::{
    error::CertificateError,
    prelude::{RustyAcmeError, RustyAcmeResult},
};

/// Used to compute the MLS thumbprint of a Basic Credential
pub fn compute_raw_key_thumbprint(
    sign_alg: JwsAlgorithm,
    hash_alg: HashAlgorithm,
    signature_public_key: &[u8],
) -> RustyAcmeResult<String> {
    let jwk = match sign_alg {
        JwsAlgorithm::Ed25519 => Ed25519PublicKey::from_bytes(signature_public_key)?.try_into_jwk()?,
        JwsAlgorithm::P256 => ES256PublicKey::from_bytes(signature_public_key)?.try_into_jwk()?,
        JwsAlgorithm::P384 => ES384PublicKey::from_bytes(signature_public_key)?.try_into_jwk()?,
        JwsAlgorithm::P521 => ES512PublicKey::from_bytes(signature_public_key)?.try_into_jwk()?,
    };
    let thumbprint = JwkThumbprint::generate(&jwk, hash_alg)?;
    Ok(thumbprint.kid)
}

/// See: https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.3
pub(crate) fn try_compute_jwk_canonicalized_thumbprint(
    cert: &x509_cert::TbsCertificate,
    hash_alg: HashAlgorithm,
) -> RustyAcmeResult<String> {
    let jwk = try_into_jwk(&cert.subject_public_key_info)?;
    let thumbprint = JwkThumbprint::generate(&jwk, hash_alg)?;
    Ok(thumbprint.kid)
}

fn try_into_jwk(spki: &SubjectPublicKeyInfoOwned) -> RustyAcmeResult<Jwk> {
    use const_oid::db::{
        rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
        rfc8410::{ID_ED_448, ID_ED_25519},
    };
    let params = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|param| x509_cert::spki::ObjectIdentifier::from_bytes(param.value()).ok());

    match (spki.algorithm.oid, params) {
        (ID_ED_25519, None) => Ok(Ed25519PublicKey::from_bytes(spki.subject_public_key.raw_bytes())?.try_into_jwk()?),
        (ID_ED_448, None) => Err(RustyAcmeError::InvalidCertificate(
            CertificateError::UnsupportedPublicKey,
        )),
        (ID_EC_PUBLIC_KEY, Some(SECP_256_R_1)) => {
            Ok(ES256PublicKey::from_bytes(spki.subject_public_key.raw_bytes())?.try_into_jwk()?)
        }
        (ID_EC_PUBLIC_KEY, Some(SECP_384_R_1)) => {
            Ok(ES384PublicKey::from_bytes(spki.subject_public_key.raw_bytes())?.try_into_jwk()?)
        }
        (ID_EC_PUBLIC_KEY, Some(SECP_521_R_1)) => {
            Ok(ES512PublicKey::from_bytes(spki.subject_public_key.raw_bytes())?.try_into_jwk()?)
        }
        _ => Err(RustyAcmeError::InvalidCertificate(
            CertificateError::UnsupportedPublicKey,
        )),
    }
}
