use const_oid::db::{
    rfc5912::{ID_EC_PUBLIC_KEY, SECP_256_R_1, SECP_384_R_1, SECP_521_R_1},
    rfc8410::ID_ED_25519,
};
use rusty_jwt_tools::{
    jsonwebtoken::{
        DecodingKey,
        errors::Result as JsonWebTokenResult,
        jwk::{Jwk, ThumbprintHash},
    },
    prelude::JwsAlgorithm,
};

use crate::{acme, acquisition::error::CertificateError};

/// The hash algorithm used for all thumbprints, regardless of the MLS ciphersuite.
const THUMBPRINT_HASH: ThumbprintHash = ThumbprintHash::SHA256;

/// Used to compute the MLS thumbprint of a Basic Credential
pub fn compute_raw_key_thumbprint(sign_alg: JwsAlgorithm, signature_public_key: &[u8]) -> acme::Result<String> {
    let key = match sign_alg {
        JwsAlgorithm::ES256 | JwsAlgorithm::ES384 | JwsAlgorithm::ES512 => {
            DecodingKey::from_ec_der(signature_public_key)
        }
        JwsAlgorithm::EdDSA => DecodingKey::from_ed_der(signature_public_key),
    };
    Ok(thumbprint(&key)?)
}

/// See: <https://datatracker.ietf.org/doc/html/rfc8037#appendix-A.3>
pub(crate) fn try_compute_jwk_canonicalized_thumbprint(
    cert: &x509_cert::TbsCertificate,
) -> Result<String, CertificateError> {
    let spki = cert.subject_public_key_info();
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|param| x509_cert::spki::ObjectIdentifier::from_bytes(param.value()).ok());
    let public_key = spki.subject_public_key.raw_bytes();

    let key = match (spki.algorithm.oid, curve) {
        (ID_ED_25519, None) => DecodingKey::from_ed_der(public_key),
        (ID_EC_PUBLIC_KEY, Some(SECP_256_R_1 | SECP_384_R_1 | SECP_521_R_1)) => DecodingKey::from_ec_der(public_key),
        _ => return Err(CertificateError::UnsupportedPublicKey),
    };
    Ok(thumbprint(&key)?)
}

fn thumbprint(key: &DecodingKey) -> JsonWebTokenResult<String> {
    Jwk::from_decoding_key(key, None)?.thumbprint(THUMBPRINT_HASH)
}
