use certval::ExtensionProcessing as _;
use rusty_jwt_tools::{
    jsonwebtoken::DecodingKey,
    prelude::{JwsAlgorithm, Pem},
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::ext::pkix::AuthorityKeyIdentifier;

use crate::{error::E2eIdentityResult, validation};

pub fn generate_key(sign_alg: JwsAlgorithm) -> E2eIdentityResult<Pem> {
    Ok(sign_alg.generate_keypair()?)
}

pub fn pem_from_bytes(bytes: &[u8], sign_alg: JwsAlgorithm) -> E2eIdentityResult<Pem> {
    Ok(sign_alg.keypair_from_bytes(bytes)?)
}

/// The public key of `keypair`, as an uncompressed SEC1 point for ECDSA and as the 32 byte key for EdDSA
pub(crate) fn public_key_bytes(alg: JwsAlgorithm, keypair: &Pem) -> E2eIdentityResult<Vec<u8>> {
    let jwk = alg.public_jwk(keypair)?;
    Ok(DecodingKey::from_jwk(&jwk)?.try_get_as_bytes()?.to_vec())
}

pub(crate) fn jws_alg_to_x509_identifier(alg: JwsAlgorithm) -> AlgorithmIdentifierOwned {
    match alg {
        JwsAlgorithm::EdDSA => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc8410::ID_ED_25519,
            parameters: None,
        },
        JwsAlgorithm::ES256 => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(const_oid::db::rfc5912::SECP_256_R_1.into()),
        },
        JwsAlgorithm::ES384 => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(const_oid::db::rfc5912::SECP_384_R_1.into()),
        },
        JwsAlgorithm::ES512 => AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
            parameters: Some(const_oid::db::rfc5912::SECP_521_R_1.into()),
        },
    }
}

pub(crate) fn extract_ski_aki_from_cert(cert: &x509_cert::Certificate) -> validation::Result<(String, Option<String>)> {
    let cert = certval::PDVCertificate::try_from(cert.clone())?;

    let ski = cert
        .get_extension(&const_oid::db::rfc5912::ID_CE_SUBJECT_KEY_IDENTIFIER)?
        .ok_or(validation::Error::MissingSki)?;
    let ski = match ski {
        certval::PDVExtension::SubjectKeyIdentifier(ski) => hex::encode(ski.0.as_bytes()),
        _ => return Err(validation::Error::ImplementationError),
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
