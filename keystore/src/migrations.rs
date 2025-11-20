use openmls::prelude::{
    Ciphersuite, Credential as MlsCredential, MlsCredentialType, SignatureScheme, TlsDeserializeTrait as _,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_x509_credential::X509Ext as _;
use x509_cert::der::Decode as _;
use zeroize::Zeroize;

use crate::{CryptoKeystoreError, CryptoKeystoreResult};

/// Entity representing a persisted `Credential` per the schema prior to integrating the signature keypair
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub(crate) struct V5Credential {
    #[sensitive]
    pub id: Vec<u8>,
    #[sensitive]
    pub credential: Vec<u8>,
    pub created_at: u64,
}

/// Entity representing a persisted `Credential` prior to replacing signature scheme with ciphersuite
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub(crate) struct V6Credential {
    /// Note: this is not a unique identifier, but the session id this credential belongs to.
    #[sensitive]
    pub id: Vec<u8>,
    #[sensitive]
    pub credential: Vec<u8>,
    pub created_at: u64,
    pub signature_scheme: u16,
    #[sensitive]
    pub public_key: Vec<u8>,
    #[sensitive]
    pub secret_key: Vec<u8>,
}

/// Entity representing a persisted `SignatureKeyPair`
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub(crate) struct StoredSignatureKeypair {
    pub signature_scheme: u16,
    #[sensitive]
    pub pk: Vec<u8>,
    #[sensitive]
    pub keypair: Vec<u8>,
    #[sensitive]
    pub credential_id: Vec<u8>,
}

/// Try to extract the relevant data from the v5 credential and signature keypair to determine whether they correspond
/// to each other. If succeeding, and they do match, return Ok(Some) with the new credential, return Ok(None) if they
/// don't, and return an Error if the data extraction fails.
pub(crate) fn migrate_to_new_credential(
    v5_credential: &V5Credential,
    stored_keypair: &StoredSignatureKeypair,
) -> CryptoKeystoreResult<Option<V6Credential>> {
    let mls_keypair = SignatureKeyPair::tls_deserialize_exact(&stored_keypair.keypair)
        .map_err(|e| CryptoKeystoreError::MigrationFailed(format!("Deserializing keypair: {e}")))?;

    if !v5_credential_matches_signature_key(v5_credential, stored_keypair, &mls_keypair)? {
        return Ok(None);
    }

    let new_credential = V6Credential {
        id: v5_credential.id.clone(),
        credential: v5_credential.credential.clone(),
        created_at: v5_credential.created_at,
        signature_scheme: stored_keypair.signature_scheme,
        secret_key: mls_keypair.private().to_owned(),
        public_key: stored_keypair.pk.clone(),
    };

    Ok(Some(new_credential))
}

pub(crate) fn v5_credential_matches_signature_key(
    v5_credential: &V5Credential,
    stored_keypair: &StoredSignatureKeypair,
    signature_key: &SignatureKeyPair,
) -> CryptoKeystoreResult<bool> {
    let mls_credential = MlsCredential::tls_deserialize_exact(&v5_credential.credential)
        .map_err(|e| CryptoKeystoreError::MigrationFailed(format!("deserializing stored credential: {e}")))?;

    match mls_credential.mls_credential() {
        MlsCredentialType::Basic(_) => {
            let keypair_identity = &stored_keypair.credential_id;
            if keypair_identity != mls_credential.identity() {
                return Ok(false);
            }
        }

        MlsCredentialType::X509(cert) => {
            let certificate_bytes = cert
                .certificates
                .first()
                .ok_or(CryptoKeystoreError::MigrationFailed("No leaf certificate".into()))?;
            let certificate_inner = x509_cert::Certificate::from_der(certificate_bytes.as_slice())
                .map_err(|e| CryptoKeystoreError::MigrationFailed(format!("decoding x509 certificate: {e}")))?;
            let credential_public_key = certificate_inner
                .public_key()
                .map_err(|e| CryptoKeystoreError::MigrationFailed(format!("extracting public key from cert: {e}")))?;

            if signature_key.public() != credential_public_key {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

/// Inverts [`Credential::signature_algorithm`](https://github.com/wireapp/openmls/blob/c9cde17076508968c9cbead5728454f0a1f60c4f/traits/src/types.rs#L472-L474)
///
/// The general strategy for this migration is simple: we duplicate the old credential for every possible ciphersuite which matches
/// its signature scheme.
///
/// In practice, we expect to see all credentials in use using `SignatureScheme::ECDSA_SECP256R1_SHA256`, which uniquely maps
/// to `Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256`, so we shouldn't see too much duplication. But on the off chance that
/// we find something without a unique mapping, it's less harmful for the database to contain all possibilities including the correct
/// one than for us to guess and possibly leave the database not containing the correct credential.
pub(crate) fn ciphersuites_for_signature_scheme(signature_scheme: u16) -> Vec<u16> {
    let Ok(signature_scheme) = SignatureScheme::try_from(signature_scheme) else {
        return Vec::new();
    };
    match signature_scheme {
        SignatureScheme::ECDSA_SECP256R1_SHA256 => vec![Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.into()],
        SignatureScheme::ECDSA_SECP384R1_SHA384 => vec![Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384.into()],
        SignatureScheme::ECDSA_SECP521R1_SHA512 => vec![Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521.into()],
        SignatureScheme::ED25519 => vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.into(),
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519.into(),
        ],
        SignatureScheme::ED448 => vec![
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448.into(),
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448.into(),
        ],
    }
}
