use openmls::prelude::{Credential as MlsCredential, MlsCredentialType, TlsDeserializeTrait as _};
use openmls_basic_credential::SignatureKeyPair;
use openmls_x509_credential::X509Ext as _;
use x509_cert::der::Decode as _;
use zeroize::Zeroize;

use crate::{CryptoKeystoreError, CryptoKeystoreResult, entities::StoredCredential};

/// Entity representing a persisted `Credential`
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub(crate) struct V5Credential {
    #[sensitive]
    pub id: Vec<u8>,
    #[sensitive]
    pub credential: Vec<u8>,
    pub created_at: u64,
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
) -> CryptoKeystoreResult<Option<StoredCredential>> {
    let mls_keypair = SignatureKeyPair::tls_deserialize_exact(&stored_keypair.keypair)
        .map_err(|e| CryptoKeystoreError::MigrationFailed(format!("Deserializing keypair: {e}")))?;

    if !v5_credential_matches_signature_key(v5_credential, stored_keypair, &mls_keypair)? {
        return Ok(None);
    }

    let new_credential = StoredCredential {
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
