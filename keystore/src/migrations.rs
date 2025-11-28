use openmls::{
    group::MlsGroup,
    prelude::{Ciphersuite, Credential as MlsCredential, MlsCredentialType, SignatureScheme, TlsDeserializeTrait as _},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_x509_credential::X509Ext as _;
use x509_cert::der::Decode as _;
use zeroize::Zeroize;

use crate::{CryptoKeystoreError, CryptoKeystoreResult, deser, entities::PersistedMlsGroup};

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

/// Make a function which inverts [`Credential::signature_algorithm`](https://github.com/wireapp/openmls/blob/c9cde17076508968c9cbead5728454f0a1f60c4f/traits/src/types.rs#L472-L474)
///
/// We need to map a signature scheme to a ciphersuite in our migrations. Most of these mappings are unambiguous.
/// However, we still need to consider the possibility that users are using unexpected signature schemes.
///
/// The strategy here is to perform an analysis of the existing conversations, counting the ciphersuites actually in use.
/// For each ambiguous signature scheme, there are these possibilities to consider:
///
/// | Ciphersuite A | Ciphersuite B | Outcome |
/// |---------------|---------------|---------|
/// |             0 |             0 | Ciphersuite unused, drop this credential |
/// |      non-zero |             0 | As all conversations use ciphersuite A, it is safe to uniquely map the credential to this ciphersuite |
/// |             0 |      non-zero | As all conversations use ciphersuite B, it is safe to uniquely map the credential to this ciphersuite |
/// |    non-zero n |    non-zero n | We arbitrarily choose the ciphersuite with smaller canonical number, breaking half the user conversations |
/// |    non-zero a |    non-zero b | We choose the ciphersuite with the greater population, breaking those conversations with the lesser |
///
/// However, we expect the cases where both A and B have non-zero counts to be very rare.
pub(crate) fn make_ciphersuite_for_signature_scheme(
    persisted_mls_groups: impl IntoIterator<Item = PersistedMlsGroup>,
) -> CryptoKeystoreResult<impl Fn(u16) -> Option<u16>> {
    let mut ed25519_aes = 0; // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    let mut ed25519_chacha = 0; // MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    let mut ed448_aes = 0; // MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448
    let mut ed448_chacha = 0; // MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448

    for mls_group in persisted_mls_groups {
        let mls_group = deser::<MlsGroup>(&mls_group.state)?;
        match mls_group.ciphersuite() {
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => ed25519_aes += 1,
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => ed25519_chacha += 1,
            Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448 => ed448_aes += 1,
            Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => ed448_chacha += 1,
            _ => {}
        }
    }

    let ed25519 = match (ed25519_aes, ed25519_chacha) {
        (0, 0) => None,
        // other 0 cases are degenerate and handled below
        (a, b) if a >= b => Some(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.into()),
        _ => Some(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519.into()),
    };

    let ed448 = match (ed448_aes, ed448_chacha) {
        (0, 0) => None,
        // other 0 cases are degenerate and handled below
        (a, b) if a >= b => Some(Ciphersuite::MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448.into()),
        _ => Some(Ciphersuite::MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448.into()),
    };

    let ciphersuite_for_signature_scheme = move |signature_scheme: u16| -> Option<u16> {
        let signature_scheme = SignatureScheme::try_from(signature_scheme).ok()?;
        match signature_scheme {
            SignatureScheme::ECDSA_SECP256R1_SHA256 => {
                Some(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256.into())
            }
            SignatureScheme::ECDSA_SECP384R1_SHA384 => {
                Some(Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384.into())
            }
            SignatureScheme::ECDSA_SECP521R1_SHA512 => {
                Some(Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521.into())
            }
            SignatureScheme::ED25519 => ed25519,
            SignatureScheme::ED448 => ed448,
        }
    };
    Ok(ciphersuite_for_signature_scheme)
}
