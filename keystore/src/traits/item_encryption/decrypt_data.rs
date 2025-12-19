use super::aad::{AES_GCM_256_NONCE_SIZE, Aad};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    traits::{Entity, EntityDeleteBorrowed, KeyType as _},
};

fn decrypt_with_nonce_and_aad(
    cipher: &aes_gcm::Aes256Gcm,
    msg: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> CryptoKeystoreResult<Vec<u8>> {
    use aes_gcm::aead::Aead as _;

    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload { msg, aad };

    let cleartext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoKeystoreError::AesGcmError)?;

    Ok(cleartext)
}

/// This trait is intended to provide a convenient way to decrypt data.
///
/// There is a blanket implementation covering all [`Entity`]s.
pub trait DecryptData: Entity {
    /// Decrypt some data, symmetrically to the process [`encrypt_data`][super::EncryptData::encrypt_data] uses.
    fn decrypt_data(
        cipher: &aes_gcm::Aes256Gcm,
        primary_key: &Self::PrimaryKey,
        data: &[u8],
    ) -> CryptoKeystoreResult<Vec<u8>>;
}

impl<E: Entity> DecryptData for E {
    fn decrypt_data(
        cipher: &aes_gcm::Aes256Gcm,
        primary_key: &E::PrimaryKey,
        data: &[u8],
    ) -> CryptoKeystoreResult<Vec<u8>> {
        let aad = Aad::from_primary_key::<E>(primary_key).serialize()?;
        let (nonce, msg) = data
            .split_at_checked(AES_GCM_256_NONCE_SIZE)
            .ok_or(CryptoKeystoreError::AesGcmError)?;
        decrypt_with_nonce_and_aad(cipher, msg, nonce, &aad)
    }
}
