use super::aad::{AES_GCM_256_NONCE_SIZE, Aad};
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult,
    traits::{EncryptionKey, Entity, EntityDeleteBorrowed, KeyType as _},
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

/// This trait uses an explicitly-set decryption key to decrypt some data.
///
/// This should rarely be used.
pub trait DecryptWithExplicitEncryptionKey {
    /// Decrypt some data with an encryption key (see [`EncryptionKey`]) instead of the instance's primary key.
    fn decrypt_data_with_encryption_key(
        cipher: &aes_gcm::Aes256Gcm,
        encryption_key: &[u8],
        data: &[u8],
    ) -> CryptoKeystoreResult<Vec<u8>>;
}

impl<E> DecryptWithExplicitEncryptionKey for E
where
    E: Entity + EncryptionKey,
{
    fn decrypt_data_with_encryption_key(
        cipher: &aes_gcm::Aes256Gcm,
        encryption_key: &[u8],
        data: &[u8],
    ) -> CryptoKeystoreResult<Vec<u8>> {
        let aad = Aad::from_encryption_key_bytes::<E>(encryption_key).serialize()?;
        let (nonce, msg) = data
            .split_at_checked(AES_GCM_256_NONCE_SIZE)
            .ok_or(CryptoKeystoreError::AesGcmError)?;
        decrypt_with_nonce_and_aad(cipher, msg, nonce, &aad)
    }
}
