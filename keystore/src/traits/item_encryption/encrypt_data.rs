use crate::{CryptoKeystoreError, CryptoKeystoreResult, traits::Entity};

use super::aad::{AES_GCM_256_NONCE_SIZE, Aad};

// About WASM Encryption:
// The store key (i.e. passphrase) is hashed using SHA256 to obtain 32 bytes
// The AES256-GCM cipher is then initialized and is used to encrypt individual values
// Entities shall decide which fields need to be encrypted
// Internal layout:
// - Cleartext: [u8] bytes
// - Ciphertext: [12 bytes of nonce..., ...encrypted data]
fn encrypt_with_nonce_and_aad(
    cipher: &aes_gcm::Aes256Gcm,
    msg: &[u8],
    nonce: &[u8],
    aad: &[u8],
) -> CryptoKeystoreResult<Vec<u8>> {
    use aes_gcm::aead::Aead as _;

    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let payload = aes_gcm::aead::Payload { msg, aad };

    let mut encrypted = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoKeystoreError::AesGcmError)?;
    let mut message = Vec::with_capacity(nonce.len() + encrypted.len());
    message.extend_from_slice(nonce);
    message.append(&mut encrypted);
    Ok(message)
}

/// This trait is intended to provide a convenient way to encrypt data.
///
/// The encryption process embeds both a nonce and an AAD: an identity comprising
/// both the entity's type and a unique identifier.
///
/// There is a blanket implementation covering all [`Entity`]s.
pub trait EncryptData {
    /// Encrypt some data, using a random nonce and an AAD.
    fn encrypt_data(&self, cipher: &aes_gcm::Aes256Gcm, data: &[u8]) -> CryptoKeystoreResult<Vec<u8>>;
}

impl<E: Entity> EncryptData for E {
    fn encrypt_data(&self, cipher: &aes_gcm::Aes256Gcm, data: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
        let aad = Aad::from(self).serialize()?;
        let nonce_bytes: [u8; AES_GCM_256_NONCE_SIZE] = rand::random();
        encrypt_with_nonce_and_aad(cipher, data, &nonce_bytes, &aad)
    }
}
