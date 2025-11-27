use async_trait::async_trait;

const AES_GCM_256_NONCE_SIZE: usize = 12;

#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Aad {
    type_name: Vec<u8>,
    id: Vec<u8>,
}

/// Entity-level encryption extensions
///
/// This trait should be removed once we have moved away from the IDB backend
/// into some (hopefully unified) database backend which supports database-level
/// encryption at rest. See WPB-16241.
#[async_trait(?Send)]
pub trait EntityEncryptionExt: Entity {
    fn aad(&self) -> CryptoKeystoreResult<Vec<u8>> {
        let aad = Aad {
            type_name: Self::COLLECTION_NAME.as_bytes().to_vec(),
            id: self.id_raw().into(),
        };
        serde_json::to_vec(&aad).map_err(Into::into)
    }

    // About WASM Encryption:
    // The store key (i.e. passphrase) is hashed using SHA256 to obtain 32 bytes
    // The AES256-GCM cipher is then initialized and is used to encrypt individual values
    // Entities shall decide which fields need to be encrypted
    // Internal layout:
    // - Cleartext: [u8] bytes
    // - Ciphertext: [12 bytes of nonce..., ...encrypted data]
    fn encrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()>;
    fn encrypt_with_nonce_and_aad(
        cipher: &aes_gcm::Aes256Gcm,
        data: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> CryptoKeystoreResult<Vec<u8>> {
        use aes_gcm::aead::Aead as _;
        let nonce = aes_gcm::Nonce::from_slice(nonce);
        let msg = data;
        let payload = aes_gcm::aead::Payload { msg, aad };

        let mut encrypted = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoKeystoreError::AesGcmError)?;
        let mut message = Vec::with_capacity(nonce.len() + encrypted.len());
        message.extend_from_slice(nonce);
        message.append(&mut encrypted);
        Ok(message)
    }

    fn encrypt_data(&self, cipher: &aes_gcm::Aes256Gcm, data: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
        let nonce_bytes: [u8; AES_GCM_256_NONCE_SIZE] = rand::random();
        Self::encrypt_with_nonce_and_aad(cipher, data, &nonce_bytes, &self.aad()?)
    }

    fn decrypt(&mut self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<()>;
    fn decrypt_data(&self, cipher: &aes_gcm::Aes256Gcm, data: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
        use aes_gcm::aead::Aead as _;

        if data.is_empty() {
            return Err(CryptoKeystoreError::MissingKeyInStore(Self::to_missing_key_err_kind()));
        }
        if data.len() < AES_GCM_256_NONCE_SIZE {
            return Err(CryptoKeystoreError::AesGcmError);
        }

        let nonce_bytes = &data[..AES_GCM_256_NONCE_SIZE];
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        let msg = &data[AES_GCM_256_NONCE_SIZE..];
        let aad = &self.aad()?;
        let payload = aes_gcm::aead::Payload { msg, aad };
        let cleartext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoKeystoreError::AesGcmError)?;
        Ok(cleartext)
    }
}
