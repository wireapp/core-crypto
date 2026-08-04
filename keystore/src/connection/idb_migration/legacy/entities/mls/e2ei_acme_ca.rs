use crate::{
    CryptoKeystoreResult,
    connection::idb_migration::legacy::{
        connection::KeystoreDatabaseConnection,
        traits::{
            DecryptData, Decryptable, Decrypting, EncryptData, Encrypting, EntityBase, UniqueEntity as _,
            UniqueEntityImplementationHelper,
        },
    },
    migrations::LegacyE2eiAcmeCA,
};

impl EntityBase for LegacyE2eiAcmeCA {
    type ConnectionType = KeystoreDatabaseConnection;
    const TABLE_NAME: &'static str = "e2ei_acme_ca";

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        panic!("this migration-only entity should never be part of a transaction")
    }
}

impl UniqueEntityImplementationHelper for LegacyE2eiAcmeCA {
    fn new(content: Vec<u8>) -> Self {
        Self { content }
    }
    fn content(&self) -> &[u8] {
        &self.content
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct E2eiAcmeCAEncrypted {
    content: Vec<u8>,
}

impl<'a> Encrypting<'a> for LegacyE2eiAcmeCA {
    type EncryptedForm = E2eiAcmeCAEncrypted;

    fn encrypt(&'a self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Self::EncryptedForm> {
        let content = <Self as EncryptData>::encrypt_data(self, cipher, &self.content)?;
        Ok(E2eiAcmeCAEncrypted { content })
    }
}

impl Decrypting<'static> for E2eiAcmeCAEncrypted {
    type DecryptedForm = LegacyE2eiAcmeCA;

    fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Self::DecryptedForm> {
        let content = <LegacyE2eiAcmeCA as DecryptData>::decrypt_data(cipher, &LegacyE2eiAcmeCA::KEY, &self.content)?;
        Ok(LegacyE2eiAcmeCA { content })
    }
}

impl Decryptable<'static> for LegacyE2eiAcmeCA {
    type DecryptableFrom = E2eiAcmeCAEncrypted;
}
