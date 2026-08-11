use zeroize::Zeroize;

use crate::CryptoKeystoreResult;
use crate::connection::idb_migration::legacy::connection::KeystoreDatabaseConnection;
use crate::connection::idb_migration::legacy::traits::DecryptData;
use crate::connection::idb_migration::legacy::traits::Decryptable;
use crate::connection::idb_migration::legacy::traits::Decrypting;
use crate::connection::idb_migration::legacy::traits::EncryptData;
use crate::connection::idb_migration::legacy::traits::Encrypting;
use crate::connection::idb_migration::legacy::traits::EntityBase;
use crate::connection::idb_migration::legacy::traits::UniqueEntity as _;
use crate::connection::idb_migration::legacy::traits::UniqueEntityImplementationHelper;

#[cfg(target_os = "unknown")]
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct E2eiAcmeCA {
    pub content: Vec<u8>,
}

impl EntityBase for E2eiAcmeCA {
    type ConnectionType = KeystoreDatabaseConnection;
    const TABLE_NAME: &'static str = "e2ei_acme_ca";

    fn to_transaction_entity(self) -> crate::transaction::dynamic_dispatch::Entity {
        panic!("this migration-only entity should never be part of a transaction")
    }
}

impl UniqueEntityImplementationHelper for E2eiAcmeCA {
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

impl<'a> Encrypting<'a> for E2eiAcmeCA {
    type EncryptedForm = E2eiAcmeCAEncrypted;

    fn encrypt(&'a self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Self::EncryptedForm> {
        let content = <Self as EncryptData>::encrypt_data(self, cipher, &self.content)?;
        Ok(E2eiAcmeCAEncrypted { content })
    }
}

impl Decrypting<'static> for E2eiAcmeCAEncrypted {
    type DecryptedForm = E2eiAcmeCA;

    fn decrypt(self, cipher: &aes_gcm::Aes256Gcm) -> CryptoKeystoreResult<Self::DecryptedForm> {
        let content = <E2eiAcmeCA as DecryptData>::decrypt_data(cipher, &E2eiAcmeCA::KEY, &self.content)?;
        Ok(E2eiAcmeCA { content })
    }
}

impl Decryptable<'static> for E2eiAcmeCA {
    type DecryptableFrom = E2eiAcmeCAEncrypted;
}

impl crate::traits::UniqueEntityImplementationHelper for E2eiAcmeCA {
    const TABLE_NAME: &'static str = "e2ei_acme_ca";
    fn new(content: Vec<u8>) -> Self {
        Self { content }
    }

    fn content(&self) -> &[u8] {
        &self.content
    }
}

impl From<E2eiAcmeCA> for crate::transaction::dynamic_dispatch::Entity {
    fn from(_value: E2eiAcmeCA) -> Self {
        panic!("This entity should never be used in a transaction")
    }
}
