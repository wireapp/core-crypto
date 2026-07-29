use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore};

use crate::{
    CryptoKeystoreError, Sha256Hash, Transaction, deser,
    entities::{
        PersistedMlsGroup, StoredCredential, StoredEncryptionKeyPair, StoredEpochEncryptionKeypair,
        StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    ser,
    traits::FetchFromDatabase,
};

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl OpenMlsKeyStore for Transaction {
    type Error = CryptoKeystoreError;

    async fn store<V: MlsEntity + Sync>(&self, id: &[u8], value: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        if id.is_empty() {
            return Err(CryptoKeystoreError::MlsKeyStoreError(
                "The provided key is empty".into(),
            ));
        }

        let data = ser(value)?;

        match V::ID {
            MlsEntityId::GroupState => {
                return Err(CryptoKeystoreError::IncorrectApiUsage(
                    "Groups must not be saved using OpenMLS's APIs. You should use the keystore's provided methods",
                ));
            }
            MlsEntityId::SignatureKeyPair => {
                return Err(CryptoKeystoreError::IncorrectApiUsage(
                    "Signature keys must not be saved using OpenMLS's APIs. Save a credential via the keystore API
                    instead.",
                ));
            }
            MlsEntityId::KeyPackage => {
                let kp = StoredKeypackage {
                    keypackage_ref: id.into(),
                    keypackage: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::HpkePrivateKey => {
                let kp = StoredHpkePrivateKey {
                    pk: id.into(),
                    sk: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::PskBundle => {
                let kp = StoredPskBundle {
                    psk_id: id.into(),
                    psk: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp = StoredEncryptionKeyPair {
                    pk: id.into(),
                    sk: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp = StoredEpochEncryptionKeypair {
                    id: id.into(),
                    keypairs: data,
                };
                self.save(kp).await?;
            }
        }

        Ok(())
    }

    async fn read<V: MlsEntity>(&self, id: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        if id.is_empty() {
            return None;
        }

        match V::ID {
            MlsEntityId::GroupState => {
                let v = FetchFromDatabase::get_borrowed::<PersistedMlsGroup>(self, id)
                    .await
                    .ok()
                    .flatten()?;
                deser(&v.state).ok()
            }
            MlsEntityId::SignatureKeyPair => {
                let hash = Sha256Hash::from_existing_hash(id).ok()?;
                let stored_credential = FetchFromDatabase::get::<StoredCredential>(self, &hash)
                    .await
                    .ok()
                    .flatten()?;
                let ciphersuite = Ciphersuite::try_from(stored_credential.ciphersuite).ok()?;
                let signature_scheme = ciphersuite.signature_algorithm();

                let mls_keypair = SignatureKeyPair::from_raw(
                    signature_scheme,
                    stored_credential.private_key.to_vec(),
                    stored_credential.public_key.to_vec(),
                );

                // In a well designed interface, something like this should not be necessary. However, we don't have
                // a well-designed interface.
                let data = ser(&mls_keypair).ok()?;
                deser(&data).ok()
            }
            MlsEntityId::KeyPackage => {
                let v = FetchFromDatabase::get_borrowed::<StoredKeypackage>(self, id)
                    .await
                    .ok()
                    .flatten()?;
                deser(&v.keypackage).ok()
            }
            MlsEntityId::HpkePrivateKey => {
                let v = FetchFromDatabase::get_borrowed::<StoredHpkePrivateKey>(self, id)
                    .await
                    .ok()
                    .flatten()?;
                deser(&v.sk).ok()
            }
            MlsEntityId::PskBundle => {
                let v = FetchFromDatabase::get_borrowed::<StoredPskBundle>(self, id)
                    .await
                    .ok()
                    .flatten()?;
                deser(&v.psk).ok()
            }
            MlsEntityId::EncryptionKeyPair => {
                let v = FetchFromDatabase::get_borrowed::<StoredEncryptionKeyPair>(self, id)
                    .await
                    .ok()
                    .flatten()?;
                deser(&v.sk).ok()
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let v = FetchFromDatabase::get_borrowed::<StoredEpochEncryptionKeypair>(self, id)
                    .await
                    .ok()
                    .flatten()?;
                deser(&v.keypairs).ok()
            }
        }
    }

    async fn delete<V: MlsEntity>(&self, id: &[u8]) -> Result<(), Self::Error> {
        match V::ID {
            MlsEntityId::GroupState => self.remove_borrowed::<PersistedMlsGroup>(id).await?,
            MlsEntityId::SignatureKeyPair => unimplemented!(
                "Deleting a signature key pair should not be done through this API, any keypair should be deleted via
                deleting a credential."
            ),
            MlsEntityId::HpkePrivateKey => self.remove_borrowed::<StoredHpkePrivateKey>(id).await?,
            MlsEntityId::KeyPackage => self.remove_borrowed::<StoredKeypackage>(id).await?,
            MlsEntityId::PskBundle => self.remove_borrowed::<StoredPskBundle>(id).await?,
            MlsEntityId::EncryptionKeyPair => self.remove_borrowed::<StoredEncryptionKeyPair>(id).await?,
            MlsEntityId::EpochEncryptionKeyPair => self.remove_borrowed::<StoredEpochEncryptionKeypair>(id).await?,
        }

        Ok(())
    }
}
