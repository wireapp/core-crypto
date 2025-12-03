use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};

use crate::{
    CryptoKeystoreError,
    entities::{
        PersistedMlsGroup, StoredCredential, StoredEncryptionKeyPair, StoredEpochEncryptionKeypair,
        StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
};

#[inline(always)]
pub fn deser<T: MlsEntity>(bytes: &[u8]) -> Result<T, CryptoKeystoreError> {
    Ok(postcard::from_bytes(bytes)?)
}

#[inline(always)]
pub fn ser<T: MlsEntity>(value: &T) -> Result<Vec<u8>, CryptoKeystoreError> {
    Ok(postcard::to_stdvec(value)?)
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl openmls_traits::key_store::OpenMlsKeyStore for crate::connection::Database {
    type Error = CryptoKeystoreError;

    async fn store<V: MlsEntity + Sync>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        if k.is_empty() {
            return Err(CryptoKeystoreError::MlsKeyStoreError(
                "The provided key is empty".into(),
            ));
        }

        let data = ser(v)?;

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
                    keypackage_ref: k.into(),
                    keypackage: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::HpkePrivateKey => {
                let kp = StoredHpkePrivateKey { pk: k.into(), sk: data };
                self.save(kp).await?;
            }
            MlsEntityId::PskBundle => {
                let kp = StoredPskBundle {
                    psk_id: k.into(),
                    psk: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp = StoredEncryptionKeyPair { pk: k.into(), sk: data };
                self.save(kp).await?;
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp = StoredEpochEncryptionKeypair {
                    id: k.into(),
                    keypairs: data,
                };
                self.save(kp).await?;
            }
        }

        Ok(())
    }

    async fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        if k.is_empty() {
            return None;
        }

        match V::ID {
            MlsEntityId::GroupState => {
                let group: PersistedMlsGroup = self.find(k).await.ok().flatten()?;
                deser(&group.state).ok()
            }
            MlsEntityId::SignatureKeyPair => {
                let stored_credential = self.find::<StoredCredential>(k).await.ok().flatten()?;
                let ciphersuite = Ciphersuite::try_from(stored_credential.ciphersuite).ok()?;
                let signature_scheme = ciphersuite.signature_algorithm();

                let mls_keypair = SignatureKeyPair::from_raw(
                    signature_scheme,
                    stored_credential.secret_key.to_vec(),
                    stored_credential.public_key.to_vec(),
                );

                // In a well designed interface, something like this should not be necessary. However, we don't have
                // a well-designed interface.
                let mls_keypair_serialized = ser(&mls_keypair).ok()?;
                deser(&mls_keypair_serialized).ok()
            }
            MlsEntityId::KeyPackage => {
                let kp: StoredKeypackage = self.find(k).await.ok().flatten()?;
                deser(&kp.keypackage).ok()
            }
            MlsEntityId::HpkePrivateKey => {
                let hpke_pk: StoredHpkePrivateKey = self.find(k).await.ok().flatten()?;
                deser(&hpke_pk.sk).ok()
            }
            MlsEntityId::PskBundle => {
                let psk_bundle: StoredPskBundle = self.find(k).await.ok().flatten()?;
                deser(&psk_bundle.psk).ok()
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp: StoredEncryptionKeyPair = self.find(k).await.ok().flatten()?;
                deser(&kp.sk).ok()
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp: StoredEpochEncryptionKeypair = self.find(k).await.ok().flatten()?;
                deser(&kp.keypairs).ok()
            }
        }
    }

    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        match V::ID {
            MlsEntityId::GroupState => self.remove::<PersistedMlsGroup, _>(k).await?,
            MlsEntityId::SignatureKeyPair => unimplemented!(
                "Deleting a signature key pair should not be done through this API, any keypair should be deleted via
                deleting a credential."
            ),
            MlsEntityId::HpkePrivateKey => self.remove::<StoredHpkePrivateKey, _>(k).await?,
            MlsEntityId::KeyPackage => self.remove::<StoredKeypackage, _>(k).await?,
            MlsEntityId::PskBundle => self.remove::<StoredPskBundle, _>(k).await?,
            MlsEntityId::EncryptionKeyPair => self.remove::<StoredEncryptionKeyPair, _>(k).await?,
            MlsEntityId::EpochEncryptionKeyPair => self.remove::<StoredEpochEncryptionKeypair, _>(k).await?,
        }

        Ok(())
    }
}
