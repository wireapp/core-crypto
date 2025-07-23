use mls_rs_core::psk::PreSharedKey as MlsRsPsk;
use mls_rs_core::{key_package::KeyPackageData as MlsRsKeyPackageData, psk::ExternalPskId};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};

use crate::entities::Psk;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, deser,
    entities::{
        KeyPackageData, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage,
        MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup,
    },
    ser,
};

use super::{Connection, FetchFromDatabase as _};

#[maybe_async::must_be_async]
impl mls_rs_core::key_package::KeyPackageStorage for Connection {
    type Error = CryptoKeystoreError;

    async fn insert(&mut self, id: Vec<u8>, pkg: MlsRsKeyPackageData) -> CryptoKeystoreResult<()> {
        let keystore_instance = (id, pkg).try_into()?;
        self.save::<KeyPackageData>(keystore_instance).await?;
        Ok(())
    }

    async fn get(&self, id: &[u8]) -> CryptoKeystoreResult<Option<MlsRsKeyPackageData>> {
        let maybe_record = self.find::<KeyPackageData>(id).await?;
        maybe_record
            .map(|keystore_instance| {
                let (_, mls_rs_instance) = keystore_instance.try_into()?;
                Ok(mls_rs_instance)
            })
            .transpose()
    }

    async fn delete(&mut self, id: &[u8]) -> CryptoKeystoreResult<()> {
        self.remove::<KeyPackageData, _>(id).await
    }
}

#[maybe_async::must_be_async]
impl mls_rs_core::psk::PreSharedKeyStorage for Connection {
    type Error = CryptoKeystoreError;

    async fn get(&self, id: &ExternalPskId) -> CryptoKeystoreResult<Option<MlsRsPsk>> {
        let maybe_record = self.find::<Psk>(id).await?;
        maybe_record
            .map(|keystore_instance| {
                let (_, mls_rs_instance) = keystore_instance.try_into()?;
                Ok(mls_rs_instance)
            })
            .transpose()
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl openmls_traits::key_store::OpenMlsKeyStore for crate::connection::Connection {
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
                let concrete_signature_keypair: &SignatureKeyPair = v
                    .downcast()
                    .expect("There's an implementation issue in OpenMLS. This shouln't be happening.");

                // Having an empty credential id seems tolerable, since the SignatureKeyPair type is retrieved from the key store via its public key.
                let credential_id = vec![];
                let kp = MlsSignatureKeyPair::new(
                    concrete_signature_keypair.signature_scheme(),
                    k.into(),
                    data,
                    credential_id,
                );
                self.save(kp).await?;
            }
            MlsEntityId::KeyPackage => {
                let kp = MlsKeyPackage {
                    keypackage_ref: k.into(),
                    keypackage: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::HpkePrivateKey => {
                let kp = MlsHpkePrivateKey { pk: k.into(), sk: data };
                self.save(kp).await?;
            }
            MlsEntityId::PskBundle => {
                let kp = MlsPskBundle {
                    psk_id: k.into(),
                    psk: data,
                };
                self.save(kp).await?;
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp = MlsEncryptionKeyPair { pk: k.into(), sk: data };
                self.save(kp).await?;
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp = MlsEpochEncryptionKeyPair {
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
                let sig: MlsSignatureKeyPair = self.find(k).await.ok().flatten()?;
                deser(&sig.keypair).ok()
            }
            MlsEntityId::KeyPackage => {
                let kp: MlsKeyPackage = self.find(k).await.ok().flatten()?;
                deser(&kp.keypackage).ok()
            }
            MlsEntityId::HpkePrivateKey => {
                let hpke_pk: MlsHpkePrivateKey = self.find(k).await.ok().flatten()?;
                deser(&hpke_pk.sk).ok()
            }
            MlsEntityId::PskBundle => {
                let psk_bundle: MlsPskBundle = self.find(k).await.ok().flatten()?;
                deser(&psk_bundle.psk).ok()
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp: MlsEncryptionKeyPair = self.find(k).await.ok().flatten()?;
                deser(&kp.sk).ok()
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp: MlsEpochEncryptionKeyPair = self.find(k).await.ok().flatten()?;
                deser(&kp.keypairs).ok()
            }
        }
    }

    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        match V::ID {
            MlsEntityId::GroupState => self.remove::<PersistedMlsGroup, _>(k).await?,
            MlsEntityId::SignatureKeyPair => self.remove::<MlsSignatureKeyPair, _>(k).await?,
            MlsEntityId::HpkePrivateKey => self.remove::<MlsHpkePrivateKey, _>(k).await?,
            MlsEntityId::KeyPackage => self.remove::<MlsKeyPackage, _>(k).await?,
            MlsEntityId::PskBundle => self.remove::<MlsPskBundle, _>(k).await?,
            MlsEntityId::EncryptionKeyPair => self.remove::<MlsEncryptionKeyPair, _>(k).await?,
            MlsEntityId::EpochEncryptionKeyPair => self.remove::<MlsEpochEncryptionKeyPair, _>(k).await?,
        }

        Ok(())
    }
}
