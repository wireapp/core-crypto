use mls_rs_core::group::{EpochRecord, GroupState};
use mls_rs_core::psk::PreSharedKey as MlsRsPsk;
use mls_rs_core::{key_package::KeyPackageData as MlsRsKeyPackageData, psk::ExternalPskId};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};

use crate::entities::{Entity, Group, Psk};
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
impl mls_rs_core::group::GroupStateStorage for Connection {
    type Error = CryptoKeystoreError;

    async fn state(&self, group_id: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        self.find::<Group>(group_id)
            .await?
            .map(|keystore_instance| keystore_instance.snapshot.clone())
            .map(Ok)
            .transpose()
    }

    async fn epoch(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Vec<u8>>, Self::Error> {
        self.find_epoch(group_id, epoch_id)
            .await?
            .map(|keystore_instance| keystore_instance.epoch_data.clone())
            .map(Ok)
            .transpose()
    }

    async fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        let transaction_guard = self.transaction.lock().await;
        let Some(transaction) = transaction_guard.as_ref() else {
            return Err(CryptoKeystoreError::MutatingOperationWithoutTransaction);
        };

        // Upsert into the group table to set the most recent snapshot
        transaction.save_mut::<Group>(state.clone().into()).await?;

        // Upsert new epochs as needed
        let mut max_epoch_id = None;
        for epoch in epoch_inserts {
            max_epoch_id = Some(epoch.id);
            transaction.save_epoch((state.id.clone(), epoch).into()).await?;
        }

        // Upsert existing epochs as needed
        for epoch in epoch_updates {
            transaction.save_epoch((state.id.clone(), epoch).into()).await?;
        }

        // Delete old epochs as needed
        if let Some(max_epoch_id) = max_epoch_id
            && max_epoch_id >= self.max_epoch_retention
        {
            let delete_less_equal = max_epoch_id - self.max_epoch_retention;
            transaction
                .delete_epoch_by_id_less_equal(state.id.as_slice(), delete_less_equal)
                .await?;
        }

        Ok(())
    }

    async fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        self.max_epoch_id(group_id).await
    }
}

#[maybe_async::must_be_async]
impl mls_rs_core::key_package::KeyPackageStorage for Connection {
    type Error = CryptoKeystoreError;

    async fn insert(&mut self, id: Vec<u8>, pkg: MlsRsKeyPackageData) -> CryptoKeystoreResult<()> {
        let keystore_instance = (id, pkg).try_into()?;
        self.save::<KeyPackageData>(keystore_instance).await?;
        Ok(())
    }

    async fn get(&self, id: &[u8]) -> CryptoKeystoreResult<Option<MlsRsKeyPackageData>> {
        let maybe_record = self.find::<KeyPackageData>(&KeyPackageData::to_entity_id(id)?).await?;
        maybe_record
            .map(|keystore_instance| {
                let (_, mls_rs_instance) = keystore_instance.try_into()?;
                Ok(mls_rs_instance)
            })
            .transpose()
    }

    async fn delete(&mut self, id: &[u8]) -> CryptoKeystoreResult<()> {
        self.remove::<KeyPackageData>(&KeyPackageData::to_entity_id(id)?).await
    }
}

#[maybe_async::must_be_async]
impl mls_rs_core::psk::PreSharedKeyStorage for Connection {
    type Error = CryptoKeystoreError;

    async fn get(&self, id: &ExternalPskId) -> CryptoKeystoreResult<Option<MlsRsPsk>> {
        let maybe_record = self.find::<Psk>(&Psk::to_entity_id(id)?).await?;
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
                let group: PersistedMlsGroup = self
                    .find(&PersistedMlsGroup::to_entity_id(k).ok()?)
                    .await
                    .ok()
                    .flatten()?;
                deser(&group.state).ok()
            }
            MlsEntityId::SignatureKeyPair => {
                let sig: MlsSignatureKeyPair = self
                    .find(&MlsSignatureKeyPair::to_entity_id(k).ok()?)
                    .await
                    .ok()
                    .flatten()?;
                deser(&sig.keypair).ok()
            }
            MlsEntityId::KeyPackage => {
                let kp: MlsKeyPackage = self.find(&MlsKeyPackage::to_entity_id(k).ok()?).await.ok().flatten()?;
                deser(&kp.keypackage).ok()
            }
            MlsEntityId::HpkePrivateKey => {
                let hpke_pk: MlsHpkePrivateKey = self
                    .find(&MlsHpkePrivateKey::to_entity_id(k).ok()?)
                    .await
                    .ok()
                    .flatten()?;
                deser(&hpke_pk.sk).ok()
            }
            MlsEntityId::PskBundle => {
                let psk_bundle: MlsPskBundle = self.find(&MlsPskBundle::to_entity_id(k).ok()?).await.ok().flatten()?;
                deser(&psk_bundle.psk).ok()
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp: MlsEncryptionKeyPair = self
                    .find(&MlsEncryptionKeyPair::to_entity_id(k).ok()?)
                    .await
                    .ok()
                    .flatten()?;
                deser(&kp.sk).ok()
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp: MlsEpochEncryptionKeyPair = self
                    .find(&MlsEpochEncryptionKeyPair::to_entity_id(k).ok()?)
                    .await
                    .ok()
                    .flatten()?;
                deser(&kp.keypairs).ok()
            }
        }
    }

    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        match V::ID {
            MlsEntityId::GroupState => {
                self.remove::<PersistedMlsGroup>(&PersistedMlsGroup::to_entity_id(k)?)
                    .await?
            }
            MlsEntityId::SignatureKeyPair => {
                self.remove::<MlsSignatureKeyPair>(&MlsSignatureKeyPair::to_entity_id(k)?)
                    .await?
            }
            MlsEntityId::HpkePrivateKey => {
                self.remove::<MlsHpkePrivateKey>(&MlsHpkePrivateKey::to_entity_id(k)?)
                    .await?
            }
            MlsEntityId::KeyPackage => self.remove::<MlsKeyPackage>(&KeyPackageData::to_entity_id(k)?).await?,
            MlsEntityId::PskBundle => self.remove::<MlsPskBundle>(&KeyPackageData::to_entity_id(k)?).await?,
            MlsEntityId::EncryptionKeyPair => {
                self.remove::<MlsEncryptionKeyPair>(&MlsEncryptionKeyPair::to_entity_id(k)?)
                    .await?
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                self.remove::<MlsEpochEncryptionKeyPair>(&MlsEpochEncryptionKeyPair::to_entity_id(k)?)
                    .await?
            }
        }

        Ok(())
    }
}
