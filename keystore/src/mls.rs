use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Sha256Hash,
    entities::{
        PersistedMlsGroup, PersistedMlsPendingGroup, StoredCredential, StoredE2eiEnrollment, StoredEncryptionKeyPair,
        StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::{FetchFromDatabase, UnifiedEntity as _, UnifiedEntityGetBorrowed as _},
};

impl crate::Database {
    /// Fetches Keypackages
    ///
    /// # Arguments
    /// * `count` - amount of entries to be returned
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    pub async fn mls_fetch_key_packages<V: MlsEntity>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>> {
        let keypackages = StoredKeypackage::load_all(&*self.conn().await)?;
        Ok(keypackages
            .into_iter()
            .filter_map(|kpb| postcard::from_bytes(&kpb.keypackage).ok())
            .take(count as _)
            .collect())
    }

    /// Checks if the given MLS group id exists in the keystore
    /// Note: in case of any error, this will return false
    ///
    /// # Arguments
    /// * `group_id` - group/conversation id
    pub async fn mls_group_exists(&self, group_id: impl AsRef<[u8]> + Send) -> bool {
        matches!(
            PersistedMlsGroup::get_borrowed(&*self.conn().await, group_id.as_ref()),
            Ok(Some(_))
        )
    }

    /// Persists a `MlsGroup`
    ///
    /// # Arguments
    /// * `group_id` - group/conversation id
    /// * `state` - the group state
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    pub async fn mls_group_persist(
        &self,
        group_id: impl AsRef<[u8]> + Send,
        state: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()> {
        self.transactionally(async |tx| {
            tx.save(PersistedMlsGroup {
                id: group_id.as_ref().to_owned(),
                state: state.into(),
                parent_id: parent_group_id.map(Into::into),
            })
            .await
        })
        .await
    }

    /// Loads `MlsGroups` from the database. It will be returned as a `HashMap` where the key is
    /// the group/conversation id and the value the group state
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    pub async fn mls_groups_restore(
        &self,
    ) -> CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, (Option<Vec<u8>>, Vec<u8>)>> {
        let groups = PersistedMlsGroup::load_all(&*self.conn().await)?;
        Ok(groups
            .into_iter()
            .map(|mut group| {
                let id = std::mem::take(&mut group.id);
                let parent_id = std::mem::take(&mut group.parent_id);
                let state = std::mem::take(&mut group.state);
                (id, (parent_id, state))
            })
            .collect())
    }

    /// Deletes `MlsGroups` from the database.
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    pub async fn mls_group_delete(&self, group_id: impl AsRef<[u8]> + Send) -> CryptoKeystoreResult<()> {
        self.transactionally(async |tx| tx.remove_borrowed::<PersistedMlsGroup>(group_id.as_ref()).await)
            .await?;
        Ok(())
    }

    /// Saves a `MlsGroup` in a temporary table (typically used in scenarios where the group cannot
    /// be committed until the backend acknowledges it, like external commits)
    ///
    /// # Arguments
    /// * `group_id` - group/conversation id
    /// * `mls_group` - the group/conversation state
    /// * `custom_configuration` - local group configuration
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    pub async fn mls_pending_groups_save(
        &self,
        group_id: impl AsRef<[u8]> + Send,
        mls_group: &[u8],
        custom_configuration: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()> {
        self.transactionally(async |tx| {
            tx.save(PersistedMlsPendingGroup {
                id: group_id.as_ref().to_owned(),
                state: mls_group.into(),
                custom_configuration: custom_configuration.into(),
                parent_id: parent_group_id.map(Into::into),
            })
            .await
        })
        .await?;
        Ok(())
    }

    /// Loads a temporary `MlsGroup` and its configuration from the database
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    pub async fn mls_pending_groups_load(
        &self,
        group_id: impl AsRef<[u8]> + Send,
    ) -> CryptoKeystoreResult<Option<(Vec<u8>, Vec<u8>)>> {
        let optional = PersistedMlsPendingGroup::get_borrowed(&*self.conn().await, group_id.as_ref())?;
        Ok(optional.map(|pending_group| (pending_group.state.clone(), pending_group.custom_configuration.clone())))
    }

    /// Deletes a temporary `MlsGroup` from the database
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    pub async fn mls_pending_groups_delete(&self, group_id: impl AsRef<[u8]> + Send) -> CryptoKeystoreResult<()> {
        self.transactionally(async |tx| tx.remove_borrowed::<PersistedMlsPendingGroup>(group_id.as_ref()).await)
            .await
            .map(|_| ())
    }

    /// Persists an enrollment instance
    ///
    /// # Arguments
    /// * `id` - hash of the enrollment and unique identifier
    /// * `content` - serialized enrollment
    pub async fn save_e2ei_enrollment(&self, id: &[u8], content: &[u8]) -> CryptoKeystoreResult<()> {
        let id = id.into();
        let content = content.into();
        self.transactionally(async |tx| tx.save(StoredE2eiEnrollment { id, content }).await)
            .await
    }

    /// Fetches and delete the enrollment instance
    ///
    /// # Arguments
    /// * `id` - hash of the enrollment and unique identifier
    pub async fn pop_e2ei_enrollment(&self, id: &[u8]) -> CryptoKeystoreResult<Option<Vec<u8>>> {
        // someone who has time could try to optimize this but honestly it's really on the cold path
        let Some(mut enrollment) = self.get_borrowed::<StoredE2eiEnrollment>(id).await? else {
            return Ok(None);
        };
        self.transactionally(async |tx| tx.remove_borrowed::<StoredE2eiEnrollment>(id).await)
            .await?;
        Ok(Some(std::mem::take(&mut enrollment.content)))
    }
}

#[inline(always)]
pub fn deser<T: MlsEntity>(bytes: &[u8]) -> Result<T, CryptoKeystoreError> {
    Ok(postcard::from_bytes(bytes)?)
}

#[inline(always)]
pub fn ser<T: MlsEntity>(value: &T) -> Result<Vec<u8>, CryptoKeystoreError> {
    Ok(postcard::to_stdvec(value)?)
}

#[cfg_attr(target_os = "unknown", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_os = "unknown"), async_trait::async_trait)]
impl openmls_traits::key_store::OpenMlsKeyStore for crate::Database {
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
                self.transactionally(async |tx| {
                    tx.save(StoredKeypackage {
                        keypackage_ref: k.into(),
                        keypackage: data,
                    })
                    .await
                })
                .await?;
            }
            MlsEntityId::HpkePrivateKey => {
                self.transactionally(async |tx| tx.save(StoredHpkePrivateKey { pk: k.into(), sk: data }).await)
                    .await?;
            }
            MlsEntityId::PskBundle => {
                self.transactionally(async |tx| {
                    tx.save(StoredPskBundle {
                        psk_id: k.into(),
                        psk: data,
                    })
                    .await
                })
                .await?;
            }
            MlsEntityId::EncryptionKeyPair => {
                self.transactionally(async |tx| tx.save(StoredEncryptionKeyPair { pk: k.into(), sk: data }).await)
                    .await?;
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                self.transactionally(async |tx| {
                    tx.save(StoredEpochEncryptionKeypair {
                        id: k.into(),
                        keypairs: data,
                    })
                    .await
                })
                .await?;
            }
        }

        Ok(())
    }

    async fn read<V: MlsEntity>(&self, key: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        if key.is_empty() {
            return None;
        }
        let conn = &*self.conn().await;

        match V::ID {
            MlsEntityId::GroupState => {
                let v = PersistedMlsGroup::get_borrowed(conn, key).ok().flatten()?;
                deser(&v.state).ok()
            }
            MlsEntityId::SignatureKeyPair => {
                let hash = Sha256Hash::from_existing_hash(key).ok()?;
                let stored_credential = StoredCredential::get(conn, &hash).ok().flatten()?;
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
                let v = StoredKeypackage::get_borrowed(conn, key).ok().flatten()?;
                deser(&v.keypackage).ok()
            }
            MlsEntityId::HpkePrivateKey => {
                let v = StoredHpkePrivateKey::get_borrowed(conn, key).ok().flatten()?;
                deser(&v.sk).ok()
            }
            MlsEntityId::PskBundle => {
                let v = StoredPskBundle::get_borrowed(conn, key).ok().flatten()?;
                deser(&v.psk).ok()
            }
            MlsEntityId::EncryptionKeyPair => {
                let v = StoredEncryptionKeyPair::get_borrowed(conn, key).ok().flatten()?;
                deser(&v.sk).ok()
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let v = StoredEpochEncryptionKeypair::get_borrowed(conn, key).ok().flatten()?;
                deser(&v.keypairs).ok()
            }
        }
    }

    async fn delete<V: MlsEntity>(&self, id: &[u8]) -> Result<(), Self::Error> {
        self.transactionally(async |tx| match V::ID {
            MlsEntityId::SignatureKeyPair => unimplemented!(
                "Deleting a signature key pair should not be done through this API, any keypair should be deleted via
                deleting a credential."
            ),
            MlsEntityId::HpkePrivateKey => tx.remove_borrowed::<StoredHpkePrivateKey>(id).await,
            MlsEntityId::KeyPackage => tx.remove_borrowed::<StoredKeypackage>(id).await,
            MlsEntityId::PskBundle => tx.remove_borrowed::<StoredPskBundle>(id).await,
            MlsEntityId::EncryptionKeyPair => tx.remove_borrowed::<StoredEncryptionKeyPair>(id).await,
            MlsEntityId::EpochEncryptionKeyPair => tx.remove_borrowed::<StoredEpochEncryptionKeypair>(id).await,
            MlsEntityId::GroupState => tx.remove_borrowed::<PersistedMlsGroup>(id).await,
        })
        .await
        .map(|_| ())
    }
}
