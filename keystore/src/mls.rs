use openmls::prelude::Ciphersuite;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
    connection::FetchFromDatabase,
    entities::{
        EntityFindParams, PersistedMlsGroup, PersistedMlsPendingGroup, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
};

/// An interface for the specialized queries in the KeyStore
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub trait CryptoKeystoreMls: Sized {
    /// Fetches Keypackages
    ///
    /// # Arguments
    /// * `count` - amount of entries to be returned
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_fetch_keypackages<V: MlsEntity>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>>;

    /// Checks if the given MLS group id exists in the keystore
    /// Note: in case of any error, this will return false
    ///
    /// # Arguments
    /// * `group_id` - group/conversation id
    async fn mls_group_exists(&self, group_id: impl AsRef<[u8]> + Send) -> bool;

    /// Persists a `MlsGroup`
    ///
    /// # Arguments
    /// * `group_id` - group/conversation id
    /// * `state` - the group state
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_group_persist(
        &self,
        group_id: impl AsRef<[u8]> + Send,
        state: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()>;

    /// Loads `MlsGroups` from the database. It will be returned as a `HashMap` where the key is
    /// the group/conversation id and the value the group state
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_groups_restore(
        &self,
    ) -> CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, (Option<Vec<u8>>, Vec<u8>)>>;

    /// Deletes `MlsGroups` from the database.
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_group_delete(&self, group_id: impl AsRef<[u8]> + Send) -> CryptoKeystoreResult<()>;

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
    async fn mls_pending_groups_save(
        &self,
        group_id: impl AsRef<[u8]> + Send,
        mls_group: &[u8],
        custom_configuration: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()>;

    /// Loads a temporary `MlsGroup` and its configuration from the database
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_pending_groups_load(
        &self,
        group_id: impl AsRef<[u8]> + Send,
    ) -> CryptoKeystoreResult<(Vec<u8>, Vec<u8>)>;

    /// Deletes a temporary `MlsGroup` from the database
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_pending_groups_delete(&self, group_id: impl AsRef<[u8]> + Send) -> CryptoKeystoreResult<()>;

    /// Persists an enrollment instance
    ///
    /// # Arguments
    /// * `id` - hash of the enrollment and unique identifier
    /// * `content` - serialized enrollment
    async fn save_e2ei_enrollment(&self, id: &[u8], content: &[u8]) -> CryptoKeystoreResult<()>;

    /// Fetches and delete the enrollment instance
    ///
    /// # Arguments
    /// * `id` - hash of the enrollment and unique identifier
    async fn pop_e2ei_enrollment(&self, id: &[u8]) -> CryptoKeystoreResult<Vec<u8>>;
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl CryptoKeystoreMls for crate::Database {
    async fn mls_fetch_keypackages<V: MlsEntity>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>> {
        let reverse = !cfg!(target_family = "wasm");
        let keypackages = self
            .find_all::<StoredKeypackage>(EntityFindParams {
                limit: Some(count),
                offset: None,
                reverse,
            })
            .await?;

        Ok(keypackages
            .into_iter()
            .filter_map(|kpb| postcard::from_bytes(&kpb.keypackage).ok())
            .collect())
    }

    async fn mls_group_exists(&self, group_id: impl AsRef<[u8]> + Send) -> bool {
        matches!(self.find::<PersistedMlsGroup>(group_id).await, Ok(Some(_)))
    }

    async fn mls_group_persist(
        &self,
        group_id: impl AsRef<[u8]> + Send,
        state: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()> {
        self.save(PersistedMlsGroup {
            id: group_id.as_ref().to_owned(),
            state: state.into(),
            parent_id: parent_group_id.map(Into::into),
        })
        .await?;

        Ok(())
    }

    async fn mls_groups_restore(
        &self,
    ) -> CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, (Option<Vec<u8>>, Vec<u8>)>> {
        let groups = self.find_all::<PersistedMlsGroup>(EntityFindParams::default()).await?;
        Ok(groups
            .into_iter()
            .map(|group: PersistedMlsGroup| (group.id.clone(), (group.parent_id.clone(), group.state.clone())))
            .collect())
    }

    async fn mls_group_delete(&self, group_id: impl AsRef<[u8]> + Send) -> CryptoKeystoreResult<()> {
        self.remove::<PersistedMlsGroup, _>(group_id).await?;

        Ok(())
    }

    async fn mls_pending_groups_save(
        &self,
        group_id: impl AsRef<[u8]> + Send,
        mls_group: &[u8],
        custom_configuration: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()> {
        self.save(PersistedMlsPendingGroup {
            id: group_id.as_ref().to_owned(),
            state: mls_group.into(),
            custom_configuration: custom_configuration.into(),
            parent_id: parent_group_id.map(Into::into),
        })
        .await?;
        Ok(())
    }

    async fn mls_pending_groups_load(
        &self,
        group_id: impl AsRef<[u8]> + Send,
    ) -> CryptoKeystoreResult<(Vec<u8>, Vec<u8>)> {
        self.find(group_id)
            .await?
            .map(|r: PersistedMlsPendingGroup| (r.state.clone(), r.custom_configuration.clone()))
            .ok_or(CryptoKeystoreError::MissingKeyInStore(
                MissingKeyErrorKind::MlsPendingGroup,
            ))
    }

    async fn mls_pending_groups_delete(&self, group_id: impl AsRef<[u8]> + Send) -> CryptoKeystoreResult<()> {
        self.remove::<PersistedMlsPendingGroup, _>(group_id).await
    }

    async fn save_e2ei_enrollment(&self, id: &[u8], content: &[u8]) -> CryptoKeystoreResult<()> {
        self.save(StoredE2eiEnrollment {
            id: id.into(),
            content: content.into(),
        })
        .await?;
        Ok(())
    }

    async fn pop_e2ei_enrollment(&self, id: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
        // someone who has time could try to optimize this but honestly it's really on the cold path
        let enrollment = self
            .find::<StoredE2eiEnrollment>(id)
            .await?
            .ok_or(CryptoKeystoreError::MissingKeyInStore(
                MissingKeyErrorKind::StoredE2eiEnrollment,
            ))?;
        self.remove::<StoredE2eiEnrollment, _>(id).await?;
        Ok(enrollment.content.clone())
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
