use crate::connection::FetchFromDatabase;
use crate::entities::{Entity, EntityBase as _};
use crate::transaction::dynamic_dispatch::EntityId;
use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
    entities::{E2eiEnrollment, EntityFindParams, MlsKeyPackage, PersistedMlsGroup, PersistedMlsPendingGroup},
};
use itertools::Group;
use openmls_traits::key_store::MlsEntity;

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
    async fn mls_group_exists(&self, group_id: &[u8]) -> bool;

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
        group_id: &[u8],
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
    async fn mls_group_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()>;

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
        group_id: &[u8],
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
    async fn mls_pending_groups_load(&self, group_id: &[u8]) -> CryptoKeystoreResult<(Vec<u8>, Vec<u8>)>;

    /// Deletes a temporary `MlsGroup` from the database
    ///
    /// # Arguments
    /// * `id` - group/conversation id
    ///
    /// # Errors
    /// Any common error that can happen during a database connection. IoError being a common error
    /// for example.
    async fn mls_pending_groups_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()>;

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
impl CryptoKeystoreMls for crate::Connection {
    async fn mls_fetch_keypackages<V: MlsEntity>(&self, count: u32) -> CryptoKeystoreResult<Vec<V>> {
        cfg_if::cfg_if! {
            if #[cfg(not(target_family = "wasm"))] {
                let reverse = true;
            } else {
                let reverse = false;
            }
        }
        let keypackages = self
            .find_all::<MlsKeyPackage>(EntityFindParams {
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

    async fn mls_group_exists(&self, group_id: &[u8]) -> CryptoKeystoreResult<bool> {
        let group_exists = self
            .find::<PersistedMlsGroup>(&PersistedMlsGroup::to_entity_id(group_id)?)
            .await?
            .is_some();
        Ok(group_exists)
    }

    async fn mls_group_persist(
        &self,
        group_id: &[u8],
        state: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()> {
        self.save(PersistedMlsGroup {
            id: group_id.into(),
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

    async fn mls_group_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()> {
        self.remove::<PersistedMlsGroup>(&PersistedMlsGroup::to_entity_id(group_id)?)
            .await?;

        Ok(())
    }

    async fn mls_pending_groups_save(
        &self,
        group_id: &[u8],
        mls_group: &[u8],
        custom_configuration: &[u8],
        parent_group_id: Option<&[u8]>,
    ) -> CryptoKeystoreResult<()> {
        self.save(PersistedMlsPendingGroup {
            id: group_id.into(),
            state: mls_group.into(),
            custom_configuration: custom_configuration.into(),
            parent_id: parent_group_id.map(Into::into),
        })
        .await?;
        Ok(())
    }

    async fn mls_pending_groups_load(&self, group_id: &[u8]) -> CryptoKeystoreResult<(Vec<u8>, Vec<u8>)> {
        self.find(&EntityId::from_collection_name(
            PersistedMlsPendingGroup::COLLECTION_NAME,
            group_id,
        )?)
        .await?
        .map(|r: PersistedMlsPendingGroup| (r.state.clone(), r.custom_configuration.clone()))
        .ok_or(CryptoKeystoreError::MissingKeyInStore(
            MissingKeyErrorKind::MlsPendingGroup,
        ))
    }

    async fn mls_pending_groups_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()> {
        self.remove::<PersistedMlsPendingGroup>(&PersistedMlsPendingGroup::to_entity_id(group_id)?)
            .await
    }

    async fn save_e2ei_enrollment(&self, id: &[u8], content: &[u8]) -> CryptoKeystoreResult<()> {
        self.save(E2eiEnrollment {
            id: id.into(),
            content: content.into(),
        })
        .await?;
        Ok(())
    }

    async fn pop_e2ei_enrollment(&self, id: &[u8]) -> CryptoKeystoreResult<Vec<u8>> {
        // someone who has time could try to optimize this but honestly it's really on the cold path
        let enrollment = self
            .find::<E2eiEnrollment>(&E2eiEnrollment::to_entity_id(id)?)
            .await?
            .ok_or(CryptoKeystoreError::MissingKeyInStore(
                MissingKeyErrorKind::E2eiEnrollment,
            ))?;
        self.remove::<E2eiEnrollment>(&E2eiEnrollment::to_entity_id(id)?)
            .await?;
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
