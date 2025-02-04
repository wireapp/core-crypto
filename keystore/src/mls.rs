// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::connection::FetchFromDatabase;
use crate::entities::MlsEpochEncryptionKeyPair;
use crate::{
    entities::{
        E2eiEnrollment, EntityFindParams, MlsEncryptionKeyPair, MlsHpkePrivateKey, MlsKeyPackage, MlsPskBundle,
        MlsSignatureKeyPair, PersistedMlsGroup, PersistedMlsPendingGroup,
    },
    CryptoKeystoreError, CryptoKeystoreResult, MissingKeyErrorKind,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};

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

    async fn mls_group_exists(&self, group_id: &[u8]) -> bool {
        matches!(self.find::<PersistedMlsGroup>(group_id).await, Ok(Some(_)))
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
        self.remove::<PersistedMlsGroup, _>(group_id).await?;

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
            cfg: custom_configuration.into(),
            parent_id: parent_group_id.map(Into::into),
        })
        .await?;
        Ok(())
    }

    async fn mls_pending_groups_load(&self, group_id: &[u8]) -> CryptoKeystoreResult<(Vec<u8>, Vec<u8>)> {
        self.find(group_id)
            .await?
            .map(|r: PersistedMlsPendingGroup| (r.state.clone(), r.cfg.clone()))
            .ok_or(CryptoKeystoreError::MissingKeyInStore(
                MissingKeyErrorKind::PersistedMlsPendingGroup,
            ))
    }

    async fn mls_pending_groups_delete(&self, group_id: &[u8]) -> CryptoKeystoreResult<()> {
        self.remove::<PersistedMlsPendingGroup, _>(group_id).await
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
            .find::<E2eiEnrollment>(id)
            .await?
            .ok_or(CryptoKeystoreError::MissingKeyInStore(
                MissingKeyErrorKind::E2eiEnrollment,
            ))?;
        self.remove::<E2eiEnrollment, _>(id).await?;
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
