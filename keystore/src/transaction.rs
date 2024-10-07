use crate::entities::{EntityBase, ProteusIdentity, ProteusPrekey, ProteusSession, UniqueEntity};
use crate::{
    connection::{Connection, DatabaseConnection, FetchFromDatabase, KeystoreDatabaseConnection, TransactionWrapper},
    deser,
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, EntityFindParams, EntityMlsExt,
        MlsCredential, MlsCredentialExt, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey,
        MlsKeyPackage, MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup,
        PersistedMlsPendingGroup, StringEntityId,
    },
    CryptoKeystoreError, CryptoKeystoreResult,
};
use async_lock::RwLock;
use itertools::Itertools;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};
use std::{ops::DerefMut, sync::Arc};

#[derive(Debug)]
pub enum Entity {
    SignatureKeyPair(MlsSignatureKeyPair),
    HpkePrivateKey(MlsHpkePrivateKey),
    KeyPackage(MlsKeyPackage),
    PskBundle(MlsPskBundle),
    EncryptionKeyPair(MlsEncryptionKeyPair),
    EpochEncryptionKeyPair(MlsEpochEncryptionKeyPair),
    MlsCredential(MlsCredential),
    PersistedMlsGroup(PersistedMlsGroup),
    PersistedMlsPendingGroup(PersistedMlsPendingGroup),
    MlsPendingMessage(MlsPendingMessage),
    E2eiEnrollment(E2eiEnrollment),
    E2eiRefreshToken(E2eiRefreshToken),
    E2eiAcmeCA(E2eiAcmeCA),
    E2eiIntermediateCert(E2eiIntermediateCert),
    E2eiCrl(E2eiCrl),
}

#[derive(Debug, Clone, PartialEq)]
enum EntityId {
    SignatureKeyPair(Vec<u8>),
    HpkePrivateKey(Vec<u8>),
    KeyPackage(Vec<u8>),
    PskBundle(Vec<u8>),
    EncryptionKeyPair(Vec<u8>),
    EpochEncryptionKeyPair(Vec<u8>),
    MlsCredential(Vec<u8>),
    PersistedMlsGroup(Vec<u8>),
    PersistedMlsPendingGroup(Vec<u8>),
    MlsPendingMessage(Vec<u8>),
    E2eiEnrollment(Vec<u8>),
    E2eiRefreshToken(Vec<u8>),
    E2eiAcmeCA(Vec<u8>),
    E2eiIntermediateCert(Vec<u8>),
    E2eiCrl(Vec<u8>),
}

impl EntityId {
    fn as_id(&self) -> StringEntityId<'_> {
        match self {
            EntityId::SignatureKeyPair(vec) => vec.as_slice().into(),
            EntityId::HpkePrivateKey(vec) => vec.as_slice().into(),
            EntityId::KeyPackage(vec) => vec.as_slice().into(),
            EntityId::PskBundle(vec) => vec.as_slice().into(),
            EntityId::EncryptionKeyPair(vec) => vec.as_slice().into(),
            EntityId::EpochEncryptionKeyPair(vec) => vec.as_slice().into(),
            EntityId::MlsCredential(vec) => vec.as_slice().into(),
            EntityId::PersistedMlsGroup(vec) => vec.as_slice().into(),
            EntityId::PersistedMlsPendingGroup(vec) => vec.as_slice().into(),
            EntityId::MlsPendingMessage(vec) => vec.as_slice().into(),
            EntityId::E2eiEnrollment(vec) => vec.as_slice().into(),
            EntityId::E2eiRefreshToken(vec) => vec.as_slice().into(),
            EntityId::E2eiAcmeCA(vec) => vec.as_slice().into(),
            EntityId::E2eiIntermediateCert(vec) => vec.as_slice().into(),
            EntityId::E2eiCrl(vec) => vec.as_slice().into(),
        }
    }
}

impl EntityId {
    fn from_mls_entity_id(entity_id: MlsEntityId, id: &[u8]) -> Self {
        match entity_id {
            MlsEntityId::SignatureKeyPair => Self::SignatureKeyPair(id.into()),
            MlsEntityId::HpkePrivateKey => Self::HpkePrivateKey(id.into()),
            MlsEntityId::KeyPackage => Self::KeyPackage(id.into()),
            MlsEntityId::PskBundle => Self::PskBundle(id.into()),
            MlsEntityId::EncryptionKeyPair => Self::EncryptionKeyPair(id.into()),
            MlsEntityId::EpochEncryptionKeyPair => Self::EpochEncryptionKeyPair(id.into()),
            MlsEntityId::GroupState => Self::PersistedMlsGroup(id.into()),
        }
    }

    fn from_collection_name(entity_id: &'static str, id: &[u8]) -> CryptoKeystoreResult<Self> {
        match entity_id {
            crate::entities::MlsSignatureKeyPair::COLLECTION_NAME => Ok(Self::SignatureKeyPair(id.into())),
            crate::entities::MlsHpkePrivateKey::COLLECTION_NAME => Ok(Self::HpkePrivateKey(id.into())),
            crate::entities::MlsKeyPackage::COLLECTION_NAME => Ok(Self::KeyPackage(id.into())),
            crate::entities::MlsPskBundle::COLLECTION_NAME => Ok(Self::PskBundle(id.into())),
            crate::entities::MlsEncryptionKeyPair::COLLECTION_NAME => Ok(Self::EncryptionKeyPair(id.into())),
            crate::entities::MlsEpochEncryptionKeyPair::COLLECTION_NAME => Ok(Self::EpochEncryptionKeyPair(id.into())),
            crate::entities::PersistedMlsGroup::COLLECTION_NAME => Ok(Self::PersistedMlsGroup(id.into())),
            crate::entities::PersistedMlsPendingGroup::COLLECTION_NAME => Ok(Self::PersistedMlsPendingGroup(id.into())),
            crate::entities::MlsCredential::COLLECTION_NAME => Ok(Self::MlsCredential(id.into())),
            crate::entities::MlsPendingMessage::COLLECTION_NAME => Ok(Self::MlsPendingMessage(id.into())),
            crate::entities::E2eiEnrollment::COLLECTION_NAME => Ok(Self::E2eiEnrollment(id.into())),
            crate::entities::E2eiCrl::COLLECTION_NAME => Ok(Self::E2eiCrl(id.into())),
            crate::entities::E2eiAcmeCA::COLLECTION_NAME => Ok(Self::E2eiAcmeCA(id.into())),
            crate::entities::E2eiRefreshToken::COLLECTION_NAME => Ok(Self::E2eiRefreshToken(id.into())),
            crate::entities::E2eiIntermediateCert::COLLECTION_NAME => Ok(Self::E2eiIntermediateCert(id.into())),
            _ => Err(CryptoKeystoreError::NotImplemented),
        }
    }
}

async fn execute_save(tx: &TransactionWrapper<'_>, entity: &Entity) -> CryptoKeystoreResult<()> {
    match entity {
        Entity::SignatureKeyPair(mls_signature_key_pair) => mls_signature_key_pair.mls_save(tx).await,
        Entity::HpkePrivateKey(mls_hpke_private_key) => mls_hpke_private_key.mls_save(tx).await,
        Entity::KeyPackage(mls_key_package) => mls_key_package.mls_save(tx).await,
        Entity::PskBundle(mls_psk_bundle) => mls_psk_bundle.mls_save(tx).await,
        Entity::EncryptionKeyPair(mls_encryption_key_pair) => mls_encryption_key_pair.mls_save(tx).await,
        Entity::EpochEncryptionKeyPair(mls_epoch_encryption_key_pair) => {
            mls_epoch_encryption_key_pair.mls_save(tx).await
        }
        Entity::MlsCredential(mls_credential) => mls_credential.mls_save(tx).await,
        Entity::PersistedMlsGroup(persisted_mls_group) => persisted_mls_group.mls_save(tx).await,
        Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => persisted_mls_pending_group.mls_save(tx).await,
        Entity::MlsPendingMessage(mls_pending_message) => mls_pending_message.mls_save(tx).await,
        Entity::E2eiEnrollment(e2ei_enrollment) => e2ei_enrollment.mls_save(tx).await,
        Entity::E2eiRefreshToken(e2ei_refresh_token) => e2ei_refresh_token.replace(tx).await,
        Entity::E2eiAcmeCA(e2ei_acme_ca) => e2ei_acme_ca.replace(tx).await,
        Entity::E2eiIntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.mls_save(tx).await,
        Entity::E2eiCrl(e2ei_crl) => e2ei_crl.mls_save(tx).await,
    }
}

async fn execute_delete(tx: &TransactionWrapper<'_>, entity_id: &EntityId) -> CryptoKeystoreResult<()> {
    use crate::entities::EntityMlsExt;
    match entity_id {
        id @ EntityId::SignatureKeyPair(_) => MlsSignatureKeyPair::mls_delete(tx, id.as_id()).await,
        id @ EntityId::HpkePrivateKey(_) => MlsHpkePrivateKey::mls_delete(tx, id.as_id()).await,
        id @ EntityId::KeyPackage(_) => MlsKeyPackage::mls_delete(tx, id.as_id()).await,
        id @ EntityId::PskBundle(_) => MlsPskBundle::mls_delete(tx, id.as_id()).await,
        id @ EntityId::EncryptionKeyPair(_) => MlsEncryptionKeyPair::mls_delete(tx, id.as_id()).await,
        id @ EntityId::EpochEncryptionKeyPair(_) => MlsEpochEncryptionKeyPair::mls_delete(tx, id.as_id()).await,
        id @ EntityId::MlsCredential(_) => MlsCredential::mls_delete(tx, id.as_id()).await,
        id @ EntityId::PersistedMlsGroup(_) => PersistedMlsGroup::mls_delete(tx, id.as_id()).await,
        id @ EntityId::PersistedMlsPendingGroup(_) => PersistedMlsPendingGroup::mls_delete(tx, id.as_id()).await,
        id @ EntityId::MlsPendingMessage(_) => MlsPendingMessage::mls_delete(tx, id.as_id()).await,
        id @ EntityId::E2eiEnrollment(_) => E2eiEnrollment::mls_delete(tx, id.as_id()).await,
        id @ EntityId::E2eiRefreshToken(_) => E2eiRefreshToken::mls_delete(tx, id.as_id()).await,
        id @ EntityId::E2eiAcmeCA(_) => E2eiAcmeCA::mls_delete(tx, id.as_id()).await,
        id @ EntityId::E2eiIntermediateCert(_) => E2eiIntermediateCert::mls_delete(tx, id.as_id()).await,
        id @ EntityId::E2eiCrl(_) => E2eiCrl::mls_delete(tx, id.as_id()).await,
    }
}

/// This represents a transaction, where all operations will be done in memory and committed at the
/// end
#[derive(Debug, Clone)]
pub struct KeystoreTransaction {
    /// Persistent storage
    db: Connection,
    /// In-memory cache
    cache: Connection,
    deleted: Arc<RwLock<Vec<EntityId>>>,
    deleted_credentials: Arc<RwLock<Vec<Vec<u8>>>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl FetchFromDatabase for KeystoreTransaction {
    async fn find<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: &[u8],
    ) -> CryptoKeystoreResult<Option<E>> {
        let cache_result = self.cache.find(id).await?;
        if let Some(cache_result) = cache_result {
            Ok(Some(cache_result))
        } else {
            let deleted_list = self.deleted.read().await;
            if deleted_list.contains(&EntityId::from_collection_name(E::COLLECTION_NAME, id)?) {
                Ok(None)
            } else {
                self.db.find(id).await
            }
        }
    }

    async fn find_unique<U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<U> {
        let cache_result = self.cache.find_unique().await;
        if let Ok(cache_result) = cache_result {
            Ok(cache_result)
        } else {
            // The deleted list doesn't have to be checked because unique entities don't implement 
            // deletion, just replace. So we can directly forward the query to the db.
            self.db.find_unique().await
        }
    }

    async fn find_all<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let cached_records: Vec<E> = self.cache.find_all(params.clone()).await?;
        let persisted_records = self.db.find_all(params).await?;
        let merged: Vec<E> = cached_records
            .into_iter()
            .chain(persisted_records)
            .unique_by(|e| e.id_raw().to_vec())
            .collect();
        Ok(merged)
    }

    async fn find_many<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>> {
        let cached_records: Vec<E> = self.cache.find_many(ids).await?;
        let persisted_records = self.db.find_many(ids).await?;
        let merged: Vec<E> = cached_records
            .into_iter()
            .chain(persisted_records)
            .unique_by(|e| e.id_raw().to_vec())
            .collect();
        Ok(merged)
    }

    async fn count<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<usize> {
        // Unfortunately, we have to do this. We cannot just add the counts of the cache and the db
        // because of possible record id overlap between cache and db.
        Ok(self.find_all::<E>(Default::default()).await?.len())
    }
}

macro_rules! commit_transaction {
     ($keystore_transaction:expr, [ $( ($records:ident, $entity:ty) ),*]) => {
        let cached_collections = ( $(
        $keystore_transaction.cache.find_all::<$entity>(Default::default()).await?,
            )* );

         let ( $( $records, )* ) = cached_collections;

        let mut conn = $keystore_transaction.db.borrow_conn().await?;
        cfg_if::cfg_if! {
            if #[cfg(target_family = "wasm")] {
                let mut tables = Vec::new();
                $(
                    if !$records.is_empty() {
                        tables.push(<$entity>::COLLECTION_NAME);
                    }
                )*
                let tx = conn.new_transaction(&tables).await?;
            } else {
                let tx = conn.new_transaction().await?;
            }
        }

         $(
            if !$records.is_empty() {
                for record in $records {
                    execute_save(&tx, &record.to_transaction_entity()).await?;
                }
            }
         )*

        for deleted_id in $keystore_transaction.deleted.read().await.iter() {
            execute_delete(&tx, deleted_id).await?
        }

        for deleted_credential in $keystore_transaction.deleted_credentials.read().await.iter() {
            MlsCredential::delete_by_credential(&tx, deleted_credential.to_owned()).await?;
        }

         tx.commit_tx().await?;
     };
}

impl KeystoreTransaction {
    pub async fn new(conn: Connection) -> CryptoKeystoreResult<Self> {
        Ok(Self {
            db: conn,
            // We're not using a proper key because we're not using the DB for security (memory is unencrypted). 
            // We're using it for its API.
            cache: Connection::open_in_memory_with_key("core_crypto_transaction_cache", "").await?,
            deleted: Arc::new(Default::default()),
            deleted_credentials: Arc::new(Default::default()),
        })
    }

    pub async fn save<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + crate::entities::EntityMlsExt + Sync,
    >(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<()> {
        self.cache.save(entity).await?;
        Ok(())
    }

    pub async fn save_mut<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + crate::entities::EntityMlsExt + Sync,
    >(
        &self,
        mut entity: E,
    ) -> CryptoKeystoreResult<E> {
        entity.pre_save().await?;
        self.cache.save(entity.clone()).await?;
        Ok(entity)
    }

    pub async fn remove<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>, S: AsRef<[u8]>>(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        self.cache.remove::<E, &S>(&id).await?;
        let mut deleted_list = self.deleted.write().await;
        deleted_list.push(EntityId::from_collection_name(E::COLLECTION_NAME, id.as_ref())?);
        Ok(())
    }

    pub async fn child_groups<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>
            + crate::entities::PersistedMlsGroupExt
            + Sync,
    >(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<Vec<E>> {
        let mut conn = self.cache.borrow_conn().await?;
        let cached_records = entity.child_groups(conn.deref_mut()).await?;
        let mut conn = self.db.borrow_conn().await?;
        let persisted_records = entity.child_groups(conn.deref_mut()).await?;
        let mut merged: Vec<E> = cached_records.into_iter().chain(persisted_records).collect();
        merged.dedup_by_key(|e| e.id_raw().to_vec());
        Ok(merged)
    }

    pub async fn cred_delete_by_credential(&self, cred: Vec<u8>) {
        let mut deleted_list = self.deleted_credentials.write().await;
        deleted_list.push(cred);
    }

    /// Persists all the operations in the database. It will effectively open a transaction
    /// internally, perform all the buffered operations and commit.
    ///
    /// TODO: currently only MLS is supported. Implement for proteus. For that, remove the default
    /// save, insert and delete functions in the `EntityBase` trait
    /// FIXME: implement a transaction wrapper for the wasm platform to await on the transaction
    pub async fn commit(&self) -> Result<(), CryptoKeystoreError> {
        commit_transaction!(
            self,
            [
                (identifier_01, MlsCredential),
                (identifier_02, MlsSignatureKeyPair),
                (identifier_03, MlsHpkePrivateKey),
                (identifier_04, MlsEncryptionKeyPair),
                (identifier_05, MlsEpochEncryptionKeyPair),
                (identifier_06, MlsPskBundle),
                (identifier_07, MlsKeyPackage),
                (identifier_08, PersistedMlsGroup),
                (identifier_09, PersistedMlsPendingGroup),
                (identifier_10, MlsPendingMessage),
                (identifier_11, E2eiEnrollment),
                (identifier_12, E2eiRefreshToken),
                (identifier_13, E2eiAcmeCA),
                (identifier_14, E2eiIntermediateCert),
                (identifier_15, E2eiCrl),
                (identifier_16, ProteusPrekey),
                (identifier_17, ProteusIdentity),
                (identifier_18, ProteusSession)
            ]
        );

        Ok(())
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl OpenMlsKeyStore for KeystoreTransaction {
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

        let data = crate::mls::ser(v)?;

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
                self.cache.save(kp).await?;
            }
            MlsEntityId::KeyPackage => {
                let kp = MlsKeyPackage {
                    keypackage_ref: k.into(),
                    keypackage: data,
                };
                self.cache.save(kp).await?;
            }
            MlsEntityId::HpkePrivateKey => {
                let kp = MlsHpkePrivateKey { pk: k.into(), sk: data };
                self.cache.save(kp).await?;
            }
            MlsEntityId::PskBundle => {
                let kp = MlsPskBundle {
                    psk_id: k.into(),
                    psk: data,
                };
                self.cache.save(kp).await?;
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp = MlsEncryptionKeyPair { pk: k.into(), sk: data };
                self.cache.save(kp).await?;
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp = MlsEpochEncryptionKeyPair {
                    id: k.into(),
                    keypairs: data,
                };
                self.cache.save(kp).await?;
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
        self.cache.delete::<V>(k).await?;
        let mut deleted_list = self.deleted.write().await;
        deleted_list.push(EntityId::from_mls_entity_id(V::ID, k));
        Ok(())
    }
}
