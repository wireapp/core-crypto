use std::{collections::VecDeque, ops::DerefMut, sync::Arc};

use async_lock::RwLock;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::key_store::{MlsEntity, MlsEntityId};

use crate::entities::UniqueEntity;
use crate::{
    connection::{Connection, DatabaseConnection, FetchFromDatabase, KeystoreDatabaseConnection, TransactionWrapper},
    entities::{
        E2eiAcmeCA, E2eiCrl, E2eiEnrollment, E2eiIntermediateCert, E2eiRefreshToken, EntityFindParams, EntityMlsExt,
        MlsCredential, MlsCredentialExt, MlsEncryptionKeyPair, MlsEpochEncryptionKeyPair, MlsHpkePrivateKey,
        MlsKeyPackage, MlsPendingMessage, MlsPskBundle, MlsSignatureKeyPair, PersistedMlsGroup,
        PersistedMlsPendingGroup, StringEntityId,
    },
    CryptoKeystoreError, CryptoKeystoreResult,
};

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

#[derive(Debug)]
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

#[derive(Debug)]
enum Operation {
    Store(Entity),
    Remove(EntityId),
    RemoveCredential(Vec<u8>),
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

impl From<Entity> for Operation {
    fn from(value: Entity) -> Self {
        Self::Store(value)
    }
}

impl From<EntityId> for Operation {
    fn from(value: EntityId) -> Self {
        Self::Remove(value)
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
        use crate::entities::EntityBase;
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

impl Operation {
    async fn execute(self, tx: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        match self {
            Operation::Store(entity) => Self::handle_entity(tx, &entity).await,
            Operation::Remove(id) => Self::handle_entity_id(tx, &id).await,
            Operation::RemoveCredential(cred) => MlsCredential::delete_by_credential(tx, cred).await,
        }
    }

    async fn handle_entity(tx: &TransactionWrapper<'_>, entity: &Entity) -> CryptoKeystoreResult<()> {
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
            Entity::PersistedMlsPendingGroup(persisted_mls_pending_group) => {
                persisted_mls_pending_group.mls_save(tx).await
            }
            Entity::MlsPendingMessage(mls_pending_message) => mls_pending_message.mls_save(tx).await,
            Entity::E2eiEnrollment(e2ei_enrollment) => e2ei_enrollment.mls_save(tx).await,
            Entity::E2eiRefreshToken(e2ei_refresh_token) => e2ei_refresh_token.replace(tx).await,
            Entity::E2eiAcmeCA(e2ei_acme_ca) => e2ei_acme_ca.replace(tx).await,
            Entity::E2eiIntermediateCert(e2ei_intermediate_cert) => e2ei_intermediate_cert.mls_save(tx).await,
            Entity::E2eiCrl(e2ei_crl) => e2ei_crl.mls_save(tx).await,
        }
    }

    async fn handle_entity_id(tx: &TransactionWrapper<'_>, entity_id: &EntityId) -> CryptoKeystoreResult<()> {
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

    #[cfg(target_family = "wasm")]
    fn scan_collection_name(&self) -> &'static str {
        use crate::entities::EntityBase;
        match self {
            Operation::Store(Entity::SignatureKeyPair(_)) | Operation::Remove(EntityId::SignatureKeyPair(_)) => {
                MlsSignatureKeyPair::COLLECTION_NAME
            }
            Operation::Store(Entity::HpkePrivateKey(_)) | Operation::Remove(EntityId::HpkePrivateKey(_)) => {
                MlsHpkePrivateKey::COLLECTION_NAME
            }
            Operation::Store(Entity::KeyPackage(_)) | Operation::Remove(EntityId::KeyPackage(_)) => {
                MlsKeyPackage::COLLECTION_NAME
            }
            Operation::Store(Entity::PskBundle(_)) | Operation::Remove(EntityId::PskBundle(_)) => {
                MlsPskBundle::COLLECTION_NAME
            }
            Operation::Store(Entity::EncryptionKeyPair(_)) | Operation::Remove(EntityId::EncryptionKeyPair(_)) => {
                MlsEncryptionKeyPair::COLLECTION_NAME
            }
            Operation::Store(Entity::EpochEncryptionKeyPair(_))
            | Operation::Remove(EntityId::EpochEncryptionKeyPair(_)) => MlsEpochEncryptionKeyPair::COLLECTION_NAME,
            Operation::Store(Entity::MlsCredential(_))
            | Operation::Remove(EntityId::MlsCredential(_))
            | Operation::RemoveCredential(_) => MlsCredential::COLLECTION_NAME,
            Operation::Store(Entity::PersistedMlsGroup(_)) | Operation::Remove(EntityId::PersistedMlsGroup(_)) => {
                PersistedMlsGroup::COLLECTION_NAME
            }
            Operation::Store(Entity::PersistedMlsPendingGroup(_))
            | Operation::Remove(EntityId::PersistedMlsPendingGroup(_)) => PersistedMlsPendingGroup::COLLECTION_NAME,
            Operation::Store(Entity::MlsPendingMessage(_)) | Operation::Remove(EntityId::MlsPendingMessage(_)) => {
                MlsPendingMessage::COLLECTION_NAME
            }
            Operation::Store(Entity::E2eiEnrollment(_)) | Operation::Remove(EntityId::E2eiEnrollment(_)) => {
                E2eiEnrollment::COLLECTION_NAME
            }
            Operation::Store(Entity::E2eiRefreshToken(_)) | Operation::Remove(EntityId::E2eiRefreshToken(_)) => {
                E2eiRefreshToken::COLLECTION_NAME
            }
            Operation::Store(Entity::E2eiAcmeCA(_)) | Operation::Remove(EntityId::E2eiAcmeCA(_)) => {
                E2eiAcmeCA::COLLECTION_NAME
            }
            Operation::Store(Entity::E2eiIntermediateCert(_))
            | Operation::Remove(EntityId::E2eiIntermediateCert(_)) => E2eiIntermediateCert::COLLECTION_NAME,
            Operation::Store(Entity::E2eiCrl(_)) | Operation::Remove(EntityId::E2eiCrl(_)) => E2eiCrl::COLLECTION_NAME,
        }
    }
}

/// This represents a transaction, where all operations will be done in memory and committed at the
/// end
#[derive(Debug, Clone)]
pub struct KeystoreTransaction {
    /// Reference to the connection
    conn: Connection,
    // ideally we'd have boxed dyn `EntityMlsExt` here, but this trait cannot be used as object
    // unfortunatelly we have to live with a lot of boilerplate code because of that
    operations: Arc<RwLock<VecDeque<Operation>>>,
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl FetchFromDatabase for KeystoreTransaction {
    async fn find<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        id: &[u8],
    ) -> CryptoKeystoreResult<Option<E>> {
        self.conn.find(id).await
    }

    async fn find_unique<U: UniqueEntity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<U> {
        self.conn.find_unique().await
    }

    async fn find_all<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        params: EntityFindParams,
    ) -> CryptoKeystoreResult<Vec<E>> {
        self.conn.find_all(params).await
    }

    async fn find_many<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
        ids: &[Vec<u8>],
    ) -> CryptoKeystoreResult<Vec<E>> {
        self.conn.find_many(ids).await
    }

    async fn count<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>>(
        &self,
    ) -> CryptoKeystoreResult<usize> {
        let mut conn = self.conn.borrow_conn().await?;
        E::count(&mut conn).await
    }
}

impl KeystoreTransaction {
    pub fn new(conn: Connection) -> Self {
        Self {
            conn,
            operations: Default::default(),
        }
    }

    async fn add_operation(&self, op: Operation) {
        self.operations.write().await.push_back(op);
    }

    pub async fn save<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + crate::entities::EntityMlsExt,
    >(
        &self,
        entity: E,
    ) -> CryptoKeystoreResult<()> {
        self.add_operation(entity.clone().to_transaction_entity().into()).await;
        Ok(())
    }

    pub async fn save_mut<
        E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection> + crate::entities::EntityMlsExt,
    >(
        &self,
        mut entity: E,
    ) -> CryptoKeystoreResult<E> {
        entity.pre_save().await?;
        self.add_operation(entity.clone().to_transaction_entity().into()).await;
        Ok(entity)
    }

    pub async fn remove<E: crate::entities::Entity<ConnectionType = KeystoreDatabaseConnection>, S: AsRef<[u8]>>(
        &self,
        id: S,
    ) -> CryptoKeystoreResult<()> {
        self.add_operation(EntityId::from_collection_name(E::COLLECTION_NAME, id.as_ref())?.into())
            .await;
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
        let mut conn = self.conn.borrow_conn().await?;
        entity.child_groups(conn.deref_mut()).await
    }

    pub async fn cred_delete_by_credential(&self, cred: Vec<u8>) {
        self.add_operation(Operation::RemoveCredential(cred)).await;
    }

    /// Persists all the operations in the database. It will effectively open a transaction
    /// internally, perform all the buffered operations and commit.
    ///
    /// TODO: currently only MLS is supported. Implement for proteus. For that, remove the default
    /// save, insert and delete functions in the `EntityBase` trait
    /// FIXME: implement a transaction wrapper for the wasm platform to await on the transaction
    pub async fn commit(&self) -> Result<(), CryptoKeystoreError> {
        // we don't necessarily need the write lock here, but since we don't want additional
        // operations being added to the queue, we get an exclusive lock
        let mut operations = self.operations.write().await;
        let mut conn = self.conn.borrow_conn().await?;
        cfg_if::cfg_if! {
            if #[cfg(target_family = "wasm")] {
                use itertools::Itertools;
                let tables = operations.iter().map(|op| op.scan_collection_name()).unique().collect::<Vec<_>>();
                let tx = conn.new_transaction(&tables).await?;
            } else {
                let tx = conn.new_transaction().await?;
            }
        }
        while let Some(op) = operations.pop_front() {
            op.execute(&tx).await?;
        }
        tx.commit_tx().await?;
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
        let mut to_store = self.operations.write().await;

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
                to_store.push_back(Entity::SignatureKeyPair(kp).into());
            }
            MlsEntityId::KeyPackage => {
                let kp = MlsKeyPackage {
                    keypackage_ref: k.into(),
                    keypackage: data,
                };
                to_store.push_back(Entity::KeyPackage(kp).into());
            }
            MlsEntityId::HpkePrivateKey => {
                let kp = MlsHpkePrivateKey { pk: k.into(), sk: data };
                to_store.push_back(Entity::HpkePrivateKey(kp).into());
            }
            MlsEntityId::PskBundle => {
                let kp = MlsPskBundle {
                    psk_id: k.into(),
                    psk: data,
                };
                to_store.push_back(Entity::PskBundle(kp).into());
            }
            MlsEntityId::EncryptionKeyPair => {
                let kp = MlsEncryptionKeyPair { pk: k.into(), sk: data };
                to_store.push_back(Entity::EncryptionKeyPair(kp).into());
            }
            MlsEntityId::EpochEncryptionKeyPair => {
                let kp = MlsEpochEncryptionKeyPair {
                    id: k.into(),
                    keypairs: data,
                };
                to_store.push_back(Entity::EpochEncryptionKeyPair(kp).into());
            }
        }
        Ok(())
    }

    async fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        self.conn.read(k).await
    }

    async fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        self.operations
            .write()
            .await
            .push_back(EntityId::from_mls_entity_id(V::ID, k).into());
        Ok(())
    }
}
