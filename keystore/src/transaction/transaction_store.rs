/// TransactionStore holds a `TransactionCache` for each entity type that
/// has been accessed throughout a transaction.
/// Any entity `E` knows its corresponding cache via `CachedEntity`
/// trait using `E::get_cache()` and therefore allows
/// `transaction_store.cache::<E>()` to return the cache for any `E`.
/// A `TransactionCache` maps an entity id to a `CacheRecord`.
/// A `CacheRecord` holds `Some(entity)`, when the coressponding entity was
/// read or written, or `None` when the entity was deleted during the
/// transaction. If a `CacheRecord` was mutated it's dirty flag will be set.
/// At the end of a transaction we will filter for any dirty records and
/// only persist these.use std::{collections::HashMap, sync::Arc};
use std::{collections::HashMap, sync::Arc};

#[cfg(target_family = "wasm")]
use crate::entities::E2eiRefreshToken;

use crate::{
    CryptoKeystoreResult,
    connection::TransactionWrapper,
    entities::{
        ConsumerData, E2eiAcmeCA, E2eiCrl, E2eiIntermediateCert, MlsPendingMessage, PersistedMlsGroup,
        PersistedMlsPendingGroup, StoredBufferedCommit, StoredCredential, StoredE2eiEnrollment,
        StoredEncryptionKeyPair, StoredEpochEncryptionKeypair, StoredHpkePrivateKey, StoredKeypackage, StoredPskBundle,
    },
    traits::{Entity, EntityDatabaseMutation, OwnedKeyType as _},
};

#[cfg(feature = "proteus-keystore")]
use crate::entities::{ProteusIdentity, ProteusPrekey, ProteusSession};

use async_lock::{RwLock, RwLockUpgradableReadGuardArc};

use crate::transaction::cache_record::CacheRecord;

/// table: primary key -> entity reference
///
/// The inner value is an option: `None` represents a deletion, `Some()` represents an upsert. Accordingly, those
/// operations will be executed when the transaction is finished.
#[derive(Debug, derive_more::Deref, Clone)]
pub struct TransactionCache<E: CachedEntity>(pub Arc<RwLock<HashMap<Vec<u8>, CacheRecord<E::Target>>>>);

impl<E: CachedEntity> Default for TransactionCache<E> {
    fn default() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }
}
pub(crate) type TransactionCacheGuard<E: CachedEntity> =
    RwLockUpgradableReadGuardArc<HashMap<Vec<u8>, CacheRecord<E::Target>>>;

macro_rules! define_transaction_store {
    (
        $struct_name:ident,
        $(
            $(#[$meta:meta])*
            $field:ident : $entity:ty
        ),* $(,)?
    ) => {
        #[derive(Default, Debug)]
        pub struct $struct_name {
            $(
                $(#[$meta])*
                $field: TransactionCache<$entity>,
            )*
        }

        impl $struct_name {
            fn caches(&self) -> Vec<&dyn Flush> {
                let mut v: Vec<&dyn Flush> = Vec::new();
                $(
                    $(#[$meta])*
                    {
                        v.push(&self.$field);
                    }
                )*
                v
            }
        }

        $(
            $(#[$meta])*
            impl CachedEntity for $entity {
                fn get_cache(transaction_store: &$struct_name) -> TransactionCache<$entity> {
                    transaction_store.$field.clone()
                }
            }
        )*
    };
}

define_transaction_store!(
    TransactionStore,
    consumer_data: ConsumerData,
    stored_hpke_private_key: StoredHpkePrivateKey,
    stored_keypackage: StoredKeypackage,
    stored_psk_bundle: StoredPskBundle,
    stored_encryption_key_pair: StoredEncryptionKeyPair,
    stored_epoch_encryption_keypair: StoredEpochEncryptionKeypair,
    stored_credential: StoredCredential,
    stored_buffered_commit: StoredBufferedCommit,
    persisted_mls_group: PersistedMlsGroup,
    persisted_mls_pending_group: PersistedMlsPendingGroup,
    mls_pending_message: MlsPendingMessage,
    stored_e2ei_enrollment: StoredE2eiEnrollment,
    #[cfg(target_family = "wasm")]
    e2ei_refresh_token: E2eiRefreshToken,
    e2ei_acme_ca: E2eiAcmeCA,
    e2ei_intermediate_cert: E2eiIntermediateCert,
    e2ei_crl: E2eiCrl,
    #[cfg(feature = "proteus-keystore")]
    proteus_identity: ProteusIdentity,
    #[cfg(feature = "proteus-keystore")]
    proteus_prekey: ProteusPrekey,
    #[cfg(feature = "proteus-keystore")]
    proteus_session: ProteusSession,
);

impl TransactionStore {
    pub async fn cache<E: CachedEntity>(&self) -> TransactionCacheGuard<E> {
        E::get_cache(&self).upgradable_read_arc().await
    }

    pub async fn flush(&self, tx: &TransactionWrapper<'_>) {
        for cache in self.caches() {
            cache.flush(tx).await;
        }
    }

    #[cfg(target_family = "wasm")]
    async fn dirty_caches_names(&self) -> Vec<&'static str> {
        let mut table_names = Vec::new();
        for cache in self.caches() {
            if cache.is_dirty().await {
                table_names.push(cache.collection_name())
            }
        }
        table_names
    }
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub(crate) trait Flush {
    async fn flush(&self, tx: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()>;

    #[cfg(target_family = "wasm")]
    async fn is_dirty(&self) -> bool;

    #[cfg(target_family = "wasm")]
    fn collection_name(&self) -> &'static str;
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl<E> Flush for TransactionCache<E>
where
    E: CachedEntity + for<'a> EntityDatabaseMutation<'a, Transaction = TransactionWrapper<'a>> + 'static,
{
    async fn flush(&self, tx: &TransactionWrapper<'_>) -> CryptoKeystoreResult<()> {
        let mut records = self.0.write().await;
        for (id, record) in records.drain() {
            if record.is_dirty() {
                let mut guard = record.write().await;
                if let Some(record) = guard.take() {
                    record.into().save(tx).await?;
                } else {
                    let key = E::PrimaryKey::from_bytes(&id).expect("Couldn't create PrimaryKey from bytes");
                    E::delete(tx, &key).await?;
                }
            }
        }
        Ok(())
    }

    #[cfg(target_family = "wasm")]
    async fn is_dirty(&self) -> bool {
        let table = E::get_cache().await;
        table.values().any(|r| r.is_dirty())
    }

    #[cfg(target_family = "wasm")]
    fn collection_name(&self) -> &'static str {
        E::COLLECTION_NAME
    }
}

pub trait CachedEntity
where
    Self: Entity + Send + Sync,
{
    /// Get this entity’s cache from a transaction store
    fn get_cache(transaction_store: &TransactionStore) -> TransactionCache<Self>;
}
