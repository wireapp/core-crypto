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

use crate::prelude::{CryptoResult, MlsConversation};
use core_crypto_keystore::entities::EntityFindParams;

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
pub(crate) trait GroupStoreEntity: std::fmt::Debug {
    type RawStoreValue: core_crypto_keystore::entities::Entity;
    type IdentityType;

    fn id(&self) -> &[u8];

    async fn fetch_from_id(
        id: &[u8],
        identity: Option<Self::IdentityType>,
        keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
    ) -> CryptoResult<Option<Self>>
    where
        Self: Sized;

    async fn fetch_all(
        keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
    ) -> CryptoResult<Vec<Self>>
    where
        Self: Sized;
}

#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl GroupStoreEntity for MlsConversation {
    type RawStoreValue = core_crypto_keystore::entities::PersistedMlsGroup;
    type IdentityType = ();

    fn id(&self) -> &[u8] {
        self.id().as_slice()
    }

    async fn fetch_from_id(
        id: &[u8],
        _: Option<Self::IdentityType>,
        keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
    ) -> crate::CryptoResult<Option<Self>> {
        use core_crypto_keystore::entities::EntityBase as _;
        let Some(store_value) = Self::RawStoreValue::find_one(keystore, &id.into()).await? else {
            return Ok(None);
        };

        let conversation = Self::from_serialized_state(store_value.state.clone(), store_value.parent_id.clone())?;
        // If the conversation is not active, pretend it doesn't exist
        Ok(if conversation.group.is_active() {
            Some(conversation)
        } else {
            None
        })
    }

    async fn fetch_all(
        keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
    ) -> CryptoResult<Vec<Self>> {
        use core_crypto_keystore::entities::EntityBase as _;

        let all_conversations = Self::RawStoreValue::find_all(keystore, EntityFindParams::default());
        Ok(all_conversations
            .await?
            .iter()
            .filter_map(|c| {
                let conversation = Self::from_serialized_state(c.state.clone(), c.parent_id.clone()).unwrap();
                conversation.group.is_active().then_some(conversation)
            })
            .collect::<Vec<_>>())
    }
}

#[cfg(feature = "proteus")]
#[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
impl GroupStoreEntity for crate::proteus::ProteusConversationSession {
    type RawStoreValue = core_crypto_keystore::entities::ProteusSession;
    type IdentityType = std::sync::Arc<proteus_wasm::keys::IdentityKeyPair>;

    fn id(&self) -> &[u8] {
        unreachable!()
    }

    async fn fetch_from_id(
        id: &[u8],
        identity: Option<Self::IdentityType>,
        keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
    ) -> crate::CryptoResult<Option<Self>> {
        use core_crypto_keystore::entities::EntityBase as _;
        let Some(store_value) = Self::RawStoreValue::find_one(keystore, &id.into()).await? else {
            return Ok(None);
        };

        let Some(identity) = identity else {
            return Err(crate::CryptoError::ProteusNotInitialized);
        };

        let session = proteus_wasm::session::Session::deserialise(identity, &store_value.session)
            .map_err(crate::ProteusError::from)?;

        Ok(Some(Self {
            identifier: store_value.id.clone(),
            session,
        }))
    }

    async fn fetch_all(
        _keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
    ) -> CryptoResult<Vec<Self>>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

pub(crate) type GroupStoreValue<V> = std::sync::Arc<async_lock::RwLock<V>>;

pub(crate) type LruMap<V> = schnellru::LruMap<Vec<u8>, GroupStoreValue<V>, HybridMemoryLimiter>;

/// LRU-cache based group/session store
/// Uses a hybrid memory limiter based on both amount of elements and total memory usage
/// As with all LRU caches, eviction is based on oldest elements
pub(crate) struct GroupStore<V: GroupStoreEntity>(LruMap<V>);

impl<V: GroupStoreEntity> std::fmt::Debug for GroupStore<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupStore")
            .field("length", &self.0.len())
            .field("memory_usage", &self.0.memory_usage())
            .field(
                "entries",
                &self
                    .0
                    .iter()
                    .map(|(k, v)| format!("{k:?}={v:?}"))
                    .collect::<Vec<String>>()
                    .join("\n"),
            )
            .finish()
    }
}

impl<V: GroupStoreEntity> Default for GroupStore<V> {
    fn default() -> Self {
        Self(schnellru::LruMap::default())
    }
}

#[cfg(test)]
impl<V: GroupStoreEntity> std::ops::Deref for GroupStore<V> {
    type Target = LruMap<V>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl<V: GroupStoreEntity> std::ops::DerefMut for GroupStore<V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<V: GroupStoreEntity> GroupStore<V> {
    #[allow(dead_code)]
    pub(crate) fn new_with_limit(len: u32) -> Self {
        let limiter = HybridMemoryLimiter::new(Some(len), None);
        let store = schnellru::LruMap::new(limiter);
        Self(store)
    }

    #[allow(dead_code)]
    pub(crate) fn new(count: Option<u32>, memory: Option<usize>) -> Self {
        let limiter = HybridMemoryLimiter::new(count, memory);
        let store = schnellru::LruMap::new(limiter);
        Self(store)
    }

    #[allow(dead_code)]
    pub(crate) fn contains_key(&self, k: &[u8]) -> bool {
        self.0.peek(k).is_some()
    }

    pub(crate) async fn get_fetch(
        &mut self,
        k: &[u8],
        keystore: &mut core_crypto_keystore::Connection,
        identity: Option<V::IdentityType>,
    ) -> crate::CryptoResult<Option<GroupStoreValue<V>>> {
        // Optimistic cache lookup
        if let Some(value) = self.0.get(k) {
            return Ok(Some(value.clone()));
        }

        let mut keystore_connection = keystore
            .borrow_conn()
            .await
            .map_err(|_| crate::CryptoError::LockPoisonError)?;

        // Not in store, fetch the thing in the keystore
        let mut value = V::fetch_from_id(k, identity, &mut keystore_connection).await?;
        if let Some(value) = value.take() {
            let value_to_insert = std::sync::Arc::new(async_lock::RwLock::new(value));
            self.insert_prepped(k.to_vec(), value_to_insert.clone());

            Ok(Some(value_to_insert))
        } else {
            Ok(None)
        }
    }

    pub(crate) async fn get_fetch_all(
        &mut self,
        keystore: &mut core_crypto_keystore::Connection,
    ) -> CryptoResult<Vec<GroupStoreValue<V>>> {
        let mut keystore_connection = keystore
            .borrow_conn()
            .await
            .map_err(|_| crate::CryptoError::LockPoisonError)?;

        let all = V::fetch_all(&mut keystore_connection)
            .await?
            .into_iter()
            .map(|g| {
                let id = g.id().to_vec();
                let to_insert = std::sync::Arc::new(async_lock::RwLock::new(g));
                self.insert_prepped(id, to_insert.clone());
                to_insert
            })
            .collect::<Vec<_>>();
        Ok(all)
    }

    fn insert_prepped(&mut self, k: Vec<u8>, prepped_entity: GroupStoreValue<V>) {
        self.0.insert(k, prepped_entity);
    }

    pub(crate) fn insert(&mut self, k: Vec<u8>, entity: V) {
        let value_to_insert = std::sync::Arc::new(async_lock::RwLock::new(entity));
        self.insert_prepped(k, value_to_insert)
    }

    pub(crate) fn try_insert(&mut self, k: Vec<u8>, entity: V) -> Result<(), V> {
        let value_to_insert = std::sync::Arc::new(async_lock::RwLock::new(entity));

        if self.0.try_insert(k, value_to_insert.clone()) {
            Ok(())
        } else {
            // This is safe because we just built the value
            Err(std::sync::Arc::try_unwrap(value_to_insert).unwrap().into_inner())
        }
    }

    pub(crate) fn remove(&mut self, k: &[u8]) -> Option<GroupStoreValue<V>> {
        self.0.remove(k)
    }

    pub(crate) fn get(&mut self, k: &[u8]) -> Option<&mut GroupStoreValue<V>> {
        self.0.get(k)
    }
}

pub(crate) struct HybridMemoryLimiter {
    mem: schnellru::ByMemoryUsage,
    len: schnellru::ByLength,
}

pub(crate) const MEMORY_LIMIT: usize = 100_000_000;
pub(crate) const ITEM_LIMIT: u32 = 100;

impl HybridMemoryLimiter {
    pub(crate) fn new(count: Option<u32>, memory: Option<usize>) -> Self {
        // false positive. We want to fetch system metrics lazily
        #[allow(clippy::unnecessary_lazy_evaluations)]
        let maybe_memory_limit = memory.or_else(|| {
            cfg_if::cfg_if! {
                if #[cfg(target_family = "wasm")] {
                    None
                } else {
                    let system = sysinfo::System::new_with_specifics(sysinfo::RefreshKind::new().with_memory(sysinfo::MemoryRefreshKind::new().with_ram()));
                    let available_sys_memory = system.available_memory();
                    if available_sys_memory > 0 {
                        Some(available_sys_memory as usize)
                    } else {
                        None
                    }
                }
            }
        });

        let mem = schnellru::ByMemoryUsage::new(maybe_memory_limit.unwrap_or(MEMORY_LIMIT));
        let len = schnellru::ByLength::new(count.unwrap_or(ITEM_LIMIT));

        Self { mem, len }
    }
}

impl Default for HybridMemoryLimiter {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl<K, V> schnellru::Limiter<K, V> for HybridMemoryLimiter {
    type KeyToInsert<'a> = K;
    type LinkType = u32;

    fn is_over_the_limit(&self, length: usize) -> bool {
        <schnellru::ByLength as schnellru::Limiter<K, V>>::is_over_the_limit(&self.len, length)
    }

    fn on_insert(&mut self, length: usize, key: Self::KeyToInsert<'_>, value: V) -> Option<(K, V)> {
        <schnellru::ByLength as schnellru::Limiter<K, V>>::on_insert(&mut self.len, length, key, value)
    }

    // Both underlying limiters have dummy implementations here
    fn on_replace(
        &mut self,
        _length: usize,
        _old_key: &mut K,
        _new_key: Self::KeyToInsert<'_>,
        _old_value: &mut V,
        _new_value: &mut V,
    ) -> bool {
        true
    }
    fn on_removed(&mut self, _key: &mut K, _value: &mut V) {}
    fn on_cleared(&mut self) {}

    fn on_grow(&mut self, new_memory_usage: usize) -> bool {
        <schnellru::ByMemoryUsage as schnellru::Limiter<K, V>>::on_grow(&mut self.mem, new_memory_usage)
    }
}

#[cfg(test)]
mod tests {
    use core_crypto_keystore::dummy_entity::{DummyStoreValue, DummyValue};
    use wasm_bindgen_test::*;

    use super::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[cfg_attr(target_family = "wasm", async_trait::async_trait(?Send))]
    #[cfg_attr(not(target_family = "wasm"), async_trait::async_trait)]
    impl GroupStoreEntity for DummyValue {
        type RawStoreValue = DummyStoreValue;

        type IdentityType = ();

        fn id(&self) -> &[u8] {
            unreachable!()
        }

        async fn fetch_from_id(
            id: &[u8],
            _identity: Option<Self::IdentityType>,
            _keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
        ) -> crate::CryptoResult<Option<Self>> {
            let id = std::str::from_utf8(id)?;
            Ok(Some(id.into()))
        }

        async fn fetch_all(
            _keystore: &mut core_crypto_keystore::connection::KeystoreDatabaseConnection,
        ) -> CryptoResult<Vec<Self>> {
            unreachable!()
        }
    }

    type TestGroupStore = GroupStore<DummyValue>;

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn group_store_init() {
        let store = TestGroupStore::new_with_limit(1);
        assert_eq!(store.len(), 0);
        let store = TestGroupStore::new_with_limit(0);
        assert_eq!(store.len(), 0);
        let store = TestGroupStore::new(Some(0), Some(0));
        assert_eq!(store.len(), 0);
        let store = TestGroupStore::new(Some(0), Some(1));
        assert_eq!(store.len(), 0);
        let store = TestGroupStore::new(Some(1), Some(0));
        assert_eq!(store.len(), 0);
        let store = TestGroupStore::new(Some(1), Some(1));
        assert_eq!(store.len(), 0);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn group_store_common_ops() {
        let mut store = TestGroupStore::new(Some(u32::MAX), Some(usize::MAX));
        for i in 1..=3 {
            let i_str = i.to_string();
            assert!(store
                .try_insert(i_str.as_bytes().to_vec(), i_str.as_str().into())
                .is_ok());
            assert_eq!(store.len(), i);
        }
        for i in 4..=6 {
            let i_str = i.to_string();
            store.insert(i_str.as_bytes().to_vec(), i_str.as_str().into());
            assert_eq!(store.len(), i);
        }

        for i in 1..=6 {
            assert!(store.contains_key(i.to_string().as_bytes()));
        }
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn group_store_operations_len_limiter() {
        let mut store = TestGroupStore::new_with_limit(2);
        assert!(store.try_insert(b"1".to_vec(), "1".into()).is_ok());
        assert_eq!(store.len(), 1);
        assert!(store.try_insert(b"2".to_vec(), "2".into()).is_ok());
        assert_eq!(store.len(), 2);
        assert!(store.try_insert(b"3".to_vec(), "3".into()).is_err());
        assert_eq!(store.len(), 2);
        store.insert(b"4".to_vec(), "4".into());
        assert_eq!(store.len(), 2);
    }

    #[async_std::test]
    #[wasm_bindgen_test]
    async fn group_store_operations_mem_limiter() {
        use schnellru::{LruMap, UnlimitedCompact};
        let mut lru: LruMap<Vec<u8>, DummyValue, UnlimitedCompact> =
            LruMap::<Vec<u8>, DummyValue, UnlimitedCompact>::new(UnlimitedCompact);
        assert_eq!(lru.guaranteed_capacity(), 0);
        assert_eq!(lru.memory_usage(), 0);
        lru.insert(1usize.to_le_bytes().to_vec(), "10".into());
        let memory_usage_step_1 = lru.memory_usage();
        lru.insert(2usize.to_le_bytes().to_vec(), "20".into());
        lru.insert(3usize.to_le_bytes().to_vec(), "30".into());
        lru.insert(4usize.to_le_bytes().to_vec(), "40".into());
        let memory_usage_step_2 = lru.memory_usage();
        assert_ne!(memory_usage_step_1, memory_usage_step_2);

        let mut store = TestGroupStore::new(None, Some(memory_usage_step_2));
        assert_eq!(store.guaranteed_capacity(), 0);
        assert_eq!(store.memory_usage(), 0);
        store.try_insert(1usize.to_le_bytes().to_vec(), "10".into()).unwrap();
        assert_eq!(store.guaranteed_capacity(), 3);
        assert!(store.memory_usage() <= memory_usage_step_1);
        store.try_insert(2usize.to_le_bytes().to_vec(), "20".into()).unwrap();
        store.try_insert(3usize.to_le_bytes().to_vec(), "30".into()).unwrap();
        for i in 1..=3usize {
            assert_eq!(
                *(store.get(i.to_le_bytes().as_ref()).unwrap().read().await),
                DummyValue::from(format!("{}", i * 10).as_str())
            );
        }
        assert_eq!(store.guaranteed_capacity(), 3);
        assert!(store.memory_usage() <= memory_usage_step_1);
        assert!(store.try_insert(4usize.to_le_bytes().to_vec(), "40".into()).is_ok());
        for i in (1usize..=4).rev() {
            assert_eq!(
                *(store.get(i.to_le_bytes().as_ref()).unwrap().read().await),
                DummyValue::from(format!("{}", i * 10).as_str())
            );
        }
        assert_eq!(store.guaranteed_capacity(), 7);
        assert!(store.memory_usage() <= memory_usage_step_2);
        store.try_insert(5usize.to_le_bytes().to_vec(), "50".into()).unwrap();
        store.try_insert(6usize.to_le_bytes().to_vec(), "60".into()).unwrap();
        store.try_insert(7usize.to_le_bytes().to_vec(), "70".into()).unwrap();
        for i in (5usize..=7).rev() {
            store.get(i.to_le_bytes().as_ref()).unwrap();
        }

        store.insert(8usize.to_le_bytes().to_vec(), "80".into());
        for i in [8usize, 7, 6, 5].iter() {
            assert_eq!(
                *(store
                    .get(i.to_le_bytes().as_ref())
                    .unwrap_or_else(|| panic!("couldn't find index {i}"))
                    .read()
                    .await),
                DummyValue::from(format!("{}", i * 10).as_str())
            );
        }

        assert_eq!(store.guaranteed_capacity(), 7);
        assert!(store.memory_usage() <= memory_usage_step_2);
        store.assert_check_internal_state();
    }
}
