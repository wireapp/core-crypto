use async_trait::async_trait;
use idb::TransactionMode;
use js_sys::{Array, Number};
use wasm_bindgen::JsValue;

use crate::{
    CryptoKeystoreResult,
    connection::storage::WasmStorageWrapper,
    entities::{ParentGroupId, PersistedMlsGroup, PersistedMlsGroupExt},
    traits::{BorrowPrimaryKey as _, Decryptable, Decrypting as _, EntityBase as _, SearchableEntity},
};

#[async_trait(?Send)]
impl<'a> SearchableEntity<ParentGroupId<'a>> for PersistedMlsGroup {
    async fn find_all_matching(
        conn: &mut Self::ConnectionType,
        parent_id: &ParentGroupId<'a>,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = *parent_id.as_ref();
        let storage = conn.storage();

        let decrypt_mls_group = |js_value: JsValue| -> CryptoKeystoreResult<PersistedMlsGroup> {
            let encrypted_group =
                serde_wasm_bindgen::from_value::<<PersistedMlsGroup as Decryptable>::DecryptableFrom>(js_value)?;
            let group = encrypted_group.decrypt(&storage.cipher)?;
            Ok(group)
        };

        match &storage.storage {
            WasmStorageWrapper::InMemory(map) => {
                // don't bother with fancy indexing for in-memory storage
                let map = map.borrow();
                let Some(entities) = map.get(Self::COLLECTION_NAME) else {
                    return Ok(Vec::new());
                };
                entities
                    .values()
                    .cloned()
                    .map(decrypt_mls_group)
                    .filter(|mls_group_result| {
                        // any decode / decryption error, or a matching group will make it through this filter
                        mls_group_result.as_ref().ok().is_none_or(|mls_group| {
                            mls_group
                                .parent_id
                                .as_ref()
                                .is_some_and(|group_parent_id| group_parent_id == parent_id)
                        })
                    })
                    .collect()
            }
            WasmStorageWrapper::Persistent(database) => {
                // _do_ bother with fancy indexing for real storage
                let tx = database.transaction(&[Self::COLLECTION_NAME], TransactionMode::ReadOnly)?;
                let object_store = tx.object_store(Self::COLLECTION_NAME)?;
                let idx = object_store.index("parent_id")?;

                let parent_id = {
                    // For whatever reason, IDB is storing these keys as JS arrays of numbers, not as
                    // Uint8Arrays. And of course for type-safety reasons, passing in a Uint8Array
                    // will fail to match against an array of numbers, even if all the digits are the same. 🙃
                    let arr = Array::new();
                    for byte in parent_id {
                        arr.push(&Number::from(*byte));
                    }
                    JsValue::from(arr)
                };
                let entities = idx.get_all(Some(parent_id.into()), None)?.await?;
                entities.into_iter().map(decrypt_mls_group).collect()
            }
        }
    }
}

#[async_trait(?Send)]
impl PersistedMlsGroupExt for PersistedMlsGroup {
    fn parent_id(&self) -> Option<&[u8]> {
        self.parent_id.as_deref()
    }

    async fn child_groups(&self, conn: &mut Self::ConnectionType) -> CryptoKeystoreResult<Vec<Self>> {
        let parent_id = self.borrow_primary_key().into();
        Self::find_all_matching(conn, &parent_id).await
    }
}
