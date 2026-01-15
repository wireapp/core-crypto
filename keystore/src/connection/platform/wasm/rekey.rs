use idb::Transaction;
use js_sys::Uint8Array;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    CryptoKeystoreResult,
    traits::{Decryptable, Decrypting as _, Encrypting, Entity, KeyType},
};

pub(super) async fn rekey_entity<E>(
    transaction: &Transaction,
    serializer: &serde_wasm_bindgen::Serializer,
    old_cipher: &aes_gcm::Aes256Gcm,
    new_cipher: &aes_gcm::Aes256Gcm,
) -> CryptoKeystoreResult<()>
where
    for<'a> E: Entity + Decryptable<'static> + Encrypting<'a>,
    <E as Decryptable<'static>>::DecryptableFrom: DeserializeOwned,
{
    let store = transaction.object_store(E::COLLECTION_NAME)?;
    for js_value in store.get_all(None, None)?.await? {
        let encrypted_entity = serde_wasm_bindgen::from_value::<E::DecryptableFrom>(js_value)?;
        let entity = encrypted_entity.decrypt(old_cipher)?;
        let encrypted = entity.encrypt(new_cipher)?;
        let js_value = encrypted.serialize(serializer)?;

        let key = Uint8Array::new_from_slice(entity.primary_key().bytes().as_ref());

        store.put(&js_value, Some(&key))?.await?;
    }

    Ok(())
}

macro_rules! rekey_entities_new {
    ($db:expr, $old_cipher:expr, $new_cipher:expr, [$($entity:ty),*]) => {
        let transaction = $db.transaction(&$db.store_names(), TransactionMode::ReadWrite)?;
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();

        $(
            $crate::connection::platform::wasm::rekey::rekey_entity::<$entity>(
                &transaction, &serializer, &$old_cipher, &$new_cipher
            )
            .await
            .map_err(|err| {
                let entity = stringify!($entity);
                let err = err.to_string();
                CryptoKeystoreError::MigrationFailed(format!("while rekeying {entity}: {err}"))
            })?;
        )*

        let result = transaction.await?;
        if !result.is_committed() {
            return Err(CryptoKeystoreError::MigrationFailed("comitting rekey idb transaction".into()));
        }
    }
}

pub(super) use rekey_entities_new;
