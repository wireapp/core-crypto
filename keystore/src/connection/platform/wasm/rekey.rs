macro_rules! rekey_entities {
    ($db: ident, $old_cipher: ident, $new_cipher: ident, [$($entity:ty),*]) => {
        let serializer = serde_wasm_bindgen::Serializer::json_compatible();
        let transaction = $db.transaction(&$db.store_names(), TransactionMode::ReadWrite)?;

        $(
            let store = transaction.object_store(<$entity>::COLLECTION_NAME)?;
            let js_values = store.get_all(None, None)?.await?;
            for js_value in js_values {
                let mut entity: $entity = serde_wasm_bindgen::from_value(js_value)?;
                entity.decrypt(&$old_cipher)?;
                let key = entity.id()?;
                entity.encrypt(&$new_cipher)?;
                let js_value = entity.serialize(&serializer)?;
                store.put(&js_value, Some(&key))?.await?;
            }
        )*

        let result = transaction.await?;
        if !result.is_committed() {
            return Err(CryptoKeystoreError::MigrationFailed);
        }
    }
}

pub(crate) use rekey_entities;
