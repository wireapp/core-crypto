use crate::{CryptoKeystore, CryptoKeystoreError, MissingKeyErrorKind};

impl CryptoKeystore {
    #[cfg(test)]
    pub fn store_mls_keypackage_bundle(
        &self,
        key: openmls::prelude::KeyPackageBundle,
    ) -> crate::CryptoKeystoreResult<()> {
        let id = key.key_package().key_id()?;
        let id = uuid::Uuid::from_slice(id)?;
        use openmls_traits::key_store::OpenMlsKeyStore as _;
        self.store(&id, &key)
            .map_err(CryptoKeystoreError::MlsKeyStoreError)?;

        Ok(())
    }

    #[cfg(feature = "memory-cache")]
    #[inline(always)]
    fn mls_cache_key<S: std::fmt::Display>(k: S) -> String {
        format!("mls:{}", k)
    }
}

impl openmls_traits::key_store::OpenMlsKeyStore for CryptoKeystore {
    type Error = String;

    fn store<K: std::hash::Hash, V: openmls_traits::key_store::ToKeyStoreValue>(
        &self,
        k: &K,
        v: &V,
    ) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        let k = Self::key_to_hash(k);
        let data = v.to_key_store_value().map_err(Into::into)?;

        use rusqlite::ToSql as _;
        let zb = rusqlite::blob::ZeroBlob(data.len() as i32);
        let params: [rusqlite::types::ToSqlOutput; 2] = [
            k.to_sql().map_err(|e| e.to_string())?,
            zb.to_sql().map_err(|e| e.to_string())?,
        ];

        let mut db = self
            .conn
            .lock()
            .map_err(|_| CryptoKeystoreError::LockPoisonError.to_string())?;

        let transaction = db.transaction().map_err(|e| e.to_string())?;

        transaction
            .execute("INSERT INTO mls_keys (uuid, key) VALUES (?, ?)", params)
            .map_err(|e| e.to_string())?;

        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction
            .blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keys",
                "key",
                row_id,
                false,
            )
            .map_err(|e| e.to_string())?;

        use std::io::Write as _;
        blob.write_all(&data).map_err(|e| e.to_string())?;
        drop(blob);

        transaction.commit().map_err(|e| e.to_string())?;

        Ok(())
    }

    fn read<K: std::hash::Hash, V: openmls_traits::key_store::FromKeyStoreValue>(
        &self,
        k: &K,
    ) -> Option<V>
    where
        Self: Sized,
    {
        let k = Self::key_to_hash(k);
        #[cfg(feature = "memory-cache")]
        if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok(mut cache) = self.memory_cache.try_write() {
                if let Some(value) = cache
                    .get(&k)
                    .and_then(|buf| V::from_key_store_value(buf).ok())
                {
                    return Some(value);
                }
            }
        }

        let mut db = self.conn.lock().ok()?;
        let transaction = db.transaction().ok()?;
        use rusqlite::OptionalExtension as _;
        let row_id = transaction
            .query_row("SELECT rowid FROM mls_keys WHERE uuid = ?", [&k], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten()
            .flatten()?;

        let mut blob = transaction
            .blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keys",
                "key",
                row_id,
                true,
            )
            .ok()?;

        use std::io::Read as _;
        let mut buf = vec![];
        blob.read_to_end(&mut buf).map_err(|e| e.to_string()).ok()?;
        let hydrated_ksv = V::from_key_store_value(&buf).ok()?;

        #[cfg(feature = "memory-cache")]
        if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok(mut cache) = self.memory_cache.try_write() {
                cache.put(k, buf);
            }
        }

        Some(hydrated_ksv)
    }

    fn delete<K: std::hash::Hash>(&self, k: &K) -> Result<(), Self::Error> {
        let k = Self::key_to_hash(k);

        #[cfg(feature = "memory-cache")]
        if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = self
                .memory_cache
                .write()
                .map_err(|_| CryptoKeystoreError::LockPoisonError.to_string())?
                .pop(&Self::mls_cache_key(&k));
        }

        let updated = self
            .conn
            .lock()
            .map_err(|_| CryptoKeystoreError::LockPoisonError.to_string())?
            .execute("DELETE FROM mls_keys WHERE uuid = ?", [k])
            .map_err(|e| e.to_string())?;

        if updated == 0 {
            return Err(CryptoKeystoreError::from(MissingKeyErrorKind::MlsKeyBundle).to_string());
        }
        Ok(())
    }
}
