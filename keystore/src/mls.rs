use crate::{
    error::{CryptoKeystoreError, CryptoKeystoreResult},
    CryptoKeystore, MissingKeyErrorKind,
};

impl CryptoKeystore {
    pub fn store_mls_keypackage_bundle(&self, key: openmls::prelude::KeyPackageBundle) -> CryptoKeystoreResult<()> {
        let id = key.key_package().key_id()?;
        let id = uuid::Uuid::from_slice(id)?;
        use openmls_traits::key_store::OpenMlsKeyStore as _;
        self.store(&id, &key).map_err(CryptoKeystoreError::MlsKeyStoreError)?;
        Ok(())
    }
}


impl openmls_traits::key_store::OpenMlsKeyStore for CryptoKeystore {
    type Error = String;

    fn store<K: std::hash::Hash, V: openmls_traits::key_store::ToKeyStoreValue>(&self, k: &K, v: &V) -> Result<(), Self::Error>
    where
        Self: Sized {
        let k = Self::key_to_hash(k);
        let data = v.to_key_store_value().map_err(Into::into)?;

        use rusqlite::ToSql as _;
        let zb = rusqlite::blob::ZeroBlob(data.len() as i32);
        let params: [rusqlite::types::ToSqlOutput; 2] = [
            k.to_sql().map_err(|e| e.to_string())?,
            zb.to_sql().map_err(|e| e.to_string())?
        ];

        let db = self.conn.lock().unwrap();
        db
            .execute(
                "INSERT INTO mls_keys (uuid, key) VALUES (?, ?)",
                params,
            )
            .map_err(|e| e.to_string())?;

        let row_id = db.last_insert_rowid();

        let mut blob = db.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_keys",
            "key",
            row_id,
            false
        ).map_err(|e| e.to_string())?;
        use std::io::Write as _;
        blob.write_all(&data).map_err(|e| e.to_string())?;

        Ok(())
    }

    fn read<K: std::hash::Hash, V: openmls_traits::key_store::FromKeyStoreValue>(&self, k: &K) -> Option<V>
    where
        Self: Sized {
        let k = Self::key_to_hash(k);
        let db = self.conn.lock().unwrap();
        use rusqlite::OptionalExtension as _;
        let maybe_row_id = db.query_row(
                "SELECT rowid FROM mls_keys WHERE uuid = ?",
                [k],
                |r| r.get(0)
            )
            .optional()
            .ok()
            .flatten();

        if let Some(row_id) = maybe_row_id {
            if let Some(mut blob) = db.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keys",
                "key",
                row_id,
                true
            ).ok() {
                use std::io::Read as _;
                let mut buf = vec![];
                blob.read_to_end(&mut buf).map_err(|e| e.to_string()).ok()?;
                return V::from_key_store_value(&buf).ok();
            }
        }

        None
    }

    #[allow(unreachable_code, unused_imports)]
    fn update<K: std::hash::Hash, V: openmls_traits::key_store::FromKeyStoreValue>(&self, _k: &K, _v: &V) -> Result<(), Self::Error>
    where
        Self: Sized {
        unimplemented!();

        let k = Self::key_to_hash(_k);
        let db = self.conn.lock().unwrap();
        if let Some(row_id) = db.query_row("SELECT rowid FROM mls_keys WHERE uuid = ?", [k], |r| r.get(0)).ok() {
            if let Some(mut blob) = db.blob_open(
                rusqlite::DatabaseName::Main,
                "mls_keys",
                "key",
                row_id,
                false
            ).ok() {
                use std::io::{Write as _, Seek as _};
                blob.seek(std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
                // FIXME: Faulty API Design/Trait, the V bound should be ToKeyStoreValue to allow a write of `v`.
                //blob.write_all(v);
                return Ok(());
            }
        }

        Err("Key uuid doesn't exist in the keystore".into())
    }

    fn delete<K: std::hash::Hash>(&self, k: &K) -> Result<(), Self::Error> {
        let k = Self::key_to_hash(k);
        let updated = self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM mls_keys WHERE uuid = ?", [k])
            .map_err(|e| e.to_string())?;

        if updated == 0 {
            return Err(CryptoKeystoreError::from(MissingKeyErrorKind::MlsKeyBundle).to_string());
        }
        Ok(())
    }
}
