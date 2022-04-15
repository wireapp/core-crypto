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

use std::io::Read;

use rusqlite::{OptionalExtension, ToSql};

use crate::{CryptoKeystore, CryptoKeystoreError, MissingKeyErrorKind};

impl CryptoKeystore {
    pub fn mls_load_identity_signature(&self, id: &str) -> crate::CryptoKeystoreResult<Option<Vec<u8>>> {
        let mut conn_lock = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        let transaction = conn_lock.transaction()?;
        use rusqlite::OptionalExtension as _;
        let maybe_rowid = transaction
            .query_row("SELECT rowid FROM mls_identities WHERE id = ?", &[id], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?;

        if let Some(rowid) = maybe_rowid {
            let mut blob =
                transaction.blob_open(rusqlite::DatabaseName::Main, "mls_identities", "signature", rowid, true)?;

            use std::io::Read as _;
            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;
            blob.close()?;

            Ok(Some(buf))
        } else {
            Ok(None)
        }
    }

    pub fn mls_save_identity_signature(&self, id: &str, signature: &[u8]) -> crate::CryptoKeystoreResult<()> {
        let zb = rusqlite::blob::ZeroBlob(signature.len() as i32);

        let mut conn_lock = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        let transaction = conn_lock.transaction()?;
        use rusqlite::ToSql as _;
        let params: [rusqlite::types::ToSqlOutput; 2] = [id.to_sql()?, zb.to_sql()?];

        transaction.execute("INSERT INTO mls_identities (id, signature) VALUES (?, ?)", params)?;
        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(
            rusqlite::DatabaseName::Main,
            "mls_identities",
            "signature",
            row_id,
            false,
        )?;

        use std::io::Write as _;
        blob.write_all(&signature)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    pub fn mls_keypackagebundle_count(&self) -> crate::CryptoKeystoreResult<usize> {
        let count = self
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM mls_keys", [], |r| r.get::<_, usize>(0))?;

        Ok(count - 1)
    }

    pub fn mls_all_keypackage_bundles<'a, V: openmls_traits::key_store::FromKeyStoreValue>(
        &'a self,
    ) -> crate::CryptoKeystoreResult<impl Iterator<Item = V> + 'a> {
        let db = self.conn.lock().unwrap();

        let mut stmt = db.prepare_cached("SELECT rowid FROM mls_keys ORDER BY rowid ASC")?;
        let kpb_ids: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .map(|r| r.map_err(crate::CryptoKeystoreError::from))
            .collect::<crate::CryptoKeystoreResult<Vec<i64>>>()?;

        drop(stmt);

        Ok(kpb_ids.into_iter().filter_map(move |row_id| {
            let mut blob = db
                .blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", row_id, true)
                .ok()?;
            use std::io::Read as _;
            let mut buf = vec![];
            blob.read_to_end(&mut buf).ok()?;
            blob.close().ok()?;

            match V::from_key_store_value(&buf) {
                Ok(value) => Some(value),
                Err(_) => None,
            }
        }))
    }

    pub fn mls_get_keypackage<V: openmls_traits::key_store::FromKeyStoreValue>(
        &self,
    ) -> crate::CryptoKeystoreResult<V> {
        if self.mls_keypackagebundle_count()? == 0 {
            return Err(crate::CryptoKeystoreError::OutOfKeyPackageBundles);
        }

        let db = self.conn.lock().unwrap();
        let rowid: i64 = db.query_row(
            "SELECT rowid FROM mls_keys ORDER BY rowid ASC LIMIT 1 OFFSET 1",
            [],
            |r| r.get(0),
        )?;

        let mut blob = db.blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", rowid, true)?;
        use std::io::Read as _;
        let mut buf = vec![];
        blob.read_to_end(&mut buf)?;
        blob.close()?;

        Ok(V::from_key_store_value(&buf)
            .map_err(|e| crate::CryptoKeystoreError::KeyStoreValueTransformError(e.into()))?)
    }

    pub fn mls_group_persist(&self, group_id: &[u8], state: &[u8]) -> crate::CryptoKeystoreResult<()> {
        let mut db = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;
        let transaction = db.transaction()?;

        let rowid: i64 = if let Some(rowid) = transaction
            .query_row(
                "SELECT rowid FROM mls_groups WHERE id = ?",
                [hex::encode(group_id)],
                |r| r.get(0),
            )
            .optional()?
        {
            rowid
        } else {
            let zb = rusqlite::blob::ZeroBlob(state.len() as i32);
            let zid = rusqlite::blob::ZeroBlob(group_id.len() as i32);
            transaction.execute(
                "INSERT INTO mls_groups (id, state) VALUES(?, ?)",
                [&zid.to_sql()?, &zb.to_sql()?],
            )?;
            let rowid = transaction.last_insert_rowid();

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, false)?;
            use std::io::Write as _;
            blob.write_all(group_id)?;
            blob.close()?;

            rowid
        };

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, false)?;
        use std::io::Write as _;
        blob.write_all(state)?;
        blob.close()?;

        transaction.commit()?;

        Ok(())
    }

    pub fn mls_groups_restore(&self) -> crate::CryptoKeystoreResult<std::collections::HashMap<Vec<u8>, Vec<u8>>> {
        let mut db = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;

        let mut stmt = db.prepare_cached("SELECT rowid FROM mls_groups ORDER BY rowid ASC")?;
        let rowids: Vec<i64> = stmt
            .query_map([], |r| r.get(0))?
            .map(|r| r.map_err(crate::CryptoKeystoreError::from))
            .collect::<crate::CryptoKeystoreResult<_>>()?;

        drop(stmt);

        if rowids.is_empty() {
            return Ok(Default::default());
        }

        let transaction = db.transaction()?;

        let mut map = std::collections::HashMap::new();
        for rowid in rowids {
            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "id", rowid, true)?;
            let mut group_id = vec![];
            blob.read_to_end(&mut group_id)?;
            blob.close()?;

            let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "mls_groups", "state", rowid, true)?;
            let mut state = vec![];
            blob.read_to_end(&mut state)?;
            blob.close()?;

            map.insert(group_id, state);
        }

        transaction.commit()?;

        Ok(map)
    }

    #[cfg(test)]
    pub fn mls_store_keypackage_bundle(
        &self,
        key: openmls::prelude::KeyPackageBundle,
    ) -> crate::CryptoKeystoreResult<()> {
        let id = uuid::Uuid::from_slice(key.key_package().external_key_id()?)?;
        use openmls_traits::key_store::OpenMlsKeyStore as _;
        self.store(id.as_bytes(), &key)
            .map_err(CryptoKeystoreError::MlsKeyStoreError)?;

        Ok(())
    }

    #[cfg(feature = "memory-cache")]
    #[inline(always)]
    fn mls_cache_key(k: &[u8]) -> Vec<u8> {
        let mut ret = vec![0; 4 + k.len()];
        ret[..4].copy_from_slice(b"mls:");
        ret[4..].copy_from_slice(k);
        ret
    }
}

impl openmls_traits::key_store::OpenMlsKeyStore for CryptoKeystore {
    type Error = String;

    fn store<V: openmls_traits::key_store::ToKeyStoreValue>(&self, k: &[u8], v: &V) -> Result<(), Self::Error>
    where
        Self: Sized,
    {
        if k.len() == 0 {
            return Err("The provided key is empty".into());
        }

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
            .blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", row_id, false)
            .map_err(|e| e.to_string())?;

        use std::io::Write as _;
        blob.write_all(&data).map_err(|e| e.to_string())?;
        blob.close().map_err(|e| e.to_string())?;

        transaction.commit().map_err(|e| e.to_string())?;

        Ok(())
    }

    fn read<V: openmls_traits::key_store::FromKeyStoreValue>(&self, k: &[u8]) -> Option<V>
    where
        Self: Sized,
    {
        if k.len() == 0 {
            return None;
        }

        #[cfg(feature = "memory-cache")]
        if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok(mut cache) = self.memory_cache.try_write() {
                if let Some(value) = cache
                    .get(&Self::mls_cache_key(k))
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
            .query_row("SELECT rowid FROM mls_keys WHERE uuid = ?", [&k], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
            .flatten()?;

        let mut blob = transaction
            .blob_open(rusqlite::DatabaseName::Main, "mls_keys", "key", row_id, true)
            .ok()?;

        use std::io::Read as _;
        let mut buf = vec![];
        blob.read_to_end(&mut buf).map_err(|e| e.to_string()).ok()?;
        blob.close().map_err(|e| e.to_string()).ok()?;

        transaction.commit().map_err(|e| e.to_string()).ok()?;

        let hydrated_ksv = V::from_key_store_value(&buf).ok()?;

        #[cfg(feature = "memory-cache")]
        if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            if let Ok(mut cache) = self.memory_cache.try_write() {
                cache.put(Self::mls_cache_key(k), buf);
            }
        }

        Some(hydrated_ksv)
    }

    fn delete(&self, k: &[u8]) -> Result<(), Self::Error> {
        if k.len() == 0 {
            return Ok(());
        }

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
