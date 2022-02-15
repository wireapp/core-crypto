use rusqlite::OptionalExtension as _;

use crate::{CryptoKeystoreError, MissingKeyErrorKind};

impl crate::CryptoKeystore {
    #[cfg(feature = "memory-cache")]
    #[inline(always)]
    fn proteus_memory_key<S: std::fmt::Display>(k: S) -> Vec<u8> {
        format!("proteus:{}", k).into_bytes()
    }

    pub fn store_prekey(&self, prekey: &proteus::keys::PreKey) -> crate::CryptoKeystoreResult<()> {
        let prekey_buf = prekey.serialise()?;
        let mut db = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;

        let transaction = db.transaction()?;

        use rusqlite::ToSql as _;
        transaction.execute(
            "INSERT INTO proteus_prekeys (id, key) VALUES (?, ?)",
            [
                prekey.key_id.value().to_sql()?,
                rusqlite::blob::ZeroBlob(prekey_buf.len() as i32).to_sql()?,
            ],
        )?;

        let row_id = transaction.last_insert_rowid();

        let mut blob = transaction.blob_open(rusqlite::DatabaseName::Main, "proteus_prekeys", "key", row_id, false)?;
        use std::io::Write as _;
        blob.write_all(&prekey_buf)?;
        drop(blob);

        transaction.commit()?;

        Ok(())
    }
}

impl proteus::session::PreKeyStore for crate::CryptoKeystore {
    type Error = CryptoKeystoreError;

    fn prekey(&mut self, id: proteus::keys::PreKeyId) -> Result<Option<proteus::keys::PreKey>, Self::Error> {
        #[cfg(feature = "memory-cache")]
        let memory_cache_key = Self::proteus_memory_key(id);

        #[cfg(feature = "memory-cache")]
        if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            if let Some(buf) = self
                .memory_cache
                .write()
                .map_err(|_| CryptoKeystoreError::LockPoisonError)?
                .get(&memory_cache_key)
            {
                return Ok(Some(proteus::keys::PreKey::deserialise(buf)?));
            }
        }

        let mut db = self.conn.lock().map_err(|_| CryptoKeystoreError::LockPoisonError)?;

        let transaction = db.transaction()?;

        let maybe_row_id = transaction
            .query_row("SELECT rowid FROM proteus_prekeys WHERE id = ?", [id.value()], |r| {
                r.get::<_, u16>(0)
            })
            .optional()?;

        if let Some(row_id) = maybe_row_id {
            let mut blob = transaction.blob_open(
                rusqlite::DatabaseName::Main,
                "proteus_prekeys",
                "key",
                row_id as i64,
                true,
            )?;

            use std::io::Read as _;
            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;
            let prekey = proteus::keys::PreKey::deserialise(&buf)?;

            #[cfg(feature = "memory-cache")]
            if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
                self.memory_cache
                    .write()
                    .map_err(|_| CryptoKeystoreError::LockPoisonError)?
                    .put(memory_cache_key, buf);
            }

            return Ok(Some(prekey));
        }

        Ok(None)
    }

    fn remove(&mut self, id: proteus::keys::PreKeyId) -> Result<(), Self::Error> {
        #[cfg(feature = "memory-cache")]
        if self.cache_enabled.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = self
                .memory_cache
                .write()
                .map_err(|_| CryptoKeystoreError::LockPoisonError)?
                .pop(format!("proteus:{}", id).as_bytes());
        }

        let updated = self
            .conn
            .lock()
            .map_err(|_| CryptoKeystoreError::LockPoisonError)?
            .execute("DELETE FROM proteus_prekeys WHERE id = ?", [id.value()])?;

        if updated == 0 {
            return Err(MissingKeyErrorKind::ProteusPrekey.into());
        }

        Ok(())
    }
}
