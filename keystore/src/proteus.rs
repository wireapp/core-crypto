use rusqlite::OptionalExtension as _;

use crate::MissingKeyErrorKind;

impl crate::CryptoKeystore {
    #[inline(always)]
    fn proteus_memory_key<S: std::fmt::Display>(k: S) -> String {
        format!("proteus:{}", k)
    }
}

impl proteus::session::PreKeyStore for crate::CryptoKeystore {
    type Error = crate::CryptoKeystoreError;

    fn prekey(&mut self, id: proteus::keys::PreKeyId) -> Result<Option<proteus::keys::PreKey>, Self::Error> {
        let memory_cache_key = Self::proteus_memory_key(id);
        if let Some(buf) = self.memory_cache.write().unwrap().get(&memory_cache_key) {
            return Ok(Some(proteus::keys::PreKey::deserialise(&buf)?));
        }

        let db = self.conn.lock().unwrap();
        let maybe_row_id = db.query_row(
            "SELECT rowid FROM proteus_prekeys WHERE id = ?",
            [id.value()],
            |r| r.get::<_, u16>(0)
        ).optional()?;

        if let Some(row_id) = maybe_row_id {
            let mut blob = db.blob_open(
                rusqlite::DatabaseName::Main,
                "proteus_prekeys",
                "key",
                row_id as i64,
                true
            )?;

            use std::io::Read as _;
            let mut buf = vec![];
            blob.read_to_end(&mut buf)?;
            let prekey = proteus::keys::PreKey::deserialise(&buf)?;
            self.memory_cache.write().unwrap().put(memory_cache_key, buf);
            return Ok(Some(prekey));
        }

        Ok(None)
    }

    fn remove(&mut self, id: proteus::keys::PreKeyId) -> Result<(), Self::Error> {
        let _ = self.memory_cache.write().unwrap().pop(&format!("proteus:{}", id));

        let updated = self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM proteus_prekeys WHERE id = ?", [id.value()])?;

        if updated == 0 {
            return Err(MissingKeyErrorKind::ProteusPrekey.into());
        }
        Ok(())
    }
}
