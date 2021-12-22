use rusqlite::OptionalExtension as _;

use crate::MissingKeyErrorKind;

impl proteus::session::PreKeyStore for crate::CryptoKeystore {
    type Error = crate::CryptoKeystoreError;

    fn prekey(&mut self, id: proteus::keys::PreKeyId) -> Result<Option<proteus::keys::PreKey>, Self::Error> {
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
            return Ok(Some(prekey));
        }

        Ok(None)
    }

    fn remove(&mut self, id: proteus::keys::PreKeyId) -> Result<(), Self::Error> {
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
