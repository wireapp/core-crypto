use rusqlite::Connection;
use zeroize::Zeroize;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Transactionlike,
    ancillary::helpers::{count_helper, delete_helper, get_helper, load_all_helper},
    traits::{Entity, EntityDatabaseMutation, PrimaryKey},
};

/// Entity representing a stored Proteus prekey.
///
/// This entity cannot be updated in the DB. A prekey id is published to peers in a prekey bundle,
/// and overwriting the prekey it names would leave those peers holding a bundle no session can be
/// established from. A save under an id which is already taken therefore reports
/// [`CryptoKeystoreError::AlreadyExists`] rather than replacing the stored prekey.
#[derive(core_crypto_macros::Debug, Clone, Zeroize, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct ProteusPrekey {
    pub id: u16,
    #[sensitive]
    pub prekey: Vec<u8>,
}

impl ProteusPrekey {
    pub fn from_raw(id: u16, prekey: Vec<u8>) -> Self {
        Self { id, prekey }
    }

    /// Get the lowest free prekey id.
    ///
    /// Ids freed by deletion are handed out before the id space is extended.
    ///
    /// Returns [`CryptoKeystoreError::NoFreePrekeyId`] if every assignable id is taken.
    pub fn get_free_id(conn: &Connection) -> CryptoKeystoreResult<u16> {
        /// Lowest prekey id assignable to an ordinary prekey.
        ///
        /// Id 0 is technically legal in Proteus but has never been auto-assigned here, so it stays reserved.
        const MIN_ASSIGNABLE_ID: u16 = 1;
        /// Highest prekey id assignable to an ordinary prekey.
        ///
        /// `u16::MAX` is reserved for the last-resort prekey. This crate depends only on
        /// `proteus-traits`, so it can't name `proteus_wasm::keys::MAX_PREKEY_ID` directly;
        /// `ProteusCentral::last_resort_prekey_id` in `core-crypto` is the other half of this
        /// invariant.
        const MAX_ASSIGNABLE_ID: u16 = u16::MAX - 1;

        // The scan walks the index on `id` in ascending order and `LIMIT 1` stops it at the first
        // gap, so the cost tracks the position of that gap rather than the size of the table.
        // It can only find gaps above an id which is present, hence the `WHEN`: if the lowest
        // assignable id is itself free, no scan is needed. Bounding `t.id` from above keeps the
        // last-resort prekey out of the scan, so it can neither yield the unassignable candidate
        // `u16::MAX` nor overflow to 65536.
        let mut stmt = conn.prepare_cached(
            "
            SELECT CASE
                WHEN NOT EXISTS (SELECT 1 FROM proteus_prekeys WHERE id = :min_assignable)
                    THEN :min_assignable
                ELSE (
                    SELECT t.id + 1
                    FROM proteus_prekeys AS t
                    WHERE t.id >= :min_assignable
                      AND t.id < :max_assignable
                      AND NOT EXISTS (SELECT 1 FROM proteus_prekeys p WHERE p.id = t.id + 1)
                    ORDER BY t.id
                    LIMIT 1
                )
            END
            ",
        )?;
        // a NULL here is the `ELSE` branch finding no gap below `:max_assignable`, which is
        // the exhausted case: an empty table takes the `WHEN` branch instead.
        stmt.query_one(
            rusqlite::named_params! {
                ":min_assignable": MIN_ASSIGNABLE_ID,
                ":max_assignable": MAX_ASSIGNABLE_ID,
            },
            |row| row.get::<_, Option<u16>>(0),
        )?
        .ok_or(CryptoKeystoreError::NoFreePrekeyId)
    }
}

impl PrimaryKey for ProteusPrekey {
    type PrimaryKey = u16;

    fn primary_key(&self) -> u16 {
        self.id
    }
}

impl Entity for ProteusPrekey {
    const TABLE_NAME: &'static str = "proteus_prekeys";

    fn get(conn: &rusqlite::Connection, key: &u16) -> CryptoKeystoreResult<Option<Self>> {
        get_helper(conn, "id", *key, |row| {
            Ok(Self::from_raw(row.get("id")?, row.get("key")?))
        })
    }

    fn count(conn: &rusqlite::Connection) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> CryptoKeystoreResult<Vec<Self>> {
        load_all_helper(conn, |row| Ok(Self::from_raw(row.get("id")?, row.get("key")?)))
    }
}

impl EntityDatabaseMutation for ProteusPrekey {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached("INSERT INTO proteus_prekeys (id, key) VALUES (?, ?)")?;
        stmt.execute(rusqlite::params![self.id, self.prekey])
            .map_err(CryptoKeystoreError::map_already_exists(Self::TABLE_NAME))?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &u16) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        delete_helper::<Self, _>(tx, "id", *id)
    }
}
