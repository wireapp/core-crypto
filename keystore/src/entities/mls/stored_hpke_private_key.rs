use zeroize::Zeroize;

use crate::{
    Transactionlike,
    traits::{BorrowPrimaryKey, PrimaryKey},
};

/// Entity representing a persisted `HpkePrivateKey` (related to LeafNode Private keys that the client is aware of)
///
/// This entity cannot be updated in the DB: the primary key is the public half of the keypair whose
/// private half it stores, and OpenMLS only ever writes one at key package generation, from a
/// freshly generated pair. A second save under the same public key with a different secret would
/// mean the two halves had come apart, so it reports
/// [`CryptoKeystoreError::AlreadyExists`][crate::CryptoKeystoreError::AlreadyExists] rather than
/// overwriting.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, Zeroize, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
#[sensitive]
pub struct StoredHpkePrivateKey {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

impl PrimaryKey for StoredHpkePrivateKey {
    type PrimaryKey = Vec<u8>;

    fn primary_key(&self) -> Vec<u8> {
        self.pk.clone()
    }
}

impl BorrowPrimaryKey for StoredHpkePrivateKey {
    type BorrowedPrimaryKey<'a> = &'a [u8];

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        &self.pk
    }
}

impl crate::traits::Entity for StoredHpkePrivateKey {
    const TABLE_NAME: &'static str = "mls_hpke_private_keys";

    fn get(conn: &rusqlite::Connection, key: &Vec<u8>) -> crate::CryptoKeystoreResult<Option<Self>> {
        let hash = crate::Sha256Hash::hash_from(key);
        crate::ancillary::helpers::get_helper(conn, "pk_sha256", hash, |row| {
            Ok(Self {
                pk: row.get("pk")?,
                sk: row.get("sk")?,
            })
        })
    }

    fn count(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<u32> {
        crate::ancillary::helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
        crate::ancillary::helpers::load_all_helper(conn, |row| {
            Ok(Self {
                pk: row.get("pk")?,
                sk: row.get("sk")?,
            })
        })
    }
}

impl crate::traits::EntityGetBorrowed for StoredHpkePrivateKey {
    fn get_borrowed(conn: &rusqlite::Connection, key: &[u8]) -> crate::CryptoKeystoreResult<Option<Self>> {
        let hash = crate::Sha256Hash::hash_from(key);
        crate::ancillary::helpers::get_helper(conn, "pk_sha256", hash, |row| {
            Ok(Self {
                pk: row.get("pk")?,
                sk: row.get("sk")?,
            })
        })
    }
}

impl crate::traits::EntityDatabaseMutation for StoredHpkePrivateKey {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let hash = crate::Sha256Hash::hash_from(&self.pk);
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached("INSERT INTO mls_hpke_private_keys (pk_sha256, pk, sk) VALUES (?, ?, ?)")?;
        stmt.execute(rusqlite::params![hash, self.pk, self.sk]).map_err(
            crate::CryptoKeystoreError::map_already_exists(<Self as crate::traits::Entity>::TABLE_NAME),
        )?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &Vec<u8>) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let hash = crate::Sha256Hash::hash_from(id);
        crate::ancillary::helpers::delete_helper::<Self, _>(tx, "pk_sha256", hash)
    }
}

impl crate::traits::EntityDeleteBorrowed for StoredHpkePrivateKey {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, id: &[u8]) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let hash = crate::Sha256Hash::hash_from(id);
        crate::ancillary::helpers::delete_helper::<Self, _>(tx, "pk_sha256", hash)
    }
}
