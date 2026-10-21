use const_format::formatcp;
use rusqlite::{Connection, OptionalExtension as _, Row, named_params, params};
use zeroize::ZeroizeOnDrop;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Sha256Hash, Transactionlike,
    entities::StoredKeyPackage,
    traits::{Entity, EntityDatabaseMutation, PrimaryKey},
};

/// Entity representing a persisted `HpkePrivateKey` (related to keypackage init keys that the client is aware of)
///
/// This entity cannot be updated in the DB: the primary key is the hashed public half of the keypair whose
/// private half it stores, and OpenMLS only ever writes one at key package generation, from a
/// freshly generated pair. A second save under the same public key with a different secret would
/// mean the two halves had come apart, so it reports [`CryptoKeystoreError::AlreadyExists`] rather than
/// overwriting.
///
/// This entity doesn't have in independent existence; it shares a table with [`StoredKeyPackage`].
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct StoredHpkePrivateKey {
    #[zeroize(skip)]
    pub public_key_hash: Sha256Hash,
    #[sensitive]
    pub secret_key: Vec<u8>,
}

impl StoredHpkePrivateKey {
    const PK_HASH_FIELD: &str = "hpke_init_public_key_hash";
    const SK_FIELD: &str = "hpke_init_private_key";

    const QUERY_ALL: &str = formatcp!(
        "SELECT {pk_hash}, {sk} FROM {table_name} WHERE {sk} IS NOT NULL",
        pk_hash = StoredHpkePrivateKey::PK_HASH_FIELD,
        sk = StoredHpkePrivateKey::SK_FIELD,
        table_name = StoredHpkePrivateKey::TABLE_NAME,
    );

    const QUERY_ONE: &str = formatcp!(
        "{query_all} AND {pk_hash} = ?",
        query_all = StoredHpkePrivateKey::QUERY_ALL,
        pk_hash = StoredHpkePrivateKey::PK_HASH_FIELD,
    );

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            public_key_hash: row.get(Self::PK_HASH_FIELD)?,
            secret_key: row.get(Self::SK_FIELD)?,
        })
    }
}

impl PrimaryKey for StoredHpkePrivateKey {
    type PrimaryKey = Sha256Hash;

    fn primary_key(&self) -> Sha256Hash {
        self.public_key_hash
    }
}

impl Entity for StoredHpkePrivateKey {
    const TABLE_NAME: &'static str = StoredKeyPackage::TABLE_NAME;

    fn get(conn: &Connection, key: &Sha256Hash) -> CryptoKeystoreResult<Option<Self>> {
        conn.prepare_cached(Self::QUERY_ONE)?
            .query_row(params![key], Self::from_row)
            .optional()
            .map_err(Into::into)
    }

    fn count(conn: &Connection) -> CryptoKeystoreResult<u32> {
        conn.prepare_cached(formatcp!(
            "SELECT count(*) FROM {table_name} WHERE {sk} IS NOT NULL",
            table_name = StoredHpkePrivateKey::TABLE_NAME,
            sk = StoredHpkePrivateKey::SK_FIELD,
        ))?
        .query_one([], |row| row.get(0))
        .map_err(Into::into)
    }

    fn load_all(conn: &Connection) -> CryptoKeystoreResult<Vec<Self>> {
        conn.prepare_cached(Self::QUERY_ALL)?
            .query_map([], Self::from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

impl EntityDatabaseMutation for StoredHpkePrivateKey {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let changed = conn
            .prepare_cached(formatcp!(
                "UPDATE {table_name}
                SET {sk} = :secret_key
                WHERE {sk} IS NULL
                AND {pk_hash} = :public_key_hash",
                table_name = StoredHpkePrivateKey::TABLE_NAME,
                sk = StoredHpkePrivateKey::SK_FIELD,
                pk_hash = StoredHpkePrivateKey::PK_HASH_FIELD,
            ))?
            .execute(named_params! {
                ":secret_key": self.secret_key,
                ":public_key_hash": self.public_key_hash,
            })?;

        if changed == 0 {
            // Either no key package has this init key, or it already has its private key.
            let key_package_exists = conn
                .prepare_cached(formatcp!(
                    "SELECT EXISTS (SELECT 1 FROM {table_name} WHERE {pk_hash} = ?)",
                    table_name = StoredHpkePrivateKey::TABLE_NAME,
                    pk_hash = StoredHpkePrivateKey::PK_HASH_FIELD
                ))?
                .query_one([self.public_key_hash], |row| row.get::<_, bool>(0))?;
            return Err(if key_package_exists {
                CryptoKeystoreError::AlreadyExists(Self::TABLE_NAME)
            } else {
                CryptoKeystoreError::NotFound("key package for HPKE init key", hex::encode(self.public_key_hash))
            });
        }
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &Sha256Hash) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let changed = conn
            .prepare_cached(formatcp!(
                "UPDATE {table_name}
                SET {sk} = NULL
                WHERE {sk} IS NOT NULL AND {pk_hash} = ?",
                table_name = StoredHpkePrivateKey::TABLE_NAME,
                sk = StoredHpkePrivateKey::SK_FIELD,
                pk_hash = StoredHpkePrivateKey::PK_HASH_FIELD,
            ))?
            .execute(params![id])?;
        Ok(changed > 0)
    }
}
