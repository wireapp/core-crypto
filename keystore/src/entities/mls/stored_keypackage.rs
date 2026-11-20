use const_format::formatcp;
use openmls::prelude::KeyPackage;
use rusqlite::{Connection, OptionalExtension as _, Row, named_params, params};
use zeroize::ZeroizeOnDrop;

use crate::{
    CryptoKeystoreError, CryptoKeystoreResult, Sha256Hash, Transactionlike,
    ancillary::helpers,
    entities::StoredCredentialPk,
    traits::{
        BorrowPrimaryKey, DeletableBySearchKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed,
        EntityGetBorrowed, PrimaryKey, SearchableEntity,
    },
};

/// Entity representing a persisted `KeyPackage`
///
/// This entity cannot be updated in the DB: the primary key is the OpenMLS hash reference of the
/// key package itself, so two rows sharing a key necessarily share their contents. A save which
/// disagrees is a bug, and reports
/// [`CryptoKeystoreError::AlreadyExists`] instead of silently replacing the stored key package.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct StoredKeyPackage {
    pub key_package_ref: Vec<u8>,
    #[sensitive]
    pub key_package: Vec<u8>,
    #[zeroize(skip)]
    pub credential: StoredCredentialPk,
    #[zeroize(skip)]
    pub hpke_init_public_key_hash: Sha256Hash,
    #[zeroize(skip)]
    pub leaf_encryption_key_hash: Sha256Hash,
}

/// A serialized key package together with its serialized private keys.
///
/// These are the three parts of an openmls `KeyPackageBundle`.
#[derive(ZeroizeOnDrop)]
pub(crate) struct KeyPackageWithPrivateKeys {
    pub(crate) key_package: Vec<u8>,
    pub(crate) hpke_init_private_key: Vec<u8>,
    pub(crate) leaf_encryption_private_key: Vec<u8>,
}

impl StoredKeyPackage {
    // this is fundamentally why we need a manual impl of the entity traits:
    // we don't want to load the hpke init private key into memory at any point,
    // even though the table owns it. That belongs in the `StoredHpkePrivateKey` entity.
    const QUERY_ALL: &str = formatcp!(
        "SELECT
            key_package_ref,
            key_package,
            credential_id,
            credential_type,
            credential_not_before,
            hpke_init_public_key_hash,
            leaf_encryption_key_hash
        FROM {table_name}",
        table_name = StoredKeyPackage::TABLE_NAME,
    );

    const QUERY_ONE: &str = formatcp!(
        "{query_all} WHERE key_package_ref = ?",
        query_all = StoredKeyPackage::QUERY_ALL
    );

    const QUERY_BY_CREDENTIAL: &str = formatcp!(
        "{query_all} WHERE credential_id = :credential_id AND credential_type = :credential_type \
         AND credential_not_before = :credential_not_before",
        query_all = StoredKeyPackage::QUERY_ALL,
    );

    const DELETE_BY_CREDENTIAL: &str = formatcp!(
        "DELETE FROM {table_name} WHERE credential_id = :credential_id AND credential_type = :credential_type \
         AND credential_not_before = :credential_not_before",
        table_name = StoredKeyPackage::TABLE_NAME,
    );

    /// Construct an instance from a key package, its hash reference and its serialization.
    ///
    /// Fails if the key package's credential is X509 and its leaf certificate can't be decoded, since then there's no
    /// `not_before` to find the credential by.
    pub(crate) fn from_key_package(
        key_package_ref: Vec<u8>,
        serialization: Vec<u8>,
        key_package: &KeyPackage,
    ) -> CryptoKeystoreResult<Self> {
        let leaf_node = key_package.leaf_node();
        Ok(Self {
            key_package_ref,
            key_package: serialization,
            credential: StoredCredentialPk::from_mls_credential(
                leaf_node.signature_key().as_slice(),
                leaf_node.credential(),
            )?,
            hpke_init_public_key_hash: Sha256Hash::hash_from(key_package.hpke_init_key().as_slice()),
            leaf_encryption_key_hash: Sha256Hash::hash_from(leaf_node.encryption_key().as_slice()),
        })
    }

    /// Store the private keys of the key package with this reference.
    ///
    /// The key package itself must already be saved.
    pub(crate) fn save_private_keys<'a, Tx>(
        tx: &'a Tx,
        key_package_ref: &[u8],
        hpke_init_private_key: &[u8],
        leaf_encryption_private_key: &[u8],
    ) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let changed = conn
            .prepare_cached(formatcp!(
                "UPDATE {table_name}
                SET hpke_init_private_key = :hpke_init_private_key,
                    leaf_encryption_private_key = :leaf_encryption_private_key
                WHERE key_package_ref = :key_package_ref",
                table_name = StoredKeyPackage::TABLE_NAME,
            ))?
            .execute(named_params! {
                ":hpke_init_private_key": hpke_init_private_key,
                ":leaf_encryption_private_key": leaf_encryption_private_key,
                ":key_package_ref": key_package_ref,
            })?;
        if changed == 0 {
            return Err(CryptoKeystoreError::NotFound(
                "key package",
                hex::encode(key_package_ref),
            ));
        }
        Ok(())
    }

    /// Load the serialized key package with this reference, together with its private keys.
    ///
    /// Returns `None` if there is no such key package. Fails if the key package lacks a private key.
    pub(crate) fn load_with_private_keys(
        conn: &Connection,
        key_package_ref: &[u8],
    ) -> CryptoKeystoreResult<Option<KeyPackageWithPrivateKeys>> {
        let row = conn
            .prepare_cached(formatcp!(
                "SELECT key_package, hpke_init_private_key, leaf_encryption_private_key
                FROM {table_name}
                WHERE key_package_ref = ?",
                table_name = StoredKeyPackage::TABLE_NAME,
            ))?
            .query_row(params![key_package_ref], |row| {
                Ok((
                    row.get::<_, Vec<u8>>("key_package")?,
                    row.get::<_, Option<Vec<u8>>>("hpke_init_private_key")?,
                    row.get::<_, Option<Vec<u8>>>("leaf_encryption_private_key")?,
                ))
            })
            .optional()?;
        let Some((key_package, hpke_init_private_key, leaf_encryption_private_key)) = row else {
            return Ok(None);
        };
        let (Some(hpke_init_private_key), Some(leaf_encryption_private_key)) =
            (hpke_init_private_key, leaf_encryption_private_key)
        else {
            return Err(CryptoKeystoreError::MlsKeyStoreError(format!(
                "key package {} is missing a private key",
                hex::encode(key_package_ref)
            )));
        };
        Ok(Some(KeyPackageWithPrivateKeys {
            key_package,
            hpke_init_private_key,
            leaf_encryption_private_key,
        }))
    }

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            key_package_ref: row.get("key_package_ref")?,
            key_package: row.get("key_package")?,
            credential: StoredCredentialPk {
                public_key_hash: row.get("credential_id")?,
                credential_type: row.get("credential_type")?,
                not_before: row.get("credential_not_before")?,
            },
            hpke_init_public_key_hash: row.get("hpke_init_public_key_hash")?,
            leaf_encryption_key_hash: row.get("leaf_encryption_key_hash")?,
        })
    }
}

impl PrimaryKey for StoredKeyPackage {
    type PrimaryKey = Vec<u8>;
    fn primary_key(&self) -> Self::PrimaryKey {
        self.key_package_ref.clone()
    }
}

impl BorrowPrimaryKey for StoredKeyPackage {
    type BorrowedPrimaryKey<'a> = &'a [u8];
    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        &self.key_package_ref
    }
}

impl Entity for StoredKeyPackage {
    const TABLE_NAME: &'static str = "mls_key_packages";
    fn get(conn: &Connection, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        <Self as EntityGetBorrowed>::get_borrowed(conn, key)
    }
    fn count(conn: &Connection) -> CryptoKeystoreResult<u32> {
        helpers::count_helper::<Self>(conn)
    }
    fn load_all(conn: &Connection) -> CryptoKeystoreResult<Vec<Self>> {
        conn.prepare_cached(Self::QUERY_ALL)?
            .query_map([], Self::from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

impl EntityGetBorrowed for StoredKeyPackage {
    fn get_borrowed(conn: &Connection, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<Option<Self>> {
        conn.prepare_cached(Self::QUERY_ONE)?
            .query_row(params![key], Self::from_row)
            .optional()
            .map_err(Into::into)
    }
}

impl EntityDatabaseMutation for StoredKeyPackage {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached(
            "INSERT INTO mls_key_packages (
                key_package_ref,
                key_package,
                credential_id,
                credential_type,
                credential_not_before,
                hpke_init_public_key_hash,
                leaf_encryption_key_hash
            )
            VALUES (
                :key_package_ref,
                :key_package,
                :credential_id,
                :credential_type,
                :credential_not_before,
                :hpke_init_public_key_hash,
                :leaf_encryption_key_hash
            )",
        )?;
        stmt.execute(named_params! {
            ":key_package_ref": self.key_package_ref,
            ":key_package": self.key_package,
            ":credential_id": self.credential.public_key_hash,
            ":credential_type": self.credential.credential_type,
            ":credential_not_before": self.credential.not_before,
            ":hpke_init_public_key_hash": self.hpke_init_public_key_hash,
            ":leaf_encryption_key_hash": self.leaf_encryption_key_hash,
        })
        .map_err(crate::CryptoKeystoreError::map_already_exists(
            <Self as Entity>::TABLE_NAME,
        ))?;
        Ok(())
    }
    fn delete<'a, Tx>(tx: &'a Tx, id: &Self::PrimaryKey) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        <Self as EntityDeleteBorrowed>::delete_borrowed(tx, id)
    }
}

impl EntityDeleteBorrowed for StoredKeyPackage {
    fn delete_borrowed<'a, Tx>(
        tx: &'a Tx,
        id: <Self as BorrowPrimaryKey>::BorrowedPrimaryKey<'_>,
    ) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        helpers::delete_helper::<Self, _>(tx, "key_package_ref", id)
    }
}

impl SearchableEntity<StoredCredentialPk> for StoredKeyPackage {
    fn find_all_matching(conn: &Connection, search_key: &StoredCredentialPk) -> CryptoKeystoreResult<Vec<Self>> {
        conn.prepare_cached(Self::QUERY_BY_CREDENTIAL)?
            .query_map(
                named_params! {
                    ":credential_id": search_key.public_key_hash,
                    ":credential_type": search_key.credential_type,
                    ":credential_not_before": search_key.not_before,
                },
                Self::from_row,
            )?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }

    fn matches(&self, search_key: &StoredCredentialPk) -> bool {
        self.credential == *search_key
    }
}

impl DeletableBySearchKey<StoredCredentialPk> for StoredKeyPackage {
    fn delete_all_matching<'a, Tx>(tx: &'a Tx, search_key: &StoredCredentialPk) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        conn.prepare_cached(Self::DELETE_BY_CREDENTIAL)?
            .execute(named_params! {
                ":credential_id": search_key.public_key_hash,
                ":credential_type": search_key.credential_type,
                ":credential_not_before": search_key.not_before,
            })?;
        Ok(())
    }
}
