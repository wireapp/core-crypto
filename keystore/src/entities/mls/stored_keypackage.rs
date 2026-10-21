use const_format::formatcp;
use openmls::prelude::KeyPackage;
use openmls_traits::key_store::MlsEntity;
use rusqlite::{Connection, OptionalExtension as _, Row, named_params, params};
use zeroize::ZeroizeOnDrop;

use crate::{
    CryptoKeystoreResult, Sha256Hash, Transactionlike,
    ancillary::helpers,
    entities::StoredCredentialPk,
    traits::{BorrowPrimaryKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed, EntityGetBorrowed, PrimaryKey},
};

/// Entity representing a persisted `KeyPackage`
///
/// This entity cannot be updated in the DB: the primary key is the OpenMLS hash reference of the
/// key package itself, so two rows sharing a key necessarily share their contents. A save which
/// disagrees is a bug, and reports
/// [`CryptoKeystoreError::AlreadyExists`][crate::CryptoKeystoreError::AlreadyExists] instead of
/// silently replacing the stored key package.
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
            hpke_init_public_key_hash,
            leaf_encryption_key_hash
        FROM {table_name}",
        table_name = StoredKeyPackage::TABLE_NAME,
    );

    const QUERY_ONE: &str = formatcp!(
        "{query_all} WHERE key_package_ref = ?",
        query_all = StoredKeyPackage::QUERY_ALL
    );

    /// Construct an instance from a pre-computed id, serialization, and a dynamic openmls entity
    ///
    /// Panics if `V` is not a `KeyPackage`.
    pub(crate) fn from_openmls<V: MlsEntity>(id: &[u8], serialization: Vec<u8>, value: &V) -> Self {
        // Ideally we'd write this whole section like
        //
        // ```rust
        // let Some(key_package) = value.downcast::<KeyPackage>() else {
        //     panic!();
        // };
        // ```
        //
        // but it turns out the `MlsEntity::downcast` impl is broken and just recurses infinitely.

        // we use typeid and not the `MlsEntity::ID` const, because it's not a sealed trait and anything
        // can claim any id there.
        // we use typeid and not `std::any::TypeId::of` (or for that matter `std::any::Any::downcast`)
        // because the std version requires `T: 'static`, which we can't get here without changing openmls
        assert_eq!(
            typeid::of::<V>(),
            typeid::of::<KeyPackage>(),
            "implementation error: only call this on a value known to be a key package"
        );

        // SAFETY: we just checked the type identity, and `KeyPackage` has no lifetime parameters,
        // so we know this must be valid.
        let key_package = unsafe { &*std::ptr::from_ref(value).cast::<KeyPackage>() };

        Self {
            key_package_ref: id.to_owned(),
            key_package: serialization,
            credential: StoredCredentialPk {
                public_key_hash: Sha256Hash::hash_from(key_package.leaf_node().signature_key().as_slice()),
                credential_type: u16::from(key_package.leaf_node().credential().credential_type()),
            },
            hpke_init_public_key_hash: Sha256Hash::hash_from(key_package.hpke_init_key().as_slice()),
            leaf_encryption_key_hash: Sha256Hash::hash_from(key_package.leaf_node().encryption_key().as_slice()),
        }
    }

    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            key_package_ref: row.get("key_package_ref")?,
            key_package: row.get("key_package")?,
            credential: StoredCredentialPk {
                public_key_hash: row.get("credential_id")?,
                credential_type: row.get("credential_type")?,
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
                hpke_init_public_key_hash,
                leaf_encryption_key_hash
            )
            VALUES (
                :key_package_ref,
                :key_package,
                :credential_id,
                :credential_type,
                :hpke_init_public_key_hash,
                :leaf_encryption_key_hash
            )",
        )?;
        stmt.execute(named_params! {
            ":key_package_ref": self.key_package_ref,
            ":key_package": self.key_package,
            ":credential_id": self.credential.public_key_hash,
            ":credential_type": self.credential.credential_type,
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
