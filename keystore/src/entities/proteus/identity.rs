use zeroize::Zeroize;

use crate::{
    CryptoKeystoreError, Transactionlike,
    traits::{Entity, PrimaryKey, UniqueEntity},
};

#[derive(core_crypto_macros::Debug, Clone, Zeroize, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
#[sensitive]
pub struct ProteusIdentity {
    pub sk: Vec<u8>,
    pub pk: Vec<u8>,
}

impl ProteusIdentity {
    pub const SK_KEY_SIZE: usize = 64;
    pub const PK_KEY_SIZE: usize = 32;
    pub const ID: &[u8; 1] = b"1";

    /// The secret key as a fixed-size array.
    ///
    /// # Errors
    ///
    /// [`CryptoKeystoreError::InvalidKeySize`] if the stored blob is not [`Self::SK_KEY_SIZE`]
    /// bytes long.
    // See [`Self::fixed_size`] for why that has to be checked here.
    pub fn sk_raw(&self) -> crate::CryptoKeystoreResult<zeroize::Zeroizing<[u8; Self::SK_KEY_SIZE]>> {
        Self::fixed_size(&self.sk, "sk")
    }

    /// The public key as a fixed-size array.
    ///
    /// # Errors
    ///
    /// [`CryptoKeystoreError::InvalidKeySize`] if the stored blob is not [`Self::PK_KEY_SIZE`]
    /// bytes long.
    // See [`Self::fixed_size`] for why that has to be checked here.
    pub fn pk_raw(&self) -> crate::CryptoKeystoreResult<zeroize::Zeroizing<[u8; Self::PK_KEY_SIZE]>> {
        Self::fixed_size(&self.pk, "pk")
    }

    /// Copy a stored key blob into a fixed-size, zeroized-on-drop buffer.
    ///
    /// The length has to be checked rather than assumed: the schema declares these columns as plain
    /// `BLOB` with no length constraint, and the legacy IndexedDB import copies the blobs across
    /// without validating them, so a truncated or corrupt row can reach us. This previously used a
    /// `debug_assert_eq!` followed by a slice, which meant a release build indexed out of bounds
    /// and panicked instead of reporting the problem.
    fn fixed_size<const N: usize>(
        blob: &[u8],
        key: &'static str,
    ) -> crate::CryptoKeystoreResult<zeroize::Zeroizing<[u8; N]>> {
        if blob.len() != N {
            return Err(CryptoKeystoreError::InvalidKeySize {
                expected: N,
                actual: blob.len(),
                key,
            });
        }

        // Copy into the zeroizing buffer rather than through a temporary, so no unprotected copy of
        // the key material is left behind.
        let mut out = zeroize::Zeroizing::new([0u8; N]);
        out.copy_from_slice(blob);
        Ok(out)
    }
}

impl crate::traits::Entity for ProteusIdentity {
    const TABLE_NAME: &'static str = "proteus_identities";

    fn get(conn: &rusqlite::Connection, _key: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<Option<Self>> {
        use rusqlite::OptionalExtension as _;
        let mut stmt = conn.prepare_cached("SELECT sk, pk FROM proteus_identities ORDER BY rowid ASC LIMIT 1")?;
        stmt.query_row([], |row| {
            Ok(Self {
                sk: row.get("sk")?,
                pk: row.get("pk")?,
            })
        })
        .optional()
        .map_err(Into::into)
    }

    fn count(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<u32> {
        crate::ancillary::helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> crate::CryptoKeystoreResult<Vec<Self>> {
        crate::ancillary::helpers::load_all_helper(conn, |row| {
            Ok(Self {
                sk: row.get("sk")?,
                pk: row.get("pk")?,
            })
        })
    }
}

impl crate::traits::EntityDatabaseMutation for ProteusIdentity {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> crate::CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        if Self::get(&conn, &())?.is_some() {
            return Err(CryptoKeystoreError::AlreadyExists(Self::TABLE_NAME));
        }
        let mut stmt = conn.prepare_cached("INSERT INTO proteus_identities (sk, pk) VALUES (?, ?)")?;
        stmt.execute(rusqlite::params![self.sk, self.pk])?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, _id: &Self::PrimaryKey) -> crate::CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let mut stmt = conn.prepare_cached("DELETE FROM proteus_identities")?;
        let updated = stmt.execute([])?;
        Ok(updated > 0)
    }
}

impl PrimaryKey for ProteusIdentity {
    type PrimaryKey = ();

    fn primary_key(&self) -> Self::PrimaryKey {
        Self::KEY
    }
}

impl UniqueEntity for ProteusIdentity {
    const KEY: Self::PrimaryKey = ();
}

#[cfg(test)]
mod tests {
    use super::ProteusIdentity;
    use crate::CryptoKeystoreError;

    /// Nothing constrains the length of these columns, so a short or over-long blob has to be
    /// reported. This used to `debug_assert_eq!` and then slice, which panicked in release builds.
    #[test]
    fn a_wrong_length_key_blob_is_rejected() {
        for (len, expect_ok) in [
            (0, false),
            (ProteusIdentity::SK_KEY_SIZE - 1, false),
            (ProteusIdentity::SK_KEY_SIZE, true),
            (ProteusIdentity::SK_KEY_SIZE + 1, false),
        ] {
            let identity = ProteusIdentity {
                sk: vec![0xab; len],
                pk: vec![0xcd; ProteusIdentity::PK_KEY_SIZE],
            };

            match (identity.sk_raw(), expect_ok) {
                (Ok(sk), true) => assert_eq!(sk.as_slice(), &vec![0xab; len][..]),
                (Err(CryptoKeystoreError::InvalidKeySize { expected, actual, key }), false) => {
                    assert_eq!(expected, ProteusIdentity::SK_KEY_SIZE);
                    assert_eq!(actual, len);
                    assert_eq!(key, "sk");
                }
                (result, _) => panic!("unexpected result for a {len}-byte secret key: {result:?}"),
            }

            // The public key is well-formed throughout, so it must keep working regardless.
            assert!(identity.pk_raw().is_ok());
        }
    }
}
