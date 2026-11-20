use rusqlite::{Connection, named_params};
use zeroize::ZeroizeOnDrop;

use crate::{
    CryptoKeystoreResult, Sha256Hash, Transactionlike,
    ancillary::{ConversationId, ConversationIdRef, helpers},
    entities::StoredCredentialPk,
    traits::{BorrowPrimaryKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed, EntityGetBorrowed, PrimaryKey},
};

/// Entity representing core-crypto's record of an MLS group
///
/// openmls stores the group's state itself, in other columns of the same row; see the `StorageProvider` impl on
/// [`MlsStorage`][crate::MlsStorage]. The `state` column holds groups serialized by the old openmls fork, until they
/// are converted.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq, ZeroizeOnDrop, serde::Serialize, serde::Deserialize)]
#[zeroize(drop)]
pub struct PersistedMlsGroup {
    pub id: ConversationId,
    pub epoch: u64,
    pub ciphersuite: u16,
    /// Hash of the public key of the credential our leaf node uses.
    ///
    /// Together with `credential_type` and `credential_not_before`, this is the primary key of that credential in
    /// `mls_credentials`, and a foreign key onto it.
    #[zeroize(skip)]
    pub credential_id: Sha256Hash,
    /// The type of the credential identified by `credential_id`.
    #[zeroize(skip)]
    pub credential_type: u16,
    /// The `not_before` of the credential identified by `credential_id`: its leaf certificate's for an X509
    /// credential, and 0 for any other.
    #[zeroize(skip)]
    pub credential_not_before: u64,
    pub own_leaf_index: u32,
    /// Distinguishes a group joined by external commit but not yet merged from an established one.
    pub is_pending: bool,
    /// Counter for outbound TNT messages
    pub tnt_tx_counter: u32,
}

impl PersistedMlsGroup {
    /// Delete this group only if it is still marked pending.
    ///
    /// A pending group and the established group it eventually becomes share a row.
    /// Abandoning a pending join must not delete an established group which has since superseded it.
    /// This accomplishes that while avoiding TOCTOU issues.
    pub fn delete_if_pending<'a, Tx>(tx: &'a Tx, id: &ConversationIdRef) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let changed = conn.execute("DELETE FROM mls_groups WHERE id = ? AND is_pending = 1", [id])?;
        Ok(changed > 0)
    }

    /// Update the columns core-crypto keeps for an existing group.
    ///
    /// openmls keeps `epoch`, `ciphersuite` and `own_leaf_index` up to date itself as it writes the group's state, so
    /// this leaves them alone. If `credential` is `None`, the recorded credential is left alone too.
    ///
    /// Fails with [`CryptoKeystoreError::NotFound`][crate::CryptoKeystoreError::NotFound] if the group has no row.
    pub fn update_own_columns<'a, Tx>(
        tx: &'a Tx,
        id: &ConversationIdRef,
        credential: Option<&StoredCredentialPk>,
        is_pending: bool,
        tnt_tx_counter: u32,
    ) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        let changed = conn
            .prepare_cached(
                "UPDATE mls_groups SET
                    credential_id = coalesce(:credential_id, credential_id),
                    credential_type = coalesce(:credential_type, credential_type),
                    credential_not_before = coalesce(:credential_not_before, credential_not_before),
                    is_pending = :is_pending,
                    tnt_tx_counter = :tnt_tx_counter
                WHERE id = :id",
            )?
            .execute(named_params! {
                ":credential_id": credential.map(|credential| credential.public_key_hash),
                ":credential_type": credential.map(|credential| credential.credential_type),
                ":credential_not_before": credential.map(|credential| credential.not_before),
                ":is_pending": is_pending,
                ":tnt_tx_counter": tnt_tx_counter,
                ":id": id,
            })?;
        if changed == 0 {
            return Err(crate::CryptoKeystoreError::NotFound(
                "mls group",
                hex::encode(id.bytes()),
            ));
        }
        Ok(())
    }

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get("id")?,
            epoch: row.get("epoch")?,
            ciphersuite: row.get("ciphersuite")?,
            credential_id: row.get("credential_id")?,
            credential_type: row.get("credential_type")?,
            credential_not_before: row.get("credential_not_before")?,
            own_leaf_index: row.get("own_leaf_index")?,
            is_pending: row.get("is_pending")?,
            tnt_tx_counter: row.get("tnt_tx_counter")?,
        })
    }
}

impl PrimaryKey for PersistedMlsGroup {
    type PrimaryKey = ConversationId;

    fn primary_key(&self) -> Self::PrimaryKey {
        self.id.clone()
    }
}

impl BorrowPrimaryKey for PersistedMlsGroup {
    type BorrowedPrimaryKey<'a> = &'a ConversationIdRef;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        self.id.as_ref()
    }
}

impl Entity for PersistedMlsGroup {
    const TABLE_NAME: &'static str = "mls_groups";

    fn get(conn: &Connection, key: &Self::PrimaryKey) -> CryptoKeystoreResult<Option<Self>> {
        helpers::get_helper(conn, "id", key, Self::from_row)
    }

    fn count(conn: &Connection) -> CryptoKeystoreResult<u32> {
        helpers::count_helper::<Self>(conn)
    }

    fn load_all(conn: &Connection) -> CryptoKeystoreResult<Vec<Self>> {
        helpers::load_all_helper(conn, Self::from_row)
    }
}

impl EntityGetBorrowed for PersistedMlsGroup {
    fn get_borrowed(conn: &Connection, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<Option<Self>> {
        helpers::get_helper(conn, "id", key, Self::from_row)
    }
}

impl EntityDatabaseMutation for PersistedMlsGroup {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        // This must upsert via `ON CONFLICT ... DO UPDATE`, not `INSERT OR REPLACE`:
        // several tables use this table's id as a foreign key, and `INSERT OR REPLACE` is actually
        // "delete then insert", so all those foreign keys would cascade-delete before we insert a replacement.
        let mut stmt = conn.prepare_cached(
            "INSERT INTO mls_groups
                ( id,  epoch,  ciphersuite,  credential_id,  credential_type,  credential_not_before,
                  own_leaf_index,  is_pending,  tnt_tx_counter)
             VALUES
                (:id, :epoch, :ciphersuite, :credential_id, :credential_type, :credential_not_before,
                 :own_leaf_index, :is_pending, :tnt_tx_counter)
             ON CONFLICT (id) DO UPDATE SET
                epoch = excluded.epoch,
                ciphersuite = excluded.ciphersuite,
                credential_id = excluded.credential_id,
                credential_type = excluded.credential_type,
                credential_not_before = excluded.credential_not_before,
                own_leaf_index = excluded.own_leaf_index,
                is_pending = excluded.is_pending,
                tnt_tx_counter = excluded.tnt_tx_counter",
        )?;
        stmt.execute(named_params![
            ":id": self.id,
            ":epoch": self.epoch,
            ":ciphersuite": self.ciphersuite,
            ":credential_id": self.credential_id,
            ":credential_type": self.credential_type,
            ":credential_not_before": self.credential_not_before,
            ":own_leaf_index": self.own_leaf_index,
            ":is_pending": self.is_pending,
            ":tnt_tx_counter": self.tnt_tx_counter,
        ])?;
        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, id: &ConversationId) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        helpers::delete_helper::<Self, _>(tx, "id", id)
    }
}

impl EntityDeleteBorrowed for PersistedMlsGroup {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, id: &ConversationIdRef) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        helpers::delete_helper::<Self, _>(tx, "id", id)
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future;

    use super::*;
    use crate::{CryptoKeystoreError, Database, entities::StoredCredential};

    const GROUP_ID: &[u8] = b"a conversation";

    fn credential(public_key: &[u8]) -> StoredCredential {
        StoredCredential {
            session_id: b"session id".to_vec(),
            credential: public_key.to_vec(),
            created_at: 0,
            ciphersuite: 1,
            public_key: public_key.to_vec(),
            credential_type: 1,
            not_before: StoredCredential::NOT_BEFORE_WITHOUT_CERTIFICATE,
            private_key: b"private key".to_vec(),
        }
    }

    /// A database holding two credentials and a group using the first of them.
    fn database() -> (std::sync::Arc<Database>, StoredCredentialPk, StoredCredentialPk) {
        future::block_on(async {
            let database = Database::open_in_memory().unwrap();
            let tx = database.new_transaction().await.unwrap();
            let first = credential(b"first public key");
            let second = credential(b"second public key");
            first.save(&*tx).unwrap();
            second.save(&*tx).unwrap();
            let first = first.primary_key();
            PersistedMlsGroup {
                id: GROUP_ID.into(),
                epoch: 7,
                ciphersuite: 2,
                credential_id: first.public_key_hash,
                credential_type: first.credential_type,
                credential_not_before: first.not_before,
                own_leaf_index: 3,
                is_pending: false,
                tnt_tx_counter: 0,
            }
            .save(&*tx)
            .unwrap();
            tx.commit().await.unwrap();
            (database, first, second.primary_key())
        })
    }

    fn load(tx: &crate::Transaction) -> PersistedMlsGroup {
        PersistedMlsGroup::get_borrowed(&tx.conn().unwrap(), ConversationIdRef::new(GROUP_ID))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn updating_own_columns_leaves_the_columns_openmls_writes_alone() {
        let (database, _, second) = database();
        future::block_on(async {
            let tx = database.new_transaction().await.unwrap();
            PersistedMlsGroup::update_own_columns(&*tx, ConversationIdRef::new(GROUP_ID), Some(&second), true, 5)
                .unwrap();

            let group = load(&tx);
            assert_eq!((group.epoch, group.ciphersuite, group.own_leaf_index), (7, 2, 3));
            assert_eq!(
                StoredCredentialPk::new(group.credential_id, group.credential_type, group.credential_not_before),
                second
            );
            assert!(group.is_pending);
            assert_eq!(group.tnt_tx_counter, 5);
        });
    }

    #[test]
    fn updating_own_columns_without_a_credential_keeps_the_recorded_one() {
        let (database, first, _) = database();
        future::block_on(async {
            let tx = database.new_transaction().await.unwrap();
            PersistedMlsGroup::update_own_columns(&*tx, ConversationIdRef::new(GROUP_ID), None, false, 1).unwrap();

            let group = load(&tx);
            assert_eq!(
                StoredCredentialPk::new(group.credential_id, group.credential_type, group.credential_not_before),
                first
            );
        });
    }

    #[test]
    fn updating_own_columns_of_a_group_without_a_row_fails() {
        let (database, first, _) = database();
        future::block_on(async {
            let tx = database.new_transaction().await.unwrap();
            let result = PersistedMlsGroup::update_own_columns(
                &*tx,
                ConversationIdRef::new(b"another conversation"),
                Some(&first),
                false,
                0,
            );
            assert!(matches!(result, Err(CryptoKeystoreError::NotFound("mls group", _))));
        });
    }
}
