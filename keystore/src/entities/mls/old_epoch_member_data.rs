use const_format::formatcp;
use rusqlite::{OptionalExtension as _, named_params};

use crate::{
    CryptoKeystoreResult, Sha256Hash, Transactionlike,
    ancillary::{ConversationEpochsOlderThan, ConversationId, ConversationIdRef, helpers::count_helper},
    traits::{
        BorrowPrimaryKey, DeletableBySearchKey, Entity, EntityDatabaseMutation, EntityDeleteBorrowed,
        EntityGetBorrowed, PrimaryKey, SearchableEntity,
    },
};

/// Primary key for [`OldEpochMemberData`]; owned form.
///
/// See [`OldEpochMemberDataPkRef`] for the borrowed form.
#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct OldEpochMemberDataPk {
    conversation_id: ConversationId,
    epoch: u64,
    leaf_node_index: u32,
}

impl PrimaryKey for OldEpochMemberData {
    type PrimaryKey = OldEpochMemberDataPk;

    fn primary_key(&self) -> Self::PrimaryKey {
        OldEpochMemberDataPk::new(self.conversation_id.clone(), self.epoch, self.leaf_node_index)
    }
}

/// Primary key for [`OldEpochMemberData`]; borrowed form.
///
/// See [`OldEpochMemberDataPk`] for the owned form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, derive_more::Constructor)]
pub struct OldEpochMemberDataPkRef<'a> {
    conversation_id: &'a ConversationIdRef,
    epoch: u64,
    leaf_node_index: u32,
}

impl BorrowPrimaryKey for OldEpochMemberData {
    type BorrowedPrimaryKey<'a> = OldEpochMemberDataPkRef<'a>;

    fn borrow_primary_key(&self) -> Self::BorrowedPrimaryKey<'_> {
        OldEpochMemberDataPkRef::new(self.conversation_id.as_ref(), self.epoch, self.leaf_node_index)
    }
}

impl<'a> From<&'a OldEpochMemberDataPk> for OldEpochMemberDataPkRef<'a> {
    fn from(
        OldEpochMemberDataPk {
            conversation_id,
            epoch,
            leaf_node_index,
        }: &'a OldEpochMemberDataPk,
    ) -> Self {
        OldEpochMemberDataPkRef {
            conversation_id: ConversationIdRef::new(conversation_id),
            epoch: *epoch,
            leaf_node_index: *leaf_node_index,
        }
    }
}

impl From<OldEpochMemberDataPkRef<'_>> for OldEpochMemberDataPk {
    fn from(key: OldEpochMemberDataPkRef<'_>) -> Self {
        Self::new(key.conversation_id.into(), key.epoch, key.leaf_node_index)
    }
}

/// Member data for TNT messages, keyed by `(ConversationId, epoch, leaf_node_index)`.
#[derive(core_crypto_macros::Debug, Clone, PartialEq, Eq)]
pub struct OldEpochMemberData {
    pub conversation_id: ConversationId,
    pub epoch: u64,
    pub leaf_node_index: u32,
    // both of these contain public, non-sensitive information
    pub credential: Vec<u8>,
    pub signature_key: Vec<u8>,
}

impl OldEpochMemberData {
    /// name of the main table
    const OLD_EPOCH_MEMBER_DATA: &str = "old_epoch_member_data";
    /// name of the foreign credentials table where credentials are actually stored
    const FOREIGN_CREDENTIALS: &str = "foreign_credentials";

    fn foreign_credentials_hash(&self) -> Sha256Hash {
        let credential_len = (self.credential.len() as u64).to_be_bytes();
        let signature_key_len = (self.signature_key.len() as u64).to_be_bytes();
        Sha256Hash::hash_from_many([
            credential_len.as_slice(),
            &self.credential,
            &signature_key_len,
            &self.signature_key,
        ])
    }

    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            conversation_id: row.get("conversation_id")?,
            epoch: row.get("epoch")?,
            leaf_node_index: row.get("leaf_node_index")?,
            credential: row.get("credential")?,
            signature_key: row.get("signature_key")?,
        })
    }
}

// -------------------------------------------------------------------------------------------------------
// For efficiency, we've split the entity storage for this entity into two SQL tables:
// OLD_EPOCH_MEMBER_DATA and FOREIGN_CREDENTIALS.
//
// This is because most users actually use the same credential across multiple conversations and epochs,
// so we can save quite a bit of storage by collapsing all those down to references.
//
// This is great for storage efficiency and fine in most other cases, but it does mean that
// we have to hand-write all the entity trait family impls.

impl EntityGetBorrowed for OldEpochMemberData {
    fn get_borrowed(
        conn: &rusqlite::Connection,
        key: Self::BorrowedPrimaryKey<'_>,
    ) -> CryptoKeystoreResult<Option<Self>> {
        let sql = formatcp!(
            "
            SELECT * FROM {oemd}
            INNER JOIN {fc}
                ON {oemd}.foreign_credential_hash = {fc}.hash
            WHERE conversation_id = :conversation_id
            AND epoch = :epoch
            AND leaf_node_index = :leaf_node_index",
            oemd = OldEpochMemberData::OLD_EPOCH_MEMBER_DATA,
            fc = OldEpochMemberData::FOREIGN_CREDENTIALS
        );

        conn.prepare_cached(sql)?
            .query_row(
                named_params! {
                    ":conversation_id": key.conversation_id,
                    ":epoch": key.epoch,
                    ":leaf_node_index": key.leaf_node_index,
                },
                Self::from_row,
            )
            .optional()
            .map_err(Into::into)
    }
}

impl Entity for OldEpochMemberData {
    const TABLE_NAME: &str = Self::OLD_EPOCH_MEMBER_DATA;

    fn get(conn: &rusqlite::Connection, key: &OldEpochMemberDataPk) -> CryptoKeystoreResult<Option<Self>> {
        Self::get_borrowed(conn, key.into())
    }

    fn count(conn: &rusqlite::Connection) -> CryptoKeystoreResult<u32> {
        count_helper::<Self>(conn)
    }

    fn load_all(conn: &rusqlite::Connection) -> CryptoKeystoreResult<Vec<Self>> {
        let sql = formatcp!(
            "
            SELECT * FROM {oemd}
            INNER JOIN {fc}
                ON {oemd}.foreign_credential_hash = {fc}.hash",
            oemd = OldEpochMemberData::OLD_EPOCH_MEMBER_DATA,
            fc = OldEpochMemberData::FOREIGN_CREDENTIALS
        );
        conn.prepare_cached(sql)?
            .query_map([], Self::from_row)?
            .collect::<Result<_, _>>()
            .map_err(Into::into)
    }
}

impl EntityDatabaseMutation for OldEpochMemberData {
    fn save<'a, Tx>(&self, tx: &'a Tx) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;

        let hash = self.foreign_credentials_hash();

        // step 1: insert the foreign credential, silently succeeding if it already exists
        conn.prepare_cached(formatcp!(
            "
            INSERT INTO {fc} ( hash,  credential,  signature_key)
            VALUES           (:hash, :credential, :signature_key)
            ON CONFLICT (hash) DO NOTHING",
            fc = OldEpochMemberData::FOREIGN_CREDENTIALS,
        ))?
        .execute(named_params! {
            ":hash": hash,
            ":credential": &self.credential,
            ":signature_key": &self.signature_key,
        })?;

        // step 2: insert the primary row, raising an error if it already exists
        conn.prepare_cached(formatcp!(
            "
            INSERT INTO {oemd} ( conversation_id,  epoch,  leaf_node_index,  foreign_credential_hash)
            VALUES             (:conversation_id, :epoch, :leaf_node_index, :foreign_credential_hash)",
            oemd = OldEpochMemberData::OLD_EPOCH_MEMBER_DATA,
        ))?
        .execute(named_params! {
            ":conversation_id": &self.conversation_id,
            ":epoch": self.epoch,
            ":leaf_node_index": self.leaf_node_index,
            ":foreign_credential_hash": hash,
        })?;

        Ok(())
    }

    fn delete<'a, Tx>(tx: &'a Tx, key: &OldEpochMemberDataPk) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        Self::delete_borrowed(tx, key.into())
    }
}

impl EntityDeleteBorrowed for OldEpochMemberData {
    fn delete_borrowed<'a, Tx>(tx: &'a Tx, key: Self::BorrowedPrimaryKey<'_>) -> CryptoKeystoreResult<bool>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        // note that we intentionally don't mess with FOREIGN_CREDENTIALS;
        // we depend on the SQL trigger to clean those up once there are no more referents
        conn.prepare_cached(formatcp!(
            "DELETE FROM {}
            WHERE conversation_id = :conversation_id
            AND epoch = :epoch
            AND leaf_node_index = :leaf_node_index",
            OldEpochMemberData::OLD_EPOCH_MEMBER_DATA
        ))?
        .execute(named_params! {
            ":conversation_id": &key.conversation_id,
            ":epoch": key.epoch,
            ":leaf_node_index": key.leaf_node_index,
        })
        .map(|affected_rows| affected_rows > 0)
        .map_err(Into::into)
    }
}

impl SearchableEntity<ConversationEpochsOlderThan<'_>> for OldEpochMemberData {
    fn find_all_matching(
        conn: &rusqlite::Connection,
        conversation_epoch: &ConversationEpochsOlderThan,
    ) -> CryptoKeystoreResult<Vec<Self>> {
        let mut stmt = conn.prepare_cached(formatcp!(
            "
            SELECT * FROM {oemd}
            INNER JOIN {fc}
                ON {oemd}.foreign_credential_hash = {fc}.hash
            WHERE conversation_id = ? AND epoch < ?",
            oemd = OldEpochMemberData::OLD_EPOCH_MEMBER_DATA,
            fc = OldEpochMemberData::FOREIGN_CREDENTIALS,
        ))?;
        stmt.query_map(
            rusqlite::params![conversation_epoch.conversation_id, conversation_epoch.epoch],
            Self::from_row,
        )?
        .collect::<Result<_, _>>()
        .map_err(Into::into)
    }

    fn matches(&self, conversation_epoch: &ConversationEpochsOlderThan) -> bool {
        &self.conversation_id == conversation_epoch.conversation_id && self.epoch < conversation_epoch.epoch
    }
}

impl DeletableBySearchKey<ConversationEpochsOlderThan<'_>> for OldEpochMemberData {
    fn delete_all_matching<'a, Tx>(
        tx: &'a Tx,
        conversation_epoch: &ConversationEpochsOlderThan,
    ) -> CryptoKeystoreResult<()>
    where
        &'a Tx: Into<Transactionlike<'a>>,
    {
        let conn = tx.into().conn()?;
        // we don't need a dedicated index because these are already the first two fields of the primary key
        let mut stmt = conn.prepare_cached(formatcp!(
            "DELETE FROM {} WHERE conversation_id = ? AND epoch < ?",
            OldEpochMemberData::TABLE_NAME
        ))?;
        stmt.execute(rusqlite::params![
            conversation_epoch.conversation_id,
            conversation_epoch.epoch
        ])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use futures_lite::future;

    use super::*;
    use crate::{
        Database,
        entities::{OldEpochData, PersistedMlsGroup, StoredCredential},
    };

    const CONVERSATION_A: &[u8] = b"conversation a";
    const CONVERSATION_B: &[u8] = b"conversation b";
    const OWN_PUBLIC_KEY: &[u8] = b"the public key of the credential both conversations were created with";
    const OWN_CREDENTIAL_TYPE: u16 = 1;

    fn make_group(id: &[u8]) -> PersistedMlsGroup {
        PersistedMlsGroup {
            id: id.into(),
            state: b"group state".to_vec(),
            epoch: 2,
            ciphersuite: 1,
            credential_id: Sha256Hash::hash_from(OWN_PUBLIC_KEY),
            credential_type: OWN_CREDENTIAL_TYPE,
            own_leaf_index: 0,
            is_pending: false,
            tnt_tx_counter: 0,
        }
    }

    fn make_old_epoch_data(conversation_id: &[u8], epoch: u64) -> OldEpochData {
        OldEpochData {
            conversation_id: conversation_id.into(),
            epoch,
            hpke_private_key: b"hpke private key".to_vec(),
            group_context: b"group context".to_vec(),
            targeted_message_psk: b"psk".to_vec(),
        }
    }

    fn make_old_epoch_member_data(
        conversation_id: &[u8],
        epoch: u64,
        leaf_node_index: u32,
        credential: &[u8],
    ) -> OldEpochMemberData {
        OldEpochMemberData {
            conversation_id: conversation_id.into(),
            epoch,
            leaf_node_index,
            credential: credential.to_vec(),
            signature_key: b"signature key".to_vec(),
        }
    }

    async fn remaining_foreign_credentials(store: &Database) -> Vec<Sha256Hash> {
        let conn = store.conn().await;
        let mut statement = conn
            .prepare("SELECT hash FROM foreign_credentials ORDER BY hash")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .expect("reading the remaining foreign credentials")
    }

    /// A foreign credential is kept while any member row still refers to it, and dropped with the last one.
    ///
    /// `foreign_credentials` is shared across epochs and conversations, so nothing can cascade into it.
    /// The `drop_unreferenced_foreign_credential` trigger stands in for that cascade. Member rows are
    /// only ever removed by cascade, so this test deletes in the same places the library does: pruning
    /// old epochs from `old_epoch_data`, and wiping a whole conversation from `mls_groups`.
    #[test]
    fn foreign_credential_is_dropped_with_its_last_reference() {
        // In both conversations, in every epoch.
        let make_shared_oemd = |conversation_id, epoch, leaf_node_index| {
            make_old_epoch_member_data(
                conversation_id,
                epoch,
                leaf_node_index,
                b"a credential shared across epochs and conversations",
            )
        };
        // Only in conversation a's first epoch, e.g. a member who has since rotated their key.
        let rotated_away = make_old_epoch_member_data(
            CONVERSATION_A,
            1,
            1,
            b"a credential used only in conversation a, epoch 1",
        );

        future::block_on(async {
            let store = Database::open_in_memory().unwrap();

            let tx = store.new_transaction().await.unwrap();
            StoredCredential {
                session_id: b"session id".to_vec(),
                credential: b"our own credential".to_vec(),
                created_at: 0,
                ciphersuite: 1,
                public_key: OWN_PUBLIC_KEY.to_vec(),
                credential_type: OWN_CREDENTIAL_TYPE,
                private_key: b"private key".to_vec(),
            }
            .save(&*tx)
            .unwrap();
            for conversation_id in [CONVERSATION_A, CONVERSATION_B] {
                make_group(conversation_id).save(&*tx).unwrap();
            }
            for (conversation_id, epoch_number) in [(CONVERSATION_A, 1), (CONVERSATION_A, 2), (CONVERSATION_B, 1)] {
                make_old_epoch_data(conversation_id, epoch_number).save(&*tx).unwrap();
                make_shared_oemd(conversation_id, epoch_number, 0).save(&*tx).unwrap();
            }
            rotated_away.save(&*tx).unwrap();
            tx.commit().await.unwrap();

            let shared_hash = make_shared_oemd(CONVERSATION_A, 1, 0).foreign_credentials_hash();

            let tx = store.new_transaction().await.unwrap();
            OldEpochData::delete_all_matching(
                &*tx,
                &ConversationEpochsOlderThan::new(ConversationIdRef::new(CONVERSATION_A), 2),
            )
            .unwrap();
            tx.commit().await.unwrap();
            assert_eq!(
                remaining_foreign_credentials(&store).await,
                [shared_hash],
                "pruning an epoch must drop the credentials only it referred to, and keep the ones other epochs \
                 still refer to"
            );

            let tx = store.new_transaction().await.unwrap();
            PersistedMlsGroup::delete(&*tx, &CONVERSATION_A.into()).unwrap();
            tx.commit().await.unwrap();
            assert_eq!(
                remaining_foreign_credentials(&store).await,
                [shared_hash],
                "wiping a conversation must keep the credentials another conversation still refers to"
            );

            let tx = store.new_transaction().await.unwrap();
            PersistedMlsGroup::delete(&*tx, &CONVERSATION_B.into()).unwrap();
            tx.commit().await.unwrap();
            assert!(
                remaining_foreign_credentials(&store).await.is_empty(),
                "once nothing refers to a foreign credential it must be gone"
            );
        });
    }
}
