//! Shared fixtures for the tests of openmls's storage.

mod access;
mod group_state;
mod keys;

use futures_lite::future;
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key, traits};
use serde::{Deserialize, Serialize};

use crate::{
    Database, Sha256Hash, Transaction,
    entities::{PersistedMlsGroup, StoredCredential},
    traits::EntityDatabaseMutation as _,
};

const GROUP_ID: &[u8] = b"a conversation";
const OWN_PUBLIC_KEY: &[u8] = b"the public key of our credential";
const OWN_CREDENTIAL_TYPE: u16 = 1;

/// Stands in for the openmls types we can't construct outside openmls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Bytes(Vec<u8>);

impl Key<CURRENT_VERSION> for Bytes {}
impl Entity<CURRENT_VERSION> for Bytes {}
impl traits::TreeSync<CURRENT_VERSION> for Bytes {}
impl traits::InterimTranscriptHash<CURRENT_VERSION> for Bytes {}
impl traits::LeafNode<CURRENT_VERSION> for Bytes {}
impl traits::QueuedProposal<CURRENT_VERSION> for Bytes {}
impl traits::ProposalRef<CURRENT_VERSION> for Bytes {}

fn bytes(value: &[u8]) -> Bytes {
    Bytes(value.to_vec())
}

/// A database with a credential, and the group's row if `with_group` is set.
fn database(with_group: bool) -> std::sync::Arc<Database> {
    future::block_on(async {
        let database = Database::open_in_memory().unwrap();
        let tx = database.new_transaction().await.unwrap();
        StoredCredential {
            session_id: b"session id".to_vec(),
            credential: b"our credential".to_vec(),
            created_at: 0,
            ciphersuite: 1,
            public_key: OWN_PUBLIC_KEY.to_vec(),
            credential_type: OWN_CREDENTIAL_TYPE,
            not_before: StoredCredential::NOT_BEFORE_WITHOUT_CERTIFICATE,
            private_key: b"private key".to_vec(),
        }
        .save(&*tx)
        .unwrap();
        if with_group {
            PersistedMlsGroup {
                id: GROUP_ID.into(),
                epoch: 0,
                ciphersuite: 1,
                credential_id: Sha256Hash::hash_from(OWN_PUBLIC_KEY),
                credential_type: OWN_CREDENTIAL_TYPE,
                credential_not_before: StoredCredential::NOT_BEFORE_WITHOUT_CERTIFICATE,
                own_leaf_index: 0,
                is_pending: false,
                tnt_tx_counter: 0,
            }
            .save(&*tx)
            .unwrap();
        }
        tx.commit().await.unwrap();
        database
    })
}

fn column<T: rusqlite::types::FromSql>(tx: &Transaction, column: &str) -> T {
    tx.conn()
        .unwrap()
        .query_row(
            &format!("SELECT {column} FROM mls_groups WHERE id = ?"),
            [GROUP_ID],
            |row| row.get(0),
        )
        .unwrap()
}
