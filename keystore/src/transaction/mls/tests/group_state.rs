//! Writing a group's state, and reading it back.

use futures_lite::future;
use openmls::{
    group::{GroupId, MlsGroupState},
    prelude::LeafNodeIndex,
};
use openmls_traits::storage::StorageProvider as _;

use super::{Bytes, GROUP_ID, bytes, column, database};
use crate::{
    CryptoKeystoreError,
    ancillary::ConversationIdRef,
    entities::PersistedMlsGroup,
    ser,
    traits::EntityGetBorrowed as _,
    transaction::mls::{MlsStorage, group_state::group_state_tag},
};

#[test]
fn writing_state_of_a_group_without_a_row_fails() {
    let database = database(false);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        let storage = MlsStorage::from(&*tx);
        let result = storage.write_tree(&GroupId::from_slice(GROUP_ID), &bytes(b"tree"));
        assert!(matches!(result, Err(CryptoKeystoreError::NotFound("mls group", _))));
    });
}

#[test]
fn tree_reads_back_until_deleted() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        let storage = MlsStorage::from(&*tx);
        assert_eq!(storage.tree::<_, Bytes>(&group_id).unwrap(), None);

        storage.write_tree(&group_id, &bytes(b"tree")).unwrap();
        assert_eq!(storage.tree::<_, Bytes>(&group_id).unwrap(), Some(bytes(b"tree")));

        storage.delete_tree(&group_id).unwrap();
        assert_eq!(storage.tree::<_, Bytes>(&group_id).unwrap(), None);
    });
}

#[test]
fn interim_transcript_hash_is_stored_as_raw_bytes() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        let storage = MlsStorage::from(&*tx);
        storage
            .write_interim_transcript_hash(&group_id, &bytes(b"hash"))
            .unwrap();
        assert_eq!(column::<Vec<u8>>(&tx, "interim_transcript_hash"), b"hash");
        assert_eq!(
            storage.interim_transcript_hash::<_, Bytes>(&group_id).unwrap(),
            Some(bytes(b"hash"))
        );
    });
}

#[test]
fn own_leaf_index_is_stored_in_the_groups_own_leaf_index_column() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        let storage = MlsStorage::from(&*tx);
        storage
            .write_own_leaf_index(&group_id, &LeafNodeIndex::new(300))
            .unwrap();

        let conn = tx.conn().unwrap();
        let group = PersistedMlsGroup::get_borrowed(&conn, ConversationIdRef::new(GROUP_ID))
            .unwrap()
            .unwrap();
        drop(conn);
        assert_eq!(group.own_leaf_index, 300);
        assert_eq!(
            storage.own_leaf_index::<_, LeafNodeIndex>(&group_id).unwrap(),
            Some(LeafNodeIndex::new(300))
        );
    });
}

#[test]
fn group_state_tags_are_the_variant_indices() {
    assert_eq!(
        ser(&MlsGroupState::Operational).unwrap(),
        [group_state_tag::OPERATIONAL]
    );
    assert_eq!(ser(&MlsGroupState::Inactive).unwrap(), [group_state_tag::INACTIVE]);
}

#[test]
fn group_state_is_stored_as_its_status() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        let storage = MlsStorage::from(&*tx);
        assert!(storage.group_state::<MlsGroupState, _>(&group_id).unwrap().is_none());

        storage.write_group_state(&group_id, &MlsGroupState::Inactive).unwrap();
        assert_eq!(column::<u8>(&tx, "group_status"), 2);
        assert!(matches!(
            storage.group_state::<MlsGroupState, _>(&group_id).unwrap(),
            Some(MlsGroupState::Inactive)
        ));

        storage
            .write_group_state(&group_id, &MlsGroupState::Operational)
            .unwrap();
        assert_eq!(column::<u8>(&tx, "group_status"), 0);
        assert!(matches!(
            storage.group_state::<MlsGroupState, _>(&group_id).unwrap(),
            Some(MlsGroupState::Operational)
        ));

        storage.delete_group_state(&group_id).unwrap();
        assert!(storage.group_state::<MlsGroupState, _>(&group_id).unwrap().is_none());
    });
}

#[test]
fn own_leaf_nodes_read_back_in_append_order() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        let storage = MlsStorage::from(&*tx);
        for leaf_node in [b"c", b"a", b"b"] {
            storage.append_own_leaf_node(&group_id, &bytes(leaf_node)).unwrap();
        }
        assert_eq!(
            storage.own_leaf_nodes::<_, Bytes>(&group_id).unwrap(),
            [bytes(b"c"), bytes(b"a"), bytes(b"b")]
        );

        storage.delete_own_leaf_nodes(&group_id).unwrap();
        assert!(storage.own_leaf_nodes::<_, Bytes>(&group_id).unwrap().is_empty());
    });
}

#[test]
fn queued_proposals_read_back_in_queue_order_and_requeuing_keeps_the_first() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        let storage = MlsStorage::from(&*tx);
        for proposal_ref in [b"3", b"1", b"2"] {
            storage
                .queue_proposal(&group_id, &bytes(proposal_ref), &bytes(b"first"))
                .unwrap();
        }
        storage
            .queue_proposal(&group_id, &bytes(b"1"), &bytes(b"second"))
            .unwrap();

        assert_eq!(
            storage.queued_proposal_refs::<_, Bytes>(&group_id).unwrap(),
            [bytes(b"3"), bytes(b"1"), bytes(b"2")]
        );
        assert_eq!(
            storage.queued_proposals::<_, Bytes, Bytes>(&group_id).unwrap(),
            [
                (bytes(b"3"), bytes(b"first")),
                (bytes(b"1"), bytes(b"first")),
                (bytes(b"2"), bytes(b"first")),
            ]
        );

        storage.remove_proposal(&group_id, &bytes(b"1")).unwrap();
        assert_eq!(
            storage.queued_proposal_refs::<_, Bytes>(&group_id).unwrap(),
            [bytes(b"3"), bytes(b"2")]
        );

        storage.clear_proposal_queue::<_, Bytes>(&group_id).unwrap();
        assert!(storage.queued_proposal_refs::<_, Bytes>(&group_id).unwrap().is_empty());
    });
}
