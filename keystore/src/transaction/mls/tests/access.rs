//! Reading and writing through each way of reaching the tables.

use futures_lite::future;
use openmls::group::GroupId;
use openmls_traits::storage::StorageProvider as _;

use super::{Bytes, GROUP_ID, bytes, database};
use crate::{CryptoKeystoreError, transaction::mls::MlsStorage};

#[test]
fn read_only_storage_reads_committed_state() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        MlsStorage::from(&*tx).write_tree(&group_id, &bytes(b"tree")).unwrap();
        tx.commit().await.unwrap();
    });

    let storage = MlsStorage::read_only(&database);
    assert_eq!(storage.tree::<_, Bytes>(&group_id).unwrap(), Some(bytes(b"tree")));
}

#[test]
fn read_only_storage_reads_through_the_transaction_in_flight() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        MlsStorage::from(&*tx).write_tree(&group_id, &bytes(b"tree")).unwrap();

        let storage = MlsStorage::read_only(&database);
        assert_eq!(storage.tree::<_, Bytes>(&group_id).unwrap(), Some(bytes(b"tree")));
    });
}

#[test]
fn read_only_storage_rejects_writes() {
    let database = database(true);
    let storage = MlsStorage::read_only(&database);
    let result = storage.write_tree(&GroupId::from_slice(GROUP_ID), &bytes(b"tree"));
    assert!(matches!(
        result,
        Err(CryptoKeystoreError::MutatingOperationWithoutTransaction)
    ));
}

#[test]
fn a_read_connection_waits_for_a_held_lock() {
    let database = database(true);
    let group_id = GroupId::from_slice(GROUP_ID);
    future::block_on(async {
        let tx = database.new_transaction().await.unwrap();
        MlsStorage::from(&*tx).write_tree(&group_id, &bytes(b"tree")).unwrap();
        tx.commit().await.unwrap();

        let held = database.raw_conn().await;
        let mut read_connection = std::pin::pin!(database.mls_read_connection());
        assert!(
            future::poll_once(&mut read_connection).await.is_none(),
            "the read connection must wait while the lock is held"
        );

        drop(held);
        let read_connection = read_connection.await;
        assert_eq!(
            read_connection.storage().tree::<_, Bytes>(&group_id).unwrap(),
            Some(bytes(b"tree"))
        );
    });
}

#[test]
fn a_read_connection_rejects_writes() {
    let database = database(true);
    future::block_on(async {
        let read_connection = database.mls_read_connection().await;
        let result = read_connection
            .storage()
            .write_tree(&GroupId::from_slice(GROUP_ID), &bytes(b"tree"));
        assert!(matches!(
            result,
            Err(CryptoKeystoreError::MutatingOperationWithoutTransaction)
        ));
    });
}

#[test]
fn read_only_storage_fails_instead_of_waiting_for_a_held_lock() {
    let database = database(true);
    future::block_on(async {
        let _held = database.raw_conn().await;
        let storage = MlsStorage::read_only(&database);
        let result = storage.tree::<_, Bytes>(&GroupId::from_slice(GROUP_ID));
        assert!(matches!(result, Err(CryptoKeystoreError::Busy)));
    });
}
