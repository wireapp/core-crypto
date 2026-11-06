use futures_lite::future;
use openmls::prelude::ContentType;
use rstest::rstest;

use crate::{
    Database, Sha256Hash, Transactionlike,
    ancillary::ConversationIdRef,
    entities::{InboxMessage, InboxMessagePk, PersistedMlsGroup, StoredCredential, WaitingFor},
    traits::{DeletableBySearchKey as _, EntityDatabaseMutation as _, FetchFromDatabase as _},
};

const CONVERSATION_ID: &[u8] = b"conversation which buffers a message";
const OTHER_CONVERSATION_ID: &[u8] = b"another conversation, which also buffers a message";
const MESSAGE: &[u8] = b"a message which arrived before we could decrypt it";
const SIBLING_MESSAGE: &[u8] = b"a second buffered message in the same conversation";
const OWN_PUBLIC_KEY: &[u8] = b"the public key of the credential the conversation was created with";
const OWN_CREDENTIAL_TYPE: u16 = 1;

/// An inbox message for `conversation_id`, waiting for epoch 2.
fn inbox_message(conversation_id: &[u8], message: &[u8], arrival_sequence: u64) -> InboxMessage {
    InboxMessage {
        conversation_id: conversation_id.into(),
        message: message.to_vec(),
        content_type: ContentType::Application,
        waiting_for: WaitingFor::Epoch,
        epoch: 2,
        arrival_sequence,
    }
}

/// The message bytes of every inbox message in the store, sorted.
async fn stored_messages(store: &Database) -> Vec<Vec<u8>> {
    let mut messages = store
        .load_all::<InboxMessage>()
        .await
        .unwrap()
        .into_iter()
        .map(std::sync::Arc::unwrap_or_clone)
        .map(|inbox_message| inbox_message.message)
        .collect::<Vec<_>>();
    messages.sort();
    messages
}

/// The primary key of an inbox message, derived independently of [`InboxMessage::primary_key`].
fn primary_key(conversation_id: &[u8], message: &[u8]) -> InboxMessagePk {
    InboxMessagePk::new(conversation_id.into(), Sha256Hash::hash_from(message))
}

/// Save our own credential, which every conversation refers to.
fn save_credential<'a, Tx>(tx: &'a Tx)
where
    &'a Tx: Into<Transactionlike<'a>>,
{
    StoredCredential {
        session_id: b"session id".to_vec(),
        credential: b"our own credential".to_vec(),
        created_at: 0,
        ciphersuite: 1,
        public_key: OWN_PUBLIC_KEY.to_vec(),
        credential_type: OWN_CREDENTIAL_TYPE,
        private_key: b"private key".to_vec(),
    }
    .save(tx)
    .unwrap();
}

/// Save a conversation with id `conversation_id`, which inbox messages can refer to.
///
/// The credential must already have been saved.
fn save_conversation<'a, Tx>(tx: &'a Tx, conversation_id: &[u8], is_pending: bool)
where
    &'a Tx: Into<Transactionlike<'a>>,
{
    PersistedMlsGroup {
        id: conversation_id.into(),
        state: b"group state".to_vec(),
        epoch: 1,
        ciphersuite: 1,
        credential_id: Sha256Hash::hash_from(OWN_PUBLIC_KEY),
        credential_type: OWN_CREDENTIAL_TYPE,
        own_leaf_index: 0,
        is_pending,
        tnt_tx_counter: 0,
    }
    .save(tx)
    .unwrap();
}

/// An inbox message can be saved for an established conversation and for a pending one alike.
///
/// The inbox serves both: a conversation joined by external commit and not yet merged, and a fully established
/// conversation buffering a message it can't process yet. Up to and including V30, `mls_pending_messages` carried a
/// foreign key onto the then-separate `mls_pending_groups`, which the second caller could never satisfy, so its saves
/// failed at commit. The inbox's foreign key points at `mls_groups`, which holds both kinds of conversation.
#[rstest]
#[case::established(false)]
#[case::pending(true)]
fn can_save_an_inbox_message_for_any_conversation(#[case] is_pending: bool) {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let expected = inbox_message(CONVERSATION_ID, MESSAGE, 1);

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, is_pending);
        expected.save(&*tx).unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            store
                .get::<InboxMessage>(&primary_key(CONVERSATION_ID, MESSAGE))
                .await
                .unwrap()
                .as_deref(),
            Some(&expected),
            "an inbox message must survive commit whether or not its conversation is pending"
        );
    });
}

/// A saved inbox message can be read back by the primary key derived from its conversation and bytes.
///
/// Callers build the key from the hash of the message themselves, so the key the entity writes has to agree with it.
#[test]
fn can_get_a_saved_inbox_message_by_primary_key() {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let expected = inbox_message(CONVERSATION_ID, MESSAGE, 1);

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, false);
        expected.save(&*tx).unwrap();
        tx.commit().await.unwrap();

        let fetched = store
            .get::<InboxMessage>(&primary_key(CONVERSATION_ID, MESSAGE))
            .await
            .unwrap()
            .expect("the inbox message was committed, so it must be gettable by primary key");
        assert_eq!(*fetched, expected);
    });
}

/// Deleting by primary key removes exactly that inbox message and leaves its siblings alone.
///
/// The sibling shares a conversation id with the deleted message, so a deletion which matched on the conversation
/// alone would take both rows with it.
#[test]
fn can_delete_an_inbox_message_by_primary_key() {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let doomed_key = primary_key(CONVERSATION_ID, MESSAGE);
        let sibling_key = primary_key(CONVERSATION_ID, SIBLING_MESSAGE);

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, false);
        inbox_message(CONVERSATION_ID, MESSAGE, 1).save(&*tx).unwrap();
        inbox_message(CONVERSATION_ID, SIBLING_MESSAGE, 2).save(&*tx).unwrap();
        tx.commit().await.unwrap();
        assert_eq!(store.count::<InboxMessage>().await.unwrap(), 2);

        let tx = store.new_transaction().await.unwrap();
        InboxMessage::delete(&*tx, &doomed_key).unwrap();
        tx.commit().await.unwrap();

        assert!(
            store.get::<InboxMessage>(&doomed_key).await.unwrap().is_none(),
            "the message deleted by primary key must be gone"
        );
        assert!(
            store.get::<InboxMessage>(&sibling_key).await.unwrap().is_some(),
            "deleting by primary key must not touch other messages in the same conversation"
        );
        assert_eq!(store.count::<InboxMessage>().await.unwrap(), 1);
    });
}

/// Deleting by conversation id takes out every inbox message in that conversation, and nothing else.
///
/// Deletion by primary key and deletion by conversation id reach the database by different routes, so exercising one
/// says nothing about the other.
#[test]
fn can_delete_all_inbox_messages_of_a_conversation() {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let survivor_key = primary_key(OTHER_CONVERSATION_ID, MESSAGE);

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, false);
        save_conversation(&*tx, OTHER_CONVERSATION_ID, false);
        inbox_message(CONVERSATION_ID, MESSAGE, 1).save(&*tx).unwrap();
        inbox_message(CONVERSATION_ID, SIBLING_MESSAGE, 2).save(&*tx).unwrap();
        inbox_message(OTHER_CONVERSATION_ID, MESSAGE, 3).save(&*tx).unwrap();
        tx.commit().await.unwrap();
        assert_eq!(store.count::<InboxMessage>().await.unwrap(), 3);

        let tx = store.new_transaction().await.unwrap();
        InboxMessage::delete_all_matching(&*tx, ConversationIdRef::new(CONVERSATION_ID)).unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            store.count::<InboxMessage>().await.unwrap(),
            1,
            "every message in the cleared conversation must be gone"
        );
        assert!(
            store.get::<InboxMessage>(&survivor_key).await.unwrap().is_some(),
            "clearing one conversation must not touch another conversation's messages"
        );
    });
}

/// Saving a message which is already in the inbox leaves the stored row exactly as it was.
///
/// A redelivered message must keep its original place in the replay order and its original reason for waiting; it is
/// the same message, not a new arrival.
#[test]
fn saving_a_duplicate_inbox_message_changes_nothing() {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let original = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: MESSAGE.to_vec(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::Epoch,
            epoch: 2,
            arrival_sequence: 1,
        };
        let redelivered = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: MESSAGE.to_vec(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::PendingJoin,
            epoch: 7,
            arrival_sequence: 5,
        };

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, false);
        original.save(&*tx).unwrap();
        redelivered
            .save(&*tx)
            .expect("saving a duplicate must succeed without writing anything");
        tx.commit().await.unwrap();

        assert_eq!(
            store
                .get::<InboxMessage>(&primary_key(CONVERSATION_ID, MESSAGE))
                .await
                .unwrap()
                .as_deref(),
            Some(&original),
            "the first copy of a message must keep its arrival sequence, reason and epoch"
        );
    });
}

/// Taking messages by reason and epoch returns exactly the matching ones, in replay order, and removes them.
///
/// Replay order is application messages, then proposals, then commits, and within each content type the order of
/// arrival. The messages here are saved out of that order, so that sorting by either key alone gives a different
/// result. Every other row differs from the taken ones in exactly one respect, and must stay behind.
#[test]
fn take_removes_matching_inbox_messages_and_returns_them_in_replay_order() {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let commit = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: b"commit".to_vec(),
            content_type: ContentType::Commit,
            waiting_for: WaitingFor::Epoch,
            epoch: 2,
            arrival_sequence: 1,
        };
        let late_application = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: b"later application message".to_vec(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::Epoch,
            epoch: 2,
            arrival_sequence: 4,
        };
        let proposal = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: b"proposal".to_vec(),
            content_type: ContentType::Proposal,
            waiting_for: WaitingFor::Epoch,
            epoch: 2,
            arrival_sequence: 3,
        };
        let early_application = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: b"earlier application message".to_vec(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::Epoch,
            epoch: 2,
            arrival_sequence: 2,
        };
        let other_epoch = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: b"waiting for another epoch".to_vec(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::Epoch,
            epoch: 3,
            arrival_sequence: 5,
        };
        let other_reason = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: b"waiting for a proposal".to_vec(),
            content_type: ContentType::Commit,
            waiting_for: WaitingFor::Proposal,
            epoch: 2,
            arrival_sequence: 6,
        };
        let other_conversation = InboxMessage {
            conversation_id: OTHER_CONVERSATION_ID.into(),
            message: b"waiting in another conversation".to_vec(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::Epoch,
            epoch: 2,
            arrival_sequence: 7,
        };

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, false);
        save_conversation(&*tx, OTHER_CONVERSATION_ID, false);
        for inbox_message in [
            &commit,
            &late_application,
            &proposal,
            &early_application,
            &other_epoch,
            &other_reason,
            &other_conversation,
        ] {
            inbox_message.save(&*tx).unwrap();
        }
        let taken = InboxMessage::take(
            &*tx,
            ConversationIdRef::new(CONVERSATION_ID),
            WaitingFor::Epoch,
            Some(2),
        )
        .unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            taken,
            [early_application, late_application, proposal, commit],
            "take must return the matching messages by content type, then by arrival"
        );

        let mut expected_remaining = [other_epoch, other_reason, other_conversation].map(|m| m.message);
        expected_remaining.sort();
        assert_eq!(
            stored_messages(&store).await,
            expected_remaining,
            "take must remove the messages it returns, and only those"
        );
    });
}

/// Taking messages without an epoch returns every message waiting for that reason, whatever its epoch.
///
/// Messages waiting for a pending join can carry any epoch, and all of them become ready when the join is merged.
#[test]
fn take_without_an_epoch_returns_inbox_messages_from_every_epoch() {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let waiting_for_join = [0, 5, 9].map(|epoch| InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: format!("buffered at epoch {epoch}").into_bytes(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::PendingJoin,
            epoch,
            arrival_sequence: epoch + 1,
        });
        let other_reason = InboxMessage {
            conversation_id: CONVERSATION_ID.into(),
            message: b"waiting for an epoch".to_vec(),
            content_type: ContentType::Application,
            waiting_for: WaitingFor::Epoch,
            epoch: 5,
            arrival_sequence: 20,
        };

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, true);
        for inbox_message in waiting_for_join.iter().chain([&other_reason]) {
            inbox_message.save(&*tx).unwrap();
        }
        let taken = InboxMessage::take(
            &*tx,
            ConversationIdRef::new(CONVERSATION_ID),
            WaitingFor::PendingJoin,
            None,
        )
        .unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            taken, waiting_for_join,
            "take without an epoch must return the messages from every epoch"
        );
        assert_eq!(
            stored_messages(&store).await,
            [other_reason.message],
            "take without an epoch must still only remove messages waiting for the given reason"
        );
    });
}

/// Dropping stale messages removes those waiting for an epoch or a proposal from before the new epoch, and nothing
/// else.
///
/// Messages waiting for a pending join are kept whatever their epoch: they wait for the merge, not for an epoch.
#[rstest]
#[case::epoch_before(CONVERSATION_ID, ContentType::Application, WaitingFor::Epoch, 1, true)]
#[case::proposal_before(CONVERSATION_ID, ContentType::Commit, WaitingFor::Proposal, 1, true)]
#[case::epoch_reached(CONVERSATION_ID, ContentType::Application, WaitingFor::Epoch, 2, false)]
#[case::proposal_reached(CONVERSATION_ID, ContentType::Commit, WaitingFor::Proposal, 2, false)]
#[case::epoch_after(CONVERSATION_ID, ContentType::Application, WaitingFor::Epoch, 3, false)]
#[case::pending_join_before(CONVERSATION_ID, ContentType::Application, WaitingFor::PendingJoin, 1, false)]
#[case::other_conversation(OTHER_CONVERSATION_ID, ContentType::Application, WaitingFor::Epoch, 1, false)]
fn drop_stale_removes_only_stale_inbox_messages(
    #[case] conversation_id: &[u8],
    #[case] content_type: ContentType,
    #[case] waiting_for: WaitingFor,
    #[case] epoch: u64,
    #[case] is_stale: bool,
) {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();
        let inbox_message = InboxMessage {
            conversation_id: conversation_id.into(),
            message: MESSAGE.to_vec(),
            content_type,
            waiting_for,
            epoch,
            arrival_sequence: 1,
        };

        let tx = store.new_transaction().await.unwrap();
        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, false);
        save_conversation(&*tx, OTHER_CONVERSATION_ID, false);
        inbox_message.save(&*tx).unwrap();
        let dropped = InboxMessage::drop_stale(&*tx, ConversationIdRef::new(CONVERSATION_ID), 2).unwrap();
        tx.commit().await.unwrap();

        assert_eq!(
            dropped,
            usize::from(is_stale),
            "drop_stale must report how many messages it dropped"
        );
        assert_eq!(
            store.count::<InboxMessage>().await.unwrap(),
            u32::from(!is_stale),
            "drop_stale must remove the message if and only if it is stale"
        );
    });
}

/// The maximum arrival sequence is 0 for an empty inbox, and otherwise the largest sequence number stored.
///
/// It must be the largest, not the latest: messages can be saved with an explicit, older sequence number when they
/// are put back.
#[test]
fn max_arrival_sequence_is_the_largest_stored() {
    future::block_on(async {
        let store = Database::open_in_memory().unwrap();

        let tx = store.new_transaction().await.unwrap();
        assert_eq!(
            InboxMessage::max_arrival_sequence(&tx.conn().unwrap()).unwrap(),
            0,
            "an empty inbox has no arrivals"
        );

        save_credential(&*tx);
        save_conversation(&*tx, CONVERSATION_ID, false);
        for arrival_sequence in [3, 7, 5] {
            inbox_message(
                CONVERSATION_ID,
                format!("arrival {arrival_sequence}").as_bytes(),
                arrival_sequence,
            )
            .save(&*tx)
            .unwrap();
        }

        assert_eq!(
            InboxMessage::max_arrival_sequence(&tx.conn().unwrap()).unwrap(),
            7,
            "the maximum is the largest sequence number, not the most recently saved one"
        );
        tx.commit().await.unwrap();
    });
}
