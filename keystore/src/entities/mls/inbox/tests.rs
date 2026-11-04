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
        not_before: StoredCredential::NOT_BEFORE_WITHOUT_CERTIFICATE,
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
        credential_not_before: StoredCredential::NOT_BEFORE_WITHOUT_CERTIFICATE,
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
    smol::block_on(async {
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
    smol::block_on(async {
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
    smol::block_on(async {
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
    smol::block_on(async {
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
