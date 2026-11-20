//! A database written by core-crypto on the old openmls fork still works after it has been migrated.
//!
//! The fixture was generated on `main` at f596f1a5e7, before the move to upstream openmls. Alice, Bob and Carol share
//! a conversation which has been through a few epochs, with an external sender, and in which everyone has sent a
//! message. Alice holds a pending proposal of Bob's to remove Carol. `alice.sqlite` is a copy of Alice's database at
//! that point. `fixture.json` holds what Alice receives afterwards:
//!
//! - `before_commit`: a message Carol sent before Bob's proposal
//! - `commit`: Bob's commit of his proposal
//! - `after_commit`: a message of Bob's in the epoch the commit starts
//!
//! `alice_key_package.sqlite` is a copy of another database of Alice's, made the same way, after she generated a key
//! package. `key_package_fixture.json` holds Bob's welcome to that key package, and a message of his after it.

use std::sync::Arc;

use openmls::prelude::tls_codec::Deserialize as _;

use crate::{
    ClientIdRef, CoreCrypto, Database, DatabaseKey,
    mls::conversation::{ConversationId, DecryptedMessage},
    test_utils::{CoreCryptoTransportSuccessProvider, message::DecryptedMessagesExt, tmp_db_file},
};

const DATABASE: &[u8] = include_bytes!("legacy_database_tests/alice.sqlite");
const FIXTURE: &str = include_str!("legacy_database_tests/fixture.json");
const KEY_PACKAGE_DATABASE: &[u8] = include_bytes!("legacy_database_tests/alice_key_package.sqlite");
const KEY_PACKAGE_FIXTURE: &str = include_str!("legacy_database_tests/key_package_fixture.json");

fn field(fixture: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(fixture[name].as_str().unwrap()).unwrap()
}

/// Open a copy of a database, migrating it, and initialize MLS for the client it belongs to.
async fn open(database: &[u8], fixture: &serde_json::Value) -> (Arc<CoreCrypto>, tempfile::TempDir) {
    let (path, dir) = tmp_db_file();
    std::fs::write(&path, database).unwrap();
    let key = DatabaseKey::try_from(field(fixture, "database_key").as_slice()).unwrap();

    let core_crypto = CoreCrypto::new(Database::open(&path, &key).await.unwrap());
    let transaction = core_crypto.new_transaction().await.unwrap();
    transaction
        .mls_init(
            ClientIdRef::new(&field(fixture, "client_id")).to_owned(),
            Arc::new(CoreCryptoTransportSuccessProvider::default()),
        )
        .await
        .unwrap();
    transaction.finish().await.unwrap();
    (core_crypto, dir)
}

fn application_message(decrypted: DecryptedMessage) -> Vec<u8> {
    match decrypted {
        DecryptedMessage::ApplicationMessage(message) => message.plaintext,
        other => panic!("expected an application message, got {other:?}"),
    }
}

#[macro_rules_attribute::apply(smol_macros::test)]
async fn a_conversation_from_the_old_openmls_fork_still_works_after_migration() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let (core_crypto, _dir) = open(DATABASE, &fixture).await;
    let transaction = core_crypto.new_transaction().await.unwrap();
    let id = ConversationId::from(field(&fixture, "conversation_id").as_slice());
    let mut conversation = transaction.conversation(&id).await.unwrap();
    assert_eq!(conversation.get_client_ids().await.unwrap().len(), 3);
    let epoch = conversation.epoch().await;

    let before_commit = conversation
        .decrypt_message(field(&fixture, "before_commit"))
        .await
        .unwrap()
        .into_single_decrypted();
    assert_eq!(application_message(before_commit), b"before the commit");

    conversation.decrypt_message(field(&fixture, "commit")).await.unwrap();
    assert_eq!(conversation.epoch().await, epoch + 1);
    assert_eq!(
        conversation.get_client_ids().await.unwrap().len(),
        2,
        "the commit of the pending proposal must have removed Carol"
    );

    let after_commit = conversation
        .decrypt_message(field(&fixture, "after_commit"))
        .await
        .unwrap()
        .into_single_decrypted();
    assert_eq!(application_message(after_commit), b"after the commit");

    // Alice's own credential came through too: she can still sign.
    conversation.encrypt_message(b"alice is still here").await.unwrap();

    drop(conversation);
    transaction.finish().await.unwrap();
}

#[macro_rules_attribute::apply(smol_macros::test)]
async fn a_key_package_from_the_old_openmls_fork_can_be_joined_with_after_migration() {
    let fixture: serde_json::Value = serde_json::from_str(KEY_PACKAGE_FIXTURE).unwrap();
    let (core_crypto, _dir) = open(KEY_PACKAGE_DATABASE, &fixture).await;
    let transaction = core_crypto.new_transaction().await.unwrap();

    let welcome = openmls::prelude::MlsMessageIn::tls_deserialize_exact(field(&fixture, "welcome")).unwrap();
    let id = transaction.process_welcome_message(welcome).await.unwrap();
    assert_eq!(id, ConversationId::from(field(&fixture, "conversation_id").as_slice()));

    let message = transaction
        .conversation(&id)
        .await
        .unwrap()
        .decrypt_message(field(&fixture, "message"))
        .await
        .unwrap()
        .into_single_decrypted();
    assert_eq!(application_message(message), b"welcome, alice");
    transaction.finish().await.unwrap();
}
