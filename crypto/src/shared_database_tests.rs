//! Several [`CoreCrypto`] instances sharing one database.
//!
//! On iOS, the app and its notification service extension run in separate processes, and both open
//! the same database file. Each process has its own [`CoreCrypto`], and so its own in-memory caches
//! of proteus sessions and MLS conversations. The transaction lock serialises their writes, but
//! nothing tells one instance that the other has changed state it has cached.
//!
//! These tests model the two processes as two instances in one process, each with its own
//! connection to the same database file, and check that state moved on by one instance is seen by
//! the other. They also cover a transaction which is rolled back after mutating cached state, which
//! leaves the cache ahead of the database in the same way.
//!
//! See WPB-27280.

use std::sync::Arc;

use crate::{CoreCrypto, Database, DatabaseKey};

#[cfg(feature = "proteus")]
mod proteus {
    use proteus_wasm::message::Envelope;

    use super::*;
    use crate::test_utils::{proteus_utils::CryptoboxLike, tmp_db_file};

    const SESSION_ID: &str = "bob";

    /// Open an independent instance on the database, as a second process would.
    async fn open_instance(path: &str, key: &DatabaseKey) -> Arc<CoreCrypto> {
        let database = Database::open(path, key).await.unwrap();
        let core_crypto = CoreCrypto::new(database);
        let transaction = core_crypto.new_transaction().await.unwrap();
        transaction.proteus_init().await.unwrap();
        transaction.finish().await.unwrap();
        core_crypto
    }

    /// Decrypt in a transaction of its own, which is committed on success and aborted on failure.
    async fn decrypt(core_crypto: &Arc<CoreCrypto>, ciphertext: &[u8]) -> crate::transaction_context::Result<Vec<u8>> {
        let transaction = core_crypto.new_transaction().await.unwrap();
        match transaction.proteus_decrypt(SESSION_ID, ciphertext).await {
            Ok(plaintext) => {
                transaction.finish().await.unwrap();
                Ok(plaintext)
            }
            Err(err) => {
                transaction.abort().await.unwrap();
                Err(err)
            }
        }
    }

    /// Encrypt in a transaction of its own, and commit it.
    async fn encrypt(core_crypto: &Arc<CoreCrypto>, plaintext: &[u8]) -> Vec<u8> {
        let transaction = core_crypto.new_transaction().await.unwrap();
        let ciphertext = transaction.proteus_encrypt(SESSION_ID, plaintext).await.unwrap();
        transaction.finish().await.unwrap();
        ciphertext
    }

    /// Bob's side of the session, with the result rather than a panic on failure.
    async fn bob_decrypts(bob: &mut CryptoboxLike, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let envelope = Envelope::deserialise(ciphertext).unwrap();
        bob.sessions
            .get_mut(SESSION_ID)
            .unwrap()
            .decrypt(&bob.prekeys, &envelope)
            .await
            .map_err(|err| format!("{err:?}"))
    }

    /// Establish a session between `alice` and Bob, with one message in each direction.
    ///
    /// Having heard from Alice, Bob ratchets forward with his next message, so whoever decrypts that
    /// message ratchets too, generating a fresh ratchet key of their own.
    async fn establish_session(alice: &Arc<CoreCrypto>) -> CryptoboxLike {
        let mut bob = CryptoboxLike::init();

        let transaction = alice.new_transaction().await.unwrap();
        let prekey_bundle = transaction.proteus_new_prekey(1).await.unwrap();
        transaction.finish().await.unwrap();

        bob.init_session_from_prekey_bundle(SESSION_ID, &prekey_bundle);
        let hello = bob.encrypt(SESSION_ID, b"hello alice");

        let transaction = alice.new_transaction().await.unwrap();
        let plaintext = transaction
            .proteus_session_from_message(SESSION_ID, &hello)
            .await
            .unwrap();
        transaction.finish().await.unwrap();
        assert_eq!(plaintext, b"hello alice");

        let reply = encrypt(alice, b"hello bob").await;
        assert_eq!(bob_decrypts(&mut bob, &reply).await.unwrap(), b"hello bob");

        bob
    }

    /// When the other instance has ratcheted the session, this instance must decrypt with that
    /// state rather than its own outdated copy.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn instance_decrypts_after_other_instance_ratchets_session() {
        let (path, _db_dir) = tmp_db_file();
        let key = DatabaseKey::generate();

        let app = open_instance(&path, &key).await;
        let mut bob = establish_session(&app).await;
        let extension = open_instance(&path, &key).await;

        // The extension receives Bob's next message, which ratchets the session, then replies.
        let from_bob = bob.encrypt(SESSION_ID, b"first");
        assert_eq!(decrypt(&extension, &from_bob).await.unwrap(), b"first");
        let from_extension = encrypt(&extension, b"reply from the extension").await;
        assert_eq!(
            bob_decrypts(&mut bob, &from_extension).await.unwrap(),
            b"reply from the extension"
        );

        // Bob ratchets again against the extension's new key; the app must follow.
        let from_bob = bob.encrypt(SESSION_ID, b"second");
        let plaintext = decrypt(&app, &from_bob)
            .await
            .expect("the app must decrypt with the session state the extension persisted");
        assert_eq!(plaintext, b"second");
    }

    /// When the other instance has replaced the session entirely, this instance must use the
    /// replacement.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn instance_decrypts_after_other_instance_replaces_session() {
        let (path, _db_dir) = tmp_db_file();
        let key = DatabaseKey::generate();

        let app = open_instance(&path, &key).await;
        let mut bob = establish_session(&app).await;
        let extension = open_instance(&path, &key).await;

        // Bob resets the session; the extension receives the new session's first message and replies,
        // so that Bob's subsequent messages are ordinary messages on the new session.
        let transaction = extension.new_transaction().await.unwrap();
        let prekey_bundle = transaction.proteus_new_prekey(2).await.unwrap();
        transaction.finish().await.unwrap();
        bob.init_session_from_prekey_bundle(SESSION_ID, &prekey_bundle);

        let from_bob = bob.encrypt(SESSION_ID, b"new session");
        let transaction = extension.new_transaction().await.unwrap();
        let plaintext = transaction
            .proteus_session_from_message(SESSION_ID, &from_bob)
            .await
            .unwrap();
        transaction.finish().await.unwrap();
        assert_eq!(plaintext, b"new session");

        let from_extension = encrypt(&extension, b"reply from the extension").await;
        assert_eq!(
            bob_decrypts(&mut bob, &from_extension).await.unwrap(),
            b"reply from the extension"
        );

        let from_bob = bob.encrypt(SESSION_ID, b"on the new session");
        let plaintext = decrypt(&app, &from_bob)
            .await
            .expect("the app must decrypt with the session the extension persisted");
        assert_eq!(plaintext, b"on the new session");
    }

    /// An instance with an outdated copy of a session must not overwrite the newer state another
    /// instance has persisted. If it does, the persisted state no longer matches Bob's, and every
    /// later message from Bob fails to decrypt, even in a freshly opened instance.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn outdated_instance_does_not_overwrite_newer_session_state() {
        let (path, _db_dir) = tmp_db_file();
        let key = DatabaseKey::generate();

        let app = open_instance(&path, &key).await;
        let mut bob = establish_session(&app).await;
        let extension = open_instance(&path, &key).await;

        // The extension ratchets the session and replies, so Bob ratchets against its new key.
        let from_bob = bob.encrypt(SESSION_ID, b"first");
        assert_eq!(decrypt(&extension, &from_bob).await.unwrap(), b"first");
        let from_extension = encrypt(&extension, b"reply from the extension").await;
        assert_eq!(
            bob_decrypts(&mut bob, &from_extension).await.unwrap(),
            b"reply from the extension"
        );

        // The app, unaware of any of that, sends and persists its session.
        let from_app = encrypt(&app, b"message from the app").await;
        assert_eq!(
            bob_decrypts(&mut bob, &from_app).await.unwrap(),
            b"message from the app"
        );

        // A freshly opened instance has no cache at all, and loads whatever was persisted.
        let restarted = open_instance(&path, &key).await;
        let from_bob = bob.encrypt(SESSION_ID, b"second");
        let plaintext = decrypt(&restarted, &from_bob)
            .await
            .expect("the persisted session must still match Bob's");
        assert_eq!(plaintext, b"second");
    }

    /// Two instances sending on the same session must not encrypt with the same message key. Bob
    /// takes the second message as a duplicate of the first and drops it; worse, the two
    /// ciphertexts share a keystream.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn instances_do_not_reuse_message_keys() {
        let (path, _db_dir) = tmp_db_file();
        let key = DatabaseKey::generate();

        let app = open_instance(&path, &key).await;
        let mut bob = establish_session(&app).await;
        let extension = open_instance(&path, &key).await;

        let from_extension = encrypt(&extension, b"message from the extension").await;
        let from_app = encrypt(&app, b"message from the app").await;

        assert_eq!(
            bob_decrypts(&mut bob, &from_extension).await.unwrap(),
            b"message from the extension"
        );
        let plaintext = bob_decrypts(&mut bob, &from_app)
            .await
            .expect("the app's message must not reuse the extension's message key");
        assert_eq!(plaintext, b"message from the app");
    }

    /// Decrypting in a transaction which is then aborted must not consume the message: the
    /// database still has the session as it was before, and so must the cache.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn aborted_decryption_does_not_consume_message() {
        let (path, _db_dir) = tmp_db_file();
        let key = DatabaseKey::generate();

        let app = open_instance(&path, &key).await;
        let mut bob = establish_session(&app).await;

        let from_bob = bob.encrypt(SESSION_ID, b"hello again");

        let transaction = app.new_transaction().await.unwrap();
        let plaintext = transaction.proteus_decrypt(SESSION_ID, &from_bob).await.unwrap();
        assert_eq!(plaintext, b"hello again");
        transaction.abort().await.unwrap();

        let plaintext = decrypt(&app, &from_bob)
            .await
            .expect("the aborted transaction must not have consumed the message");
        assert_eq!(plaintext, b"hello again");
    }
}

mod mls {
    use super::*;
    use crate::{
        mls::conversation::{ConversationId, DecryptedMessage},
        test_utils::{SessionContext, TestContext, message::DecryptedMessagesExt},
    };

    async fn epoch(core_crypto: &Arc<CoreCrypto>, id: &ConversationId) -> u64 {
        let transaction = core_crypto.new_transaction().await.unwrap();
        let epoch = transaction.conversation(id).await.unwrap().epoch().await;
        transaction.finish().await.unwrap();
        epoch
    }

    /// Decrypt an application message in a transaction of its own, which is committed on success
    /// and aborted on failure.
    async fn decrypt(core_crypto: &Arc<CoreCrypto>, id: &ConversationId, message: &[u8]) -> Result<Vec<u8>, String> {
        let transaction = core_crypto.new_transaction().await.unwrap();
        let result = transaction
            .conversation(id)
            .await
            .unwrap()
            .decrypt_message(message)
            .await
            .map(DecryptedMessagesExt::into_single);
        match result {
            Ok(DecryptedMessage::ApplicationMessage(decrypted)) => {
                transaction.finish().await.unwrap();
                Ok(decrypted.plaintext)
            }
            Ok(other) => {
                transaction.abort().await.unwrap();
                Err(format!("expected an application message, got {other:?}"))
            }
            Err(err) => {
                transaction.abort().await.unwrap();
                Err(format!("{err:?}"))
            }
        }
    }

    /// Bob commits, moving the conversation to a new epoch, and returns the commit.
    async fn bob_commits(bob: &SessionContext, id: &ConversationId) -> Vec<u8> {
        bob.transaction
            .conversation(id)
            .await
            .unwrap()
            .update_key_material()
            .await
            .unwrap();
        bob.mls_transport().await.latest_commit().await.to_bytes().unwrap()
    }

    async fn bob_encrypts(bob: &SessionContext, id: &ConversationId, plaintext: &[u8]) -> Vec<u8> {
        bob.transaction
            .conversation(id)
            .await
            .unwrap()
            .encrypt_message(plaintext)
            .await
            .unwrap()
    }

    /// Set up a conversation between Alice and Bob, and hand back Alice's instance, which has the
    /// conversation cached, and a second instance on Alice's database.
    ///
    /// Alice's own transaction is finished, so that the instances can take turns with the database.
    async fn set_up<'a>(
        case: &'a TestContext,
        alice: &'a SessionContext,
        bob: &'a SessionContext,
    ) -> (ConversationId, Arc<CoreCrypto>, Arc<CoreCrypto>) {
        let conversation = case.create_conversation([alice, bob]).await;
        let id = conversation.id().clone();
        alice.transaction.finish().await.unwrap();

        let app = alice.core_crypto();
        let extension = alice.open_another_instance().await;
        (id, app, extension)
    }

    /// When the other instance has processed a commit, this instance must decrypt messages in the
    /// new epoch.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn instance_decrypts_after_other_instance_processes_commit() {
        let case = TestContext::default();
        let [alice, bob] = case.sessions().await;
        let (id, app, extension) = set_up(&case, &alice, &bob).await;

        let commit = bob_commits(&bob, &id).await;
        let transaction = extension.new_transaction().await.unwrap();
        transaction
            .conversation(&id)
            .await
            .unwrap()
            .decrypt_message(&commit)
            .await
            .unwrap();
        transaction.finish().await.unwrap();

        let message = bob_encrypts(&bob, &id, b"in the new epoch").await;
        let plaintext = decrypt(&app, &id, &message)
            .await
            .expect("the app must decrypt in the epoch the extension moved the conversation to");
        assert_eq!(plaintext, b"in the new epoch");
    }

    /// An instance with an outdated copy of a conversation must not overwrite the newer state
    /// another instance has persisted. If it does, the commit which the other instance processed is
    /// lost for good: the conversation is stuck in the old epoch, even in a freshly opened
    /// instance.
    #[macro_rules_attribute::apply(smol_macros::test)]
    async fn outdated_instance_does_not_roll_back_conversation() {
        let case = TestContext::default();
        let [alice, bob] = case.sessions().await;
        let (id, app, extension) = set_up(&case, &alice, &bob).await;

        let commit = bob_commits(&bob, &id).await;
        let transaction = extension.new_transaction().await.unwrap();
        transaction
            .conversation(&id)
            .await
            .unwrap()
            .decrypt_message(&commit)
            .await
            .unwrap();
        transaction.finish().await.unwrap();
        let new_epoch = epoch(&extension, &id).await;

        // The app, unaware of the commit, sends and persists its conversation.
        let transaction = app.new_transaction().await.unwrap();
        // The message itself would be rejected by the delivery service as being for an old epoch;
        // what matters here is what the app persists.
        let _ = transaction
            .conversation(&id)
            .await
            .unwrap()
            .encrypt_message(b"from the app")
            .await
            .unwrap();
        transaction.finish().await.unwrap();

        // A freshly opened instance has no cache at all, and loads whatever was persisted.
        let restarted = alice.open_another_instance().await;
        assert_eq!(
            epoch(&restarted, &id).await,
            new_epoch,
            "the persisted conversation must not go back to an earlier epoch"
        );

        let message = bob_encrypts(&bob, &id, b"in the new epoch").await;
        let plaintext = decrypt(&restarted, &id, &message)
            .await
            .expect("a fresh instance must decrypt in the new epoch");
        assert_eq!(plaintext, b"in the new epoch");
    }
}
