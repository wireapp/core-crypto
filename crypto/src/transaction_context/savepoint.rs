use core_crypto_keystore::CryptoKeystoreError;

use super::TransactionContextInner;
use crate::{RecursiveError, mls::conversation::ConversationIdRef};

impl TransactionContextInner {
    /// Run `operation` inside a savepoint of this transaction.
    ///
    /// If `operation` fails, its database writes are rolled back, and so is the in-memory state
    /// which mirrors them: conversations it changed are reloaded from the database, and epoch
    /// changes it queued are dropped.
    ///
    /// Restoring a conversation takes its group lock, so don't hold one across this call. If
    /// restoring fails, that error is returned instead of the one from `operation`.
    pub(crate) async fn with_savepoint<T, E>(
        &self,
        savepoint_name: &str,
        operation: impl AsyncFnOnce() -> Result<T, E>,
        map_err: impl Fn(&'static str) -> Box<dyn FnOnce(CryptoKeystoreError) -> E>,
    ) -> Result<T, E>
    where
        E: From<RecursiveError>,
    {
        let epoch_changes_before = self.pending_epoch_changes.lock().await.len();
        let touched_before = self.touched_conversations.lock().await.len();

        #[expect(clippy::disallowed_methods, reason = "this is the wrapper")]
        let result = self
            .transaction
            .with_savepoint(savepoint_name, operation, map_err)
            .await;

        if result.is_err() {
            self.pending_epoch_changes.lock().await.truncate(epoch_changes_before);
            let mut touched = self.touched_conversations.lock().await.split_off(touched_before);
            touched.sort();
            touched.dedup();
            let session = self.core_crypto.mls.read().await.clone();
            if let Some(session) = session {
                session
                    .conversation_cache
                    .lock()
                    .await
                    .restore(touched.iter().map(AsRef::as_ref))
                    .await
                    .map_err(RecursiveError::root(
                        "restoring conversations after a savepoint rollback",
                    ))?;
            }
        }

        result
    }

    /// Note that the in-memory state of conversation `id` is about to change, so a savepoint
    /// rollback knows to restore it.
    pub(crate) async fn conversation_touched(&self, id: &ConversationIdRef) {
        self.touched_conversations.lock().await.push(id.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use crate::{test_utils::*, transaction_context::Error};

    /// Run `operation` in a savepoint, then fail so the savepoint is rolled back.
    async fn in_rolled_back_savepoint(session: &SessionContext, operation: impl AsyncFnOnce()) {
        let result = session
            .transaction
            .inner()
            .unwrap()
            .with_savepoint(
                "rolled_back_savepoint",
                async move || {
                    operation().await;
                    Err::<(), _>(Error::CallerError("rolling back the savepoint"))
                },
                Error::savepoint,
            )
            .await;
        assert!(matches!(result, Err(Error::CallerError(_))));
    }

    /// Both a fresh lookup and a handle taken before the savepoint see the state from before it.
    #[apply(all_cred_cipher)]
    async fn rolled_back_savepoint_restores_cached_conversation(case: TestContext) {
        let [alice] = case.sessions().await;
        let conversation = case.create_conversation([&alice]).await;
        let id = conversation.id().clone();
        let handle = alice.transaction.conversation(&id).await.unwrap();

        in_rolled_back_savepoint(&alice, async || {
            let mut conversation = alice.transaction.conversation(&id).await.unwrap();
            conversation.update_key_material().await.unwrap();
            assert_eq!(handle.epoch().await, 1);
        })
        .await;

        assert_eq!(handle.epoch().await, 0);
        assert_eq!(alice.transaction.conversation(&id).await.unwrap().epoch().await, 0);
    }

    /// A conversation created inside a rolled-back savepoint was never stored, so it must not be found.
    #[apply(all_cred_cipher)]
    async fn rolled_back_savepoint_forgets_new_conversation(case: TestContext) {
        let [alice] = case.sessions().await;
        let id = conversation_id();

        in_rolled_back_savepoint(&alice, async || {
            alice
                .transaction
                .new_conversation(&id, &alice.initial_credential, case.cfg.clone())
                .await
                .unwrap();
        })
        .await;

        assert!(!alice.transaction.conversation_exists(&id).await.unwrap());
    }

    /// An epoch change inside a rolled-back savepoint never happened, so observers must not hear of it.
    #[apply(all_cred_cipher)]
    async fn rolled_back_savepoint_drops_epoch_changes(case: TestContext) {
        let [mut alice] = case.sessions().await;
        let id = case.create_conversation([&alice]).await.id().clone();
        alice.commit_transaction().await;

        let observer = TestEpochObserver::new();
        alice
            .session()
            .await
            .register_epoch_observer(observer.clone())
            .await
            .unwrap();

        in_rolled_back_savepoint(&alice, async || {
            let mut conversation = alice.transaction.conversation(&id).await.unwrap();
            conversation.update_key_material().await.unwrap();
        })
        .await;
        alice.commit_transaction().await;

        assert!(!observer.has_changed().await);
    }
}
