use crate::prelude::{ConversationId, HistorySecret};
use async_trait::async_trait;
use std::sync::Arc;

use super::{Error, Session};

/// The `HistoryObserver` will be called when updating the history client in a conversation
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
pub trait HistoryObserver: Send + Sync {
    /// This function will be called when a new history client has been created and accepted
    /// by the delivery service.
    ///
    /// The `secret` parameter contains the history client's secrets.
    async fn history_client_created(&self, conversation_id: ConversationId, secret: &HistorySecret);
}

impl Session {
    /// Add an history observer to this session.
    /// (see [HistoryObserver]).
    ///
    /// This function should be called 0 or 1 times in a session's lifetime. If called
    /// when an epoch observer already exists, this will return an error.
    pub async fn register_history_observer(
        &self,
        history_observer: Arc<dyn HistoryObserver>,
    ) -> crate::prelude::Result<()> {
        let mut history_guard = self.history_observer.write().await;
        if history_guard.is_some() {
            return Err(Error::HistoryObserverAlreadyExists);
        }
        history_guard.replace(history_observer);
        Ok(())
    }

    /// Notify the history handler that the history client has been replaced, if one is present.
    pub(crate) async fn notify_new_history_client(
        &self,
        conversation_id: ConversationId,
        history_secret: &HistorySecret,
    ) {
        if let Some(handler) = self.history_observer.read().await.as_ref() {
            handler.history_client_created(conversation_id, history_secret).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::mls::conversation::Conversation;
    use crate::test_utils::{TestContext, TestHistoryObserver, all_cred_cipher};
    use rstest::rstest;
    use rstest_reuse::apply;

    #[apply(all_cred_cipher)]
    pub async fn observe_new_history_client(case: TestContext) {
        let [session_context] = case.sessions().await;
        Box::pin(async move {
            let test_conv = case.create_conversation([&session_context]).await;

            let observer = TestHistoryObserver::new();
            session_context
                .session()
                .await
                .register_history_observer(observer.clone())
                .await
                .unwrap();

            // generate a new history secret
            let history_secret = test_conv.guard().await.generate_history_secret().await.unwrap();
            let client_id = history_secret.client_id.clone();
            let id = test_conv.advance_epoch().await.id;

            session_context
                .session()
                .await
                .notify_new_history_client(id.clone(), &history_secret)
                .await;

            // ensure we have observed the epoch change
            let observed_history_clients = observer.observed_history_clients().await;
            assert_eq!(
                observed_history_clients.len(),
                1,
                "we triggered exactly one epoch change and so should observe one epoch change"
            );
            assert_eq!(
                observed_history_clients[0].0, id,
                "conversation id of observed epoch change must match"
            );
            assert_eq!(
                observed_history_clients[0].1, client_id,
                "history client id of observed history client change must match"
            );
        })
        .await
    }
}
