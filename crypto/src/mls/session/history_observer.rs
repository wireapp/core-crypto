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
