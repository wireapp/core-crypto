use std::sync::Arc;

use async_trait::async_trait;

use crate::prelude::ConversationId;

use super::{Client, Error, Result};

/// An `EpochObserver` is notified whenever a conversation's epoch changes.
#[async_trait]
pub trait EpochObserver: Send + Sync {
    /// This function will be called every time a conversation's epoch changes.
    ///
    /// The `epoch` parameter is the new epoch.
    ///
    /// <div class="warning">
    /// This function must not block! Foreign implementors of this inteface can
    /// spawn a task indirecting the notification, or (unblocking) send the notification
    /// on some kind of channel, or anything else, as long as the operation completes
    /// quickly.
    /// </div>
    async fn epoch_changed(&self, conversation_id: ConversationId, epoch: u64);
}

impl Client {
    /// Add an epoch observer to this client.
    ///
    /// This function should be called 0 or 1 times in a client's lifetime. If called
    /// when an epoch observer already exists, this will return an error.
    pub async fn register_epoch_observer(&self, epoch_observer: Arc<dyn EpochObserver>) -> Result<()> {
        let mut guard = self.state.write().await;
        let inner = guard.as_mut().ok_or(Error::MlsNotInitialized)?;
        if inner.epoch_observer.is_some() {
            return Err(Error::EpochObserverAlreadyExists);
        }
        inner.epoch_observer = Some(epoch_observer);
        Ok(())
    }

    /// Notify the observer that the epoch has changed, if one is present.
    pub(crate) async fn notify_epoch_changed(&self, conversation_id: ConversationId, epoch: u64) {
        let guard = self.state.read().await;
        if let Some(inner) = guard.as_ref() {
            if let Some(observer) = inner.epoch_observer.as_ref() {
                observer.epoch_changed(conversation_id, epoch).await;
            }
        }
    }
}
