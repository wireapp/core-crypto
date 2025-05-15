use std::sync::Arc;

use async_trait::async_trait;

use crate::{CoreCrypto, RecursiveError, mls::HasSessionAndCrypto as _, prelude::ConversationId};

use super::{Error, Result, Session};

/// An `EpochObserver` is notified whenever a conversation's epoch changes.
#[cfg_attr(target_family = "wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
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

impl Session {
    /// Add an epoch observer to this session.
    ///
    /// This function should be called 0 or 1 times in a session's lifetime. If called
    /// when an epoch observer already exists, this will return an error.
    pub(crate) async fn register_epoch_observer(&self, epoch_observer: Arc<dyn EpochObserver>) -> Result<()> {
        let mut guard = self.inner.write().await;
        let inner = guard.as_mut().ok_or(Error::MlsNotInitialized)?;
        if inner.epoch_observer.is_some() {
            return Err(Error::EpochObserverAlreadyExists);
        }
        inner.epoch_observer = Some(epoch_observer);
        Ok(())
    }

    /// Notify the observer that the epoch has changed, if one is present.
    pub(crate) async fn notify_epoch_changed(&self, conversation_id: ConversationId, epoch: u64) {
        let guard = self.inner.read().await;
        if let Some(inner) = guard.as_ref() {
            if let Some(observer) = inner.epoch_observer.as_ref() {
                observer.epoch_changed(conversation_id, epoch).await;
            }
        }
    }
}

impl CoreCrypto {
    /// Add an epoch observer to this session.
    ///
    /// This function should be called 0 or 1 times in a session's lifetime.
    /// If called when an epoch observer already exists, this will return an error.
    pub async fn register_epoch_observer(&self, epoch_observer: Arc<dyn EpochObserver>) -> Result<()> {
        let session = self
            .session()
            .await
            .map_err(RecursiveError::mls("getting mls session"))?;
        session.register_epoch_observer(epoch_observer).await
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use rstest_reuse::apply;
    use wasm_bindgen_test::*;

    use crate::test_utils::{TestContext, TestEpochObserver, all_cred_cipher};

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn observe_local_epoch_change(case: TestContext) {
        let [session_context] = case.sessions().await;
        Box::pin(async move {
            let test_conv = case.create_conversation([&session_context]).await;

            let observer = TestEpochObserver::new();
            session_context
                .session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // trigger an epoch
            let id = test_conv.advance_epoch().await.id;

            // ensure we have observed the epoch change
            let observed_epochs = observer.observed_epochs().await;
            assert_eq!(
                observed_epochs.len(),
                1,
                "we triggered exactly one epoch change and so should observe one epoch change"
            );
            assert_eq!(
                observed_epochs[0].0, id,
                "conversation id of observed epoch change must match"
            );
        })
        .await
    }

    #[apply(all_cred_cipher)]
    #[wasm_bindgen_test]
    pub async fn observe_remote_epoch_change(case: TestContext) {
        let [alice, bob] = case.sessions().await;
        Box::pin(async move {
            let test_conv = case.create_conversation([&alice, &bob]).await;

            //  bob has the observer
            let observer = TestEpochObserver::new();
            bob.session()
                .await
                .register_epoch_observer(observer.clone())
                .await
                .unwrap();

            // alice triggers an epoch
            let id = test_conv.advance_epoch().await.id;

            // ensure we have observed the epoch change
            let observed_epochs = observer.observed_epochs().await;
            assert_eq!(
                observed_epochs.len(),
                1,
                "we triggered exactly one epoch change and so should observe one epoch change"
            );
            assert_eq!(
                observed_epochs[0].0, id,
                "conversation id of observed epoch change must match"
            );
        })
        .await
    }
}
