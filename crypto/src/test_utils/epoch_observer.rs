use std::sync::Arc;

use async_lock::Mutex;
use async_trait::async_trait;

use crate::prelude::{ConversationId, EpochObserver};

pub(crate) struct TestEpochObserver(Mutex<EpochObserverInner>);

#[derive(Default)]
struct EpochObserverInner {
    observed_epochs: Vec<(ConversationId, u64)>,
}

impl TestEpochObserver {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(Default::default()))
    }

    pub(crate) async fn reset(&self) {
        let mut guard = self.0.lock().await;
        guard.observed_epochs.clear();
    }

    pub(crate) async fn has_changed(&self) -> bool {
        let guard = self.0.lock().await;
        !guard.observed_epochs.is_empty()
    }

    pub(crate) async fn observed_epochs(&self) -> Vec<(ConversationId, u64)> {
        self.0.lock().await.observed_epochs.clone()
    }
}

#[cfg_attr(target_family="wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl EpochObserver for TestEpochObserver {
    async fn epoch_changed(&self, conversation_id: ConversationId, epoch: u64) {
        let mut guard = self.0.lock().await;
        guard.observed_epochs.push((conversation_id, epoch));
    }
}
