use crate::prelude::{ClientId, ConversationId, HistoryObserver, HistorySecret};
use async_lock::Mutex;
use async_trait::async_trait;
use std::sync::Arc;

pub(crate) struct TestHistoryObserver(Mutex<HistoryObserverInner>);

#[derive(Default)]
struct HistoryObserverInner {
    observed_history_clients: Vec<(ConversationId, ClientId)>,
}

impl TestHistoryObserver {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self(Default::default()))
    }

    #[allow(dead_code)]
    pub(crate) async fn reset(&self) {
        let mut guard = self.0.lock().await;
        guard.observed_history_clients.clear();
    }

    #[allow(dead_code)]
    pub(crate) async fn has_changed(&self) -> bool {
        let guard = self.0.lock().await;
        !guard.observed_history_clients.is_empty()
    }

    pub(crate) async fn observed_history_clients(&self) -> Vec<(ConversationId, ClientId)> {
        self.0.lock().await.observed_history_clients.clone()
    }
}

#[cfg_attr(target_family="wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl HistoryObserver for TestHistoryObserver {
    async fn history_client_created(&self, conversation_id: ConversationId, secret: &HistorySecret) {
        let mut guard = self.0.lock().await;
        guard
            .observed_history_clients
            .push((conversation_id, secret.client_id.clone()))
    }
}
