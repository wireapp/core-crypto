use async_lock::Mutex;
use async_trait::async_trait;
use std::sync::Arc;

use crate::prelude::{ConversationId, HistoryObserver, HistorySecret, Obfuscated};

#[derive(Debug)]
pub(crate) struct TestHistoryObserver(Mutex<HistoryObserverInner>);

#[derive(Default)]
struct HistoryObserverInner {
    observed_history_clients: Vec<(ConversationId, HistorySecret)>,
}

impl std::fmt::Debug for HistoryObserverInner {
    // Need to implement this manually because we can't derive `Debug` on `HistorySecret`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryObserverInner")
            .field(
                "observed_history_clients",
                &self
                    .observed_history_clients
                    .iter()
                    .map(|(id, secret)| (Obfuscated::from(id), Obfuscated::from(secret)))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
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

    pub(crate) async fn observed_history_clients(&self) -> Vec<(ConversationId, HistorySecret)> {
        self.0
            .lock()
            .await
            .observed_history_clients
            .iter()
            .map(|(id, secret)| {
                let encoded = rmp_serde::to_vec(&secret).unwrap();
                let history_secret = rmp_serde::from_slice::<HistorySecret>(&encoded).unwrap();
                (id.clone(), history_secret)
            })
            .collect()
    }
}

#[cfg_attr(target_family="wasm", async_trait(?Send))]
#[cfg_attr(not(target_family = "wasm"), async_trait)]
impl HistoryObserver for TestHistoryObserver {
    async fn history_client_created(&self, conversation_id: ConversationId, secret: &HistorySecret) {
        let mut guard = self.0.lock().await;
        let encoded = rmp_serde::to_vec(&secret).unwrap();
        let history_secret = rmp_serde::from_slice::<HistorySecret>(&encoded).unwrap();

        guard.observed_history_clients.push((conversation_id, history_secret))
    }
}
