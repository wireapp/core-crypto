use std::sync::Mutex;

use futures_channel::oneshot;
use futures_util::{FutureExt as _, future::Shared};

/// Use this to cancel a `CoreCrypto` transaction and running foreign callbacks. Should be used in the Swift wrapper
/// only.
#[derive(Debug, uniffi::Object)]
pub struct CoreCryptoCancellationToken {
    /// We're using a non-async lock to avoid spawning another future to wait during
    /// [CoreCryptoCancellationToken::cancel].
    sender: Mutex<Option<oneshot::Sender<()>>>,
    receiver: Shared<oneshot::Receiver<()>>,
}

#[uniffi::export]
impl CoreCryptoCancellationToken {
    /// Create a new `CoreCryptoCancellationToken`.
    #[expect(clippy::new_without_default)]
    #[uniffi::constructor]
    pub fn new() -> Self {
        let (sender, receiver) = oneshot::channel();

        Self {
            sender: Mutex::new(Some(sender)),
            receiver: receiver.shared(),
        }
    }

    /// Cancel the token and resolve all futures waiting for its cancellation.
    pub fn cancel(&self) {
        let sender = self
            .sender
            .lock()
            .unwrap_or_else(|poisoned| {
                log::warn!("recovering poisoned cancellation sender");
                poisoned.into_inner()
            })
            .take();

        if let Some(sender) = sender {
            let _ = sender.send(());
        }
    }
}

impl CoreCryptoCancellationToken {
    /// Return a future that resolves when this token is cancelled.
    pub(crate) fn cancelled(&self) -> Shared<oneshot::Receiver<()>> {
        self.receiver.clone()
    }
}
