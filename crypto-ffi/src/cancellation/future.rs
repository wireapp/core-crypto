use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::CoreCryptoCancellationToken;

pub(crate) struct Cancelled {
    pub(crate) token: Arc<CoreCryptoCancellationToken>,
    pub(crate) wakers_index: Option<usize>,
}

impl Future for Cancelled {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if this.token.is_cancelled() {
            return Poll::Ready(());
        }

        let mut wakers = this.token.wakers();
        // Cancellation may have happened while waiting for the wakers lock.
        if this.token.is_cancelled() {
            return Poll::Ready(());
        }

        wakers.insert(&mut this.wakers_index, cx.waker());
        Poll::Pending
    }
}

impl Drop for Cancelled {
    fn drop(&mut self) {
        let Some(index) = self.wakers_index.take() else {
            return;
        };

        self.token.wakers().remove(index);
    }
}
