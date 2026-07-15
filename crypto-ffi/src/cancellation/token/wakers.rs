use std::task::Waker;

/// The collection of wakers where each future that's waiting for cancellation of this token will register when it's
/// polled (which is a no op in case of repeated polling).
#[derive(Debug, Default)]
pub(crate) struct CancellationWakers {
    wakers: Vec<Option<Waker>>,
}

impl CancellationWakers {
    /// Called by the future to register its waker.
    pub(crate) fn insert(&mut self, wakers_index: &mut Option<usize>, waker: &Waker) {
        // If there is already a waker at the given index...
        if let Some(entry) = wakers_index.and_then(|index| self.wakers.get_mut(index)) {
            if entry
                .as_ref()
                .is_none_or(|existing_waker| !existing_waker.will_wake(waker))
            {
                // Only replace it if it doesn't awake the same task (i.e., not a repeated poll for the same
                // future).
                *entry = Some(waker.clone());
            }
            return;
        }

        // If we're still here, we need to add the given waker to the wakers list.
        // To avoid the vector to grow for the lifetime of the future, reuse the first `None` position. If there
        // isn't one, extend the vector.
        let index = self.wakers.iter().position(Option::is_none).unwrap_or_else(|| {
            self.wakers.push(None);
            self.wakers.len() - 1
        });

        self.wakers[index] = Some(waker.clone());
        *wakers_index = Some(index);
    }

    pub(crate) fn remove(&mut self, index: usize) {
        // We need to keep the indices stable, so removal means just emptying the entry.
        if let Some(entry) = self.wakers.get_mut(index) {
            *entry = None;
        }
    }

    pub(super) fn take_all(&mut self) -> Vec<Option<Waker>> {
        std::mem::take(&mut self.wakers)
    }
}
