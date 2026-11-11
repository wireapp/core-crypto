use std::borrow::Cow;

use super::{Result, TransactionContext};
use crate::{DecryptedMessage, RecursiveError, mls::conversation::ConversationIdRef};

impl TransactionContext {
    /// Decrypt and process a MLS or TNT message.
    ///
    /// Effect on local state depends on what the message turns out to be:
    ///
    /// - a commit from another member supersedes any local pending commit, and consumes all pending proposals;
    /// - our own commit, delivered back to us, is merged rather than discarded;
    /// - proposals and application messages leave local pending state untouched.
    ///
    /// The message bytes must be TLS-serialized.
    ///
    /// Returns a vector. The first item in this vector is always the message this function was called with;
    /// subsequent items are buffered messages which have been unblocked by that first message. If the initial
    /// message was deferred, this vector will be empty.
    ///
    /// Errors occurred when decrypting the message with which this function was called propagate as normal.
    /// Errors occurred when decrypting buffered messages unblocked by the initial message are propagated in
    /// case they are infrastructure errors. If they are not, then they are logged but not propagated, and the
    /// related message is dropped.
    ///
    /// Logically decryption is an operation on a conversation, and in fact that is how it is implemented internally.
    /// But there's a trap: normally, we only want to load and handle non-pending conversations, so the type system
    /// can ensure we don't do illegal operations on a conversation which hasn't been realized yet. But for decryption
    /// specifically we have to route it through a pending conversation, because that's how the pending conversation
    /// can learn that it's time to merge itself.
    pub async fn decrypt_message(
        &self,
        id: &ConversationIdRef,
        bytes: impl Into<Cow<'_, [u8]>>,
    ) -> Result<Vec<DecryptedMessage>> {
        let mut conversation = self.conversation_regardless_of_pending_status(id).await?;
        conversation
            .decrypt_message(bytes)
            .await
            .map_err(RecursiveError::context(
                "dispatching message decryption to conversation",
            ))
            .map_err(Into::into)
    }
}
