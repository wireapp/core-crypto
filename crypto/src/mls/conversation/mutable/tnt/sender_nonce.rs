use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// A shared nonce type for Transient and Targeted Messages.
#[derive(Clone, Default, Copy, TlsSize, TlsSerialize, TlsDeserialize, derive_more::Into, derive_more::From)]
#[repr(transparent)]
pub(crate) struct SenderNonce(u32);

impl SenderNonce {
    /// This fails if the inner value exceeds [u32::MAX]. We're using the conversation error type here because this
    /// method is called form exactly one place inside that module. If we ever add another call site from another
    /// module, it will be better to use a module-internal error here.
    pub(crate) fn increment(&mut self) -> crate::mls::conversation::Result<()> {
        self.0 = self
            .0
            .checked_add(1)
            .ok_or_else(|| crate::mls::conversation::Error::SenderNonceOverflow)?;
        Ok(())
    }
}
