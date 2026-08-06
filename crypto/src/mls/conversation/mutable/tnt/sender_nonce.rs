use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::mls::conversation::{Error, Result};

/// A shared nonce type for Transient and Targeted Messages.
#[derive(Clone, Default, Copy, TlsSize, TlsSerialize, TlsDeserialize, derive_more::Into, derive_more::From)]
#[repr(transparent)]
pub(crate) struct SenderNonce(u32);

impl SenderNonce {
    /// This fails if the inner value exceeds [u32::MAX].
    pub(crate) fn increment(&mut self) -> Result<()> {
        self.0 = self.0.checked_add(1).ok_or_else(|| Error::SenderNonceOverflow)?;
        Ok(())
    }
}
