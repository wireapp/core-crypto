use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// A shared nonce type for Transient and Targeted Messages.
#[derive(Clone, Default, Copy, TlsSize, TlsSerialize, TlsDeserialize, derive_more::Into, derive_more::From)]
#[repr(transparent)]
pub struct SenderNonce(u32);

impl SenderNonce {
    pub(crate) fn increment(&mut self) {
        self.0 += 1;
    }
}
